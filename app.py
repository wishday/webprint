#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web打印服务 - 基于Python Flask + CUPS
支持文档/图片上传、打印设置、队列管理
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
import os
import subprocess
import json
import uuid
from datetime import datetime
import threading
import time
import logging
import sys

# 导入IPP客户端
try:
    from ipp_client import IPPTOOL_AVAILABLE
except ImportError:
    IPPTOOL_AVAILABLE = False
    logging.warning("IPP客户端不可用，墨盒信息将返回模拟数据")

app = Flask(__name__)

# HTML缓存（用于打印机主页）
html_cache = {}

app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['PREVIEW_FOLDER'] = os.path.join(os.path.dirname(__file__), 'previews')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB最大文件
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'txt', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'rtf', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'}

# 确保上传目录和预览目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PREVIEW_FOLDER'], exist_ok=True)

# 配置日志（使用本地日志路径）
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 存储打印任务状态
print_jobs = {}
print_jobs_lock = threading.Lock()  # 添加线程锁保护共享数据


def is_safe_path(base_path, target_path):
    """
    检查目标路径是否在基础路径内，防止路径遍历攻击

    Args:
        base_path: 允许访问的基础目录
        target_path: 目标路径

    Returns:
        bool: 安全返回True，不安全返回False
    """
    # 规范化路径，解析所有符号链接和相对路径
    base_abs = os.path.abspath(base_path)
    target_abs = os.path.abspath(target_path)

    # 检查目标路径是否以基础路径开头
    return target_abs.startswith(base_abs + os.sep) or target_abs == base_abs


def get_printer_uri(printer_name):
    """
    获取打印机URI

    Args:
        printer_name: 打印机名称

    Returns:
        打印机URI字符串，如果失败返回None
    """
    try:
        result = subprocess.run(
            ['lpstat', '-p', printer_name, '-v'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.error(f"获取打印机URI失败: {result.stderr}")
            return None

        printer_uri = None
        for line in result.stdout.split('\n'):
            import re
            match = re.search(r'device\s+for\s+' + re.escape(printer_name) + r':\s*(\S+)', line)
            if match:
                printer_uri = match.group(1).strip()
                break

        return printer_uri

    except subprocess.TimeoutExpired:
        logger.error(f"获取打印机URI超时")
        return None
    except Exception as e:
        logger.error(f"获取打印机URI失败: {e}")
        return None


def get_safe_path(base_path, filename):
    """
    获取安全的文件路径，防止路径遍历攻击

    Args:
        base_path: 允许访问的基础目录
        filename: 文件名

    Returns:
        str: 安全的文件路径，如果不安全返回None
    """
    # 移除所有路径遍历字符
    filename = os.path.basename(filename)

    # 拼接完整路径
    filepath = os.path.join(base_path, filename)

    # 检查路径安全性
    if is_safe_path(base_path, filepath):
        return filepath
    else:
        logger.warning(f"检测到潜在的路径遍历攻击: {filename}")
        return None


def get_safe_path_with_subdirs(base_path, relative_path):
    """
    获取安全的文件路径（允许子目录），防止路径遍历攻击

    Args:
        base_path: 允许访问的基础目录
        relative_path: 相对路径（可包含子目录）

    Returns:
        str: 安全的文件路径，如果不安全返回None
    """
    # 规范化相对路径
    relative_path = os.path.normpath(relative_path)

    # 拼接完整路径
    filepath = os.path.join(base_path, relative_path)

    # 检查路径安全性
    if is_safe_path(base_path, filepath):
        return filepath
    else:
        logger.warning(f"检测到潜在的路径遍历攻击: {relative_path}")
        return None

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_image_file(filename):
    """检查是否为图片文件"""
    image_extensions = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in image_extensions

def is_document_file(filename):
    """检查是否为文档文件（非PDF）"""
    doc_extensions = {'txt', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'rtf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in doc_extensions

def get_file_type(filename):
    """获取文件类型分类"""
    if not filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['pdf']:
        return 'pdf'
    elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
        return 'image'
    elif ext in ['txt', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'rtf']:
        return 'document'
    else:
        return 'other'

def convert_to_pdf(input_file, output_dir):
    """
    使用LibreOffice将文档转换为PDF
    
    Args:
        input_file: 输入文件路径
        output_dir: 输出目录
    
    Returns:
        转换后的PDF文件路径，如果失败返回None
    """
    try:
        filename = os.path.basename(input_file)
        name, ext = os.path.splitext(filename)
        
        # 检查libreoffice是否可用
        try:
            subprocess.run(['libreoffice', '--version'], 
                         capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error("LibreOffice未安装或不可用")
            return None
        
        # 使用libreoffice转换
        cmd = [
            'libreoffice',
            '--headless',
            '--convert-to', 'pdf',
            '--outdir', output_dir,
            input_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # 返回转换后的PDF路径
            pdf_filename = f"{name}.pdf"
            pdf_path = os.path.join(output_dir, pdf_filename)
            if os.path.exists(pdf_path):
                return pdf_path
        
        logger.error(f"文档转换失败: {result.stderr}")
        return None
    except FileNotFoundError:
        logger.error("LibreOffice未安装，无法转换文档")
        return None
    except subprocess.TimeoutExpired:
        logger.error("文档转换超时")
        return None
    except Exception as e:
        logger.error(f"文档转换失败: {e}")
        return None

def get_preview_file(original_filename):
    """
    获取预览文件路径
    
    Args:
        original_filename: 原始文件名
    
    Returns:
        预览文件路径（PDF或图片），如果无法预览返回None
    """
    # 安全检查：只获取文件名，移除路径部分
    original_filename = os.path.basename(original_filename)

    # 获取安全的文件路径
    original_path = get_safe_path(app.config['UPLOAD_FOLDER'], original_filename)
    if not original_path or not os.path.exists(original_path):
        return None

    # 如果是图片，直接返回
    if is_image_file(original_filename):
        return original_path

    # 如果是PDF，直接返回
    if original_filename.lower().endswith('.pdf'):
        return original_path

    # 如果是文档，尝试转换为PDF
    if is_document_file(original_filename):
        name, ext = os.path.splitext(original_filename)
        pdf_filename = f"{name}.pdf"

        # 获取安全的PDF路径
        pdf_path = get_safe_path(app.config['PREVIEW_FOLDER'], pdf_filename)
        if not pdf_path:
            return None

        # 如果PDF已存在，直接返回
        if os.path.exists(pdf_path):
            return pdf_path

        # 否则转换
        converted_pdf = convert_to_pdf(original_path, app.config['PREVIEW_FOLDER'])
        if converted_pdf:
            return converted_pdf
    
    return None

def get_printers():
    """获取可用的CUPS打印机列表"""
    try:
        result = subprocess.run(
            ['lpstat', '-p'],
            capture_output=True,
            text=True,
            timeout=5
        )
        printers = []
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                # 检测包含"printer"关键字的行
                if 'printer' in line.lower():
                    # 提取打印机名称
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].lower() == 'printer':
                        printer_name = parts[1]
                        # 提取状态
                        status = 'idle'
                        if 'is ready' in line.lower():
                            status = 'ready'
                        elif 'is processing' in line.lower():
                            status = 'processing'
                        elif 'is stopped' in line.lower():
                            status = 'stopped'

                        # 获取打印机URI
                        printer_uri = get_printer_uri(printer_name)

                        printers.append({
                            'name': printer_name,
                            'status': status,
                            'uri': printer_uri
                        })

        if not printers:
            logger.warning("未检测到可用打印机")

        return printers
    except Exception as e:
        logger.error(f"获取打印机列表失败: {e}")
        return []

def cleanup_old_jobs():
    """定期清理24小时前的任务记录和关联文件"""
    while True:
        time.sleep(3600)  # 每小时清理一次
        try:
            with print_jobs_lock:
                now = datetime.now()
                old_jobs = [
                    job_id for job_id, job in print_jobs.items()
                    if (now - datetime.fromisoformat(job['timestamp'])).total_seconds() > 86400
                ]
                for job_id in old_jobs:
                    # 删除关联文件
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], print_jobs[job_id]['filename'])
                    if os.path.exists(filepath):
                        try:
                            os.remove(filepath)
                            print(f"清理旧文件: {print_jobs[job_id]['filename']}")
                        except Exception as e:
                            print(f"删除文件失败: {e}")
                    # 删除任务记录
                    del print_jobs[job_id]
                    print(f"清理旧任务: {job_id}")
                if old_jobs:
                    print(f"共清理 {len(old_jobs)} 个旧任务记录")
        except Exception as e:
            print(f"清理任务失败: {e}")

# 在启动时启动清理线程
cleanup_thread = threading.Thread(target=cleanup_old_jobs, daemon=True)
cleanup_thread.start()

def submit_print_job(filepath, printer_name, color_mode='mono', duplex='one-sided', orientation='portrait', paper_size='A4', paper_type='plain', copies=1, page_range=None):
    """
    提交打印任务到CUPS

    Args:
        filepath: 文件路径
        printer_name: 打印机名称
        color_mode: color/mono
        duplex: one-sided/two-sided-long-edge/two-sided-short-edge
        orientation: portrait/landscape (打印方向)
        paper_size: 纸张大小 (A4, A3, A2, A1, 5x7, 6x8, 7x10)
        paper_type: 纸张材质 (plain, glossy)
        copies: 打印份数
        page_range: 页面范围，格式如 "1-5,8,10-12"
    """
    job_id = str(uuid.uuid4())

    try:
        # 构建lp命令
        cmd = ['lp', '-d', printer_name, '-n', str(copies)]

        # 添加纸张大小设置
        # CUPS纸张大小映射
        paper_size_map = {
            'A4': 'A4',
            'A3': 'A3',
            'A2': 'A2',
            'A1': 'A1',
            '5inch': '3.5x5in',  # 5寸照片 (89×127mm)
            '6inch': '4x6in',    # 6寸照片 (102×152mm) - 国际标准照片
            '7inch': '5x7in',    # 7寸照片 (127×178mm)
            '8inch': '6x8in',    # 8寸照片 (152×203mm)
            '10inch': '8x10in'   # 10寸照片 (203×254mm)
        }
        cups_paper_size = paper_size_map.get(paper_size, 'A4')
        cmd.extend(['-o', f'media={cups_paper_size}'])

        # 添加纸张材质设置
        # CUPS介质类型映射
        paper_type_map = {
            'plain': 'Plain',
            'glossy': 'Glossy'
        }
        cups_paper_type = paper_type_map.get(paper_type, 'Plain')
        cmd.extend(['-o', f'media-type={cups_paper_type}'])

        # 添加色彩设置（使用组合参数确保覆盖CUPS默认设置）
        if color_mode == 'mono':
            # 黑白打印：使用多种参数确保兼容性和覆盖默认设置
            cmd.extend(['-o', 'print-color-mode=monochrome'])
            cmd.extend(['-o', 'ColorModel=KGray'])
            cmd.extend(['-o', 'ColorMode=Gray'])
        else:
            # 彩色打印：使用多种参数确保兼容性和覆盖默认设置
            cmd.extend(['-o', 'print-color-mode=color'])
            cmd.extend(['-o', 'ColorModel=RGB'])
            cmd.extend(['-o', 'ColorMode=Color'])

        # 添加双面打印设置
        if duplex == 'two-sided-long-edge':
            cmd.extend(['-o', 'sides=two-sided-long-edge'])
        elif duplex == 'two-sided-short-edge':
            cmd.extend(['-o', 'sides=two-sided-short-edge'])
        else:
            cmd.extend(['-o', 'sides=one-sided'])

        # 添加打印方向设置（纵向/横向）
        if orientation == 'landscape':
            cmd.extend(['-o', 'orientation-requested=4'])
            cmd.extend(['-o', 'landscape'])
        else:
            cmd.extend(['-o', 'orientation-requested=3'])
            cmd.extend(['-o', 'portrait'])

        # 添加页面范围设置（修复：使用-o page-ranges而不是-P）
        if page_range and page_range.strip():
            cmd.extend(['-o', f'page-ranges={page_range.strip()}'])
        
        # 添加文件
        cmd.append(filepath)
        
        # 记录打印命令（用于调试）
        logger.info(f"执行打印命令: {' '.join(cmd)}")
        logger.info(f"打印参数: color_mode={color_mode}, duplex={duplex}, orientation={orientation}, paper_size={paper_size}, paper_type={paper_type}, copies={copies}, page_range={page_range}")

        # 执行打印命令
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # 提取CUPS任务ID
        cups_job_id = None
        if result.returncode == 0:
            # 从输出中提取任务ID，格式通常是 "request id is PDF_Printer-1 (1 file(s))"
            output = result.stdout.strip()
            if 'request id' in output.lower():
                # 提取包含打印机名称和任务ID的部分
                words = output.split()
                for word in words:
                    # 查找格式为 "PrinterName-123" 的词
                    if '-' in word:
                        parts = word.split('-')
                        if len(parts) >= 2:
                            # 检查最后一部分是否为纯数字（任务ID）
                            potential_id = parts[-1]
                            if potential_id.isdigit():
                                cups_job_id = potential_id
                                break

        # 更新任务状态
        print_jobs[job_id] = {
            'id': job_id,
            'cups_job_id': cups_job_id,
            'filename': os.path.basename(filepath),
            'printer': printer_name,
            'color_mode': color_mode,
            'duplex': duplex,
            'orientation': orientation,
            'paper_size': paper_size,
            'paper_type': paper_type,
            'copies': copies,
            'page_range': page_range,
            'status': 'submitted' if result.returncode == 0 else 'failed',
            'message': result.stdout if result.returncode == 0 else result.stderr,
            'timestamp': datetime.now().isoformat(),
            'progress': 0
        }
        
        if result.returncode == 0:
            # 启动后台线程监控进度
            monitor_thread = threading.Thread(
                target=monitor_job_progress,
                args=(job_id, cups_job_id, printer_name)
            )
            monitor_thread.daemon = True
            monitor_thread.start()
        
        return job_id, result.returncode == 0
        
    except Exception as e:
        print_jobs[job_id] = {
            'id': job_id,
            'filename': os.path.basename(filepath),
            'printer': printer_name,
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat(),
            'progress': 0
        }
        return job_id, False

def monitor_job_progress(job_id, cups_job_id, printer_name):
    """
    监控打印任务进度
    
    支持长时间打印任务，动态调整监控间隔：
    - 前10分钟：每2秒检查一次
    - 10-30分钟：每10秒检查一次
    - 30-60分钟：每30秒检查一次
    - 60分钟以上：每60秒检查一次
    - 最大监控时间：2小时
    """
    # 如果没有获取到cups_job_id，直接标记为完成
    if not cups_job_id:
        print_jobs[job_id]['status'] = 'completed'
        print_jobs[job_id]['progress'] = 100
        print_jobs[job_id]['message'] += ' (任务已提交，无法监控详细进度)'
        return
    
    # 构建CUPS任务标识符
    job_identifier = f"{printer_name}-{cups_job_id}"
    
    # 记录开始时间
    start_time = time.time()
    max_monitor_time = 2 * 60 * 60  # 最大监控时间：2小时（7200秒）
    
    while job_id in print_jobs:
        # 计算已运行时间
        elapsed_time = time.time() - start_time
        
        # 检查是否超过最大监控时间
        if elapsed_time >= max_monitor_time:
            if print_jobs[job_id]['status'] == 'processing':
                print_jobs[job_id]['status'] = 'completed'
                print_jobs[job_id]['progress'] = 100
                print_jobs[job_id]['message'] += f' (监控超时，已运行{int(elapsed_time/60)}分钟，任务可能已完成)'
            break
        
        try:
            # 使用lpstat检查特定任务的状态
            # lpstat -o <job-id> 检查特定任务
            result = subprocess.run(
                ['lpstat', '-o', job_identifier],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # 任务还在队列中
                output = result.stdout.strip()
                
                # 根据已运行时间调整进度显示
                progress = min(95, int((elapsed_time / 600) * 60))  # 前10分钟到60%
                if elapsed_time > 600:
                    progress = min(95, 60 + int((elapsed_time - 600) / 1800) * 35)  # 10-40分钟到95%
                
                # 检查任务状态
                if 'held' in output.lower():
                    # 任务被暂停
                    print_jobs[job_id]['status'] = 'processing'
                    print_jobs[job_id]['progress'] = min(80, progress)
                elif 'processing' in output.lower() or 'is printing' in output.lower():
                    # 任务正在打印
                    print_jobs[job_id]['status'] = 'processing'
                    print_jobs[job_id]['progress'] = min(95, max(60, progress))
                else:
                    # 任务在队列中等待
                    print_jobs[job_id]['status'] = 'processing'
                    print_jobs[job_id]['progress'] = min(60, progress)
            else:
                # 任务不在活动队列中，检查已完成队列
                completed_result = subprocess.run(
                    ['lpstat', '-W', 'completed', '-o', job_identifier],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if completed_result.returncode == 0:
                    # 任务已完成
                    print_jobs[job_id]['status'] = 'completed'
                    print_jobs[job_id]['progress'] = 100
                    print_jobs[job_id]['message'] += f' (打印完成，耗时{int(elapsed_time)}秒)'
                    break
                
                # 检查未完成的任务（包括暂停、等待等状态）
                not_completed_result = subprocess.run(
                    ['lpstat', '-W', 'not-completed', '-o', job_identifier],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if not_completed_result.returncode == 0:
                    # 任务还在未完成队列中，但不在活动队列
                    # 可能是暂停状态或等待状态
                    output = not_completed_result.stdout.strip()
                    if 'held' in output.lower() or 'paused' in output.lower():
                        print_jobs[job_id]['status'] = 'processing'
                        print_jobs[job_id]['message'] += ' (任务已暂停)'
                        print_jobs[job_id]['progress'] = min(80, int((elapsed_time / 600) * 60))
                    else:
                        # 其他状态，继续监控
                        print_jobs[job_id]['status'] = 'processing'
                        print_jobs[job_id]['progress'] = min(80, int((elapsed_time / 600) * 60))
                else:
                    # 任务不在未完成队列中，检查所有队列
                    all_result = subprocess.run(
                        ['lpstat', '-W', 'all', '-o', job_identifier],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if all_result.returncode == 0:
                        # 任务在历史记录中，但不在活动和已完成队列
                        output = all_result.stdout.strip()
                        if 'aborted' in output.lower() or 'canceled' in output.lower() or 'cancelled' in output.lower():
                            print_jobs[job_id]['status'] = 'cancelled'
                            print_jobs[job_id]['message'] += ' (任务已取消)'
                            break
                        else:
                            # 其他未知状态，可能是失败或异常
                            print_jobs[job_id]['status'] = 'completed'
                            print_jobs[job_id]['progress'] = 100
                            print_jobs[job_id]['message'] += ' (任务状态未知，已停止监控)'
                            break
                    else:
                        # 任务完全不存在于任何队列
                        # 可能是任务创建失败或已被系统清理
                        print_jobs[job_id]['status'] = 'completed'
                        print_jobs[job_id]['progress'] = 100
                        print_jobs[job_id]['message'] += ' (任务已完成或被系统清理)'
                        break
            
            # 动态调整监控间隔
            if elapsed_time < 600:  # 前10分钟：每2秒检查一次
                time.sleep(2)
            elif elapsed_time < 1800:  # 10-30分钟：每10秒检查一次
                time.sleep(10)
            elif elapsed_time < 3600:  # 30-60分钟：每30秒检查一次
                time.sleep(30)
            else:  # 60分钟以上：每60秒检查一次
                time.sleep(60)
            
        except Exception as e:
            print(f"监控任务进度失败: {e}")
            # 出错时等待较长时间再重试
            time.sleep(10)


def get_print_queue():
    """获取打印队列状态"""
    try:
        result = subprocess.run(['lpstat', '-o'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            queue = []
            for line in lines:
                if line.strip():
                    # lpstat -o 输出格式: "printer-name-123    username    1024   filename"
                    parts = [part for part in line.split() if part]
                    if len(parts) >= 4:
                        # 第一部分是 printer-jobID
                        job_info = parts[0]
                        queue.append({
                            'job_id': job_info.split('-')[-1] if '-' in job_info else job_info,
                            'user': parts[1],
                            'size': parts[2],
                            'filename': ' '.join(parts[3:]),
                            'printer': job_info.rsplit('-', 1)[0] if '-' in job_info else job_info
                        })
            return queue
    except Exception as e:
        print(f"获取打印队列失败: {e}")
    return []


def get_printer_queue(printer_name):
    """获取特定打印机的队列信息"""
    queue = []
    status = "unknown"
    
    try:
        # 获取打印队列
        result = subprocess.run(['lpstat', '-o'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    # lpstat -o 输出格式: "printer-name-123    username    1024   filename"
                    parts = [part for part in line.split() if part]
                    if len(parts) >= 4:
                        # 第一部分是 printer-jobID
                        job_info = parts[0]
                        # 检查是否属于指定打印机
                        if job_info.startswith(f"{printer_name}-"):
                            queue.append({
                                'job_id': job_info.split('-')[-1],
                                'user': parts[1],
                                'size': parts[2],
                                'filename': ' '.join(parts[3:])
                            })
    except Exception as e:
        logger.error(f"获取打印队列失败: {e}")
    
    try:
        # 获取打印机状态
        printer_status = subprocess.run(
            ['lpstat', '-p', printer_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if printer_status.returncode == 0:
            status_line = printer_status.stdout.strip()
            if "idle" in status_line.lower():
                status = "idle"
            elif "printing" in status_line.lower():
                status = "printing"
            elif "disabled" in status_line.lower():
                status = "disabled"
        else:
            logger.warning(f"获取打印机状态失败: {printer_status.stderr}")
    except Exception as e:
        logger.error(f"获取打印机状态失败: {e}")
    
    # 总是返回队列信息，即使状态获取失败
    return {
        'printer': printer_name,
        'status': status,
        'queue': queue,
        'queue_length': len(queue)
    }

@app.route('/')
def index():
    """主页面"""
    return render_template('index.html')

@app.route('/screenshots/<path:filename>')
def serve_screenshots(filename):
    """提供截图文件访问"""
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'screenshots'), filename)

@app.route('/api/printers', methods=['GET'])
def api_printers():
    """获取可用打印机列表"""
    printers = get_printers()
    return jsonify({'printers': printers})

@app.route('/api/upload', methods=['POST'])
def api_upload():
    """上传文件"""
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # 获取文件名和扩展名
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            
            # 添加时间戳避免文件名冲突
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{name}_{timestamp}{ext}"
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return jsonify({
                'success': True,
                'filename': filename,
                'filepath': filepath
            })
        except Exception as e:
            return jsonify({'error': f'文件保存失败: {str(e)}'}), 500
    
    return jsonify({'error': '不支持的文件类型'}), 400

@app.route('/api/preview/<path:filename>', methods=['GET'])
def api_preview(filename):
    """获取文件预览"""
    try:
        preview_file = get_preview_file(filename)
        
        if not preview_file:
            # 无法获取预览文件
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            document_extensions = ['doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'rtf', 'txt']
            
            if ext in document_extensions:
                # 文档文件需要LibreOffice转换
                return jsonify({
                    'error': '文档转换失败',
                    'message': 'LibreOffice未安装或不可用，无法预览此文档',
                    'solution': '请安装LibreOffice: sudo apt-get install libreoffice'
                }), 500
            else:
                return jsonify({'error': '无法预览此文件'}), 404
        
        if os.path.exists(preview_file):
            # 获取文件所在的目录
            preview_dir = os.path.dirname(preview_file)
            preview_filename = os.path.basename(preview_file)
            
            # 根据文件类型设置Content-Type
            if preview_file.lower().endswith('.pdf'):
                # 手动创建响应，确保inline显示
                response = send_from_directory(
                    preview_dir, 
                    preview_filename, 
                    mimetype='application/pdf'
                )
                # 强制设置Content-Disposition为inline，移除filename参数
                response.headers['Content-Disposition'] = 'inline'
                return response
            else:
                # 图片文件
                ext = preview_file.rsplit('.', 1)[1].lower()
                mime_types = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif',
                    'bmp': 'image/bmp',
                    'svg': 'image/svg+xml'
                }
                return send_from_directory(
                    preview_dir, 
                    preview_filename, 
                    mimetype=mime_types.get(ext, 'application/octet-stream')
                )
        else:
            return jsonify({'error': '预览文件不存在'}), 404
    except Exception as e:
        logger.error(f"获取预览失败: {e}")
        return jsonify({'error': f'预览失败: {str(e)}'}), 500

@app.route('/api/files', methods=['GET'])
def api_list_files():
    """获取已上传的文件列表"""
    try:
        files = []
        upload_folder = app.config['UPLOAD_FOLDER']

        if os.path.exists(upload_folder):
            for filename in os.listdir(upload_folder):
                filepath = os.path.join(upload_folder, filename)
                if os.path.isfile(filepath):
                    # 获取文件信息
                    stat = os.stat(filepath)
                    files.append({
                        'filename': filename,
                        'filepath': filepath,
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'type': get_file_type(filename)
                    })

        # 按修改时间倒序排列（最新的在前）
        files.sort(key=lambda x: x['mtime'], reverse=True)

        return jsonify({'success': True, 'files': files})
    except Exception as e:
        logger.error(f"获取文件列表失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<path:filename>', methods=['DELETE'])
def api_delete_file(filename):
    """删除上传的文件"""
    # 获取安全的文件路径
    filepath = get_safe_path(app.config['UPLOAD_FOLDER'], filename)
    
    if not filepath:
        logger.warning(f"非法文件路径访问尝试: {filename}")
        return jsonify({'error': '非法文件路径'}), 403
    
    if os.path.exists(filepath):
        try:
            # 删除原始文件
            os.remove(filepath)
            
            # 同时删除对应的预览文件（如果存在）
            # 对于文档文件，预览文件会保存在PREVIEW_FOLDER
            name, ext = os.path.splitext(filename)
            if is_document_file(filename) and not ext.lower().endswith('.pdf'):
                # 文档文件的预览是转换后的PDF
                preview_pdf = get_safe_path(app.config['PREVIEW_FOLDER'], f"{name}.pdf")
                if preview_pdf and os.path.exists(preview_pdf):
                    try:
                        os.remove(preview_pdf)
                        logger.info(f"已删除预览文件: {preview_pdf}")
                    except Exception as e:
                        logger.warning(f"删除预览文件失败: {e}")
                        # 不影响主流程，继续
            
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"删除文件失败: {e}")
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': '文件不存在'}), 404

def validate_page_range(page_range):
    """验证页面范围格式"""
    import re
    # 允许的格式: "1", "1-5", "1-5,8", "1-5,8,10-12"
    pattern = r'^(\d+(-\d+)?)(,\s*\d+(-\d+)?)*$'
    return bool(re.match(pattern, page_range))

@app.route('/api/print', methods=['POST'])
def api_print():
    """提交打印任务"""
    logger.info("=" * 80)
    logger.info("接收到打印请求")

    # 记录原始数据
    logger.info(f"原始数据: {request.data}")

    try:
        data = request.json
        logger.info(f"解析后的JSON: {json.dumps(data, indent=2, ensure_ascii=False)}")
    except Exception as e:
        logger.error(f"JSON解析失败: {e}")
        return jsonify({'error': '请求数据格式错误'}), 400

    filepath = data.get('filepath')
    printer_name = data.get('printer')
    color_mode = data.get('color_mode', 'mono')  # 默认改为mono（黑白）
    duplex = data.get('duplex', 'one-sided')
    orientation = data.get('orientation', 'portrait')
    paper_size = data.get('paper_size', 'A4')
    paper_type = data.get('paper_type', 'plain')
    copies = data.get('copies', '1')
    page_range = data.get('page_range', None)

    # 记录解析后的参数
    logger.info(f"解析后的参数:")
    logger.info(f"  filepath: {filepath}")
    logger.info(f"  printer_name: {printer_name}")
    logger.info(f"  color_mode: {color_mode}")
    logger.info(f"  duplex: {duplex}")
    logger.info(f"  orientation: {orientation}")
    logger.info(f"  paper_size: {paper_size}")
    logger.info(f"  paper_type: {paper_type}")
    logger.info(f"  copies: {copies}")
    logger.info(f"  page_range: {page_range}")

    # 基本参数验证
    if not filepath or not printer_name:
        return jsonify({'error': '缺少必要参数'}), 400

    if not os.path.exists(filepath):
        return jsonify({'error': '文件不存在'}), 404

    # 验证纸张大小
    valid_paper_sizes = ['A4', 'A3', 'A2', 'A1', '5inch', '6inch', '7inch', '8inch', '10inch']
    if paper_size not in valid_paper_sizes:
        return jsonify({'error': f'无效的纸张大小，支持的格式: {", ".join(valid_paper_sizes)}'}), 400

    # 验证纸张材质
    valid_paper_types = ['plain', 'glossy']
    if paper_type not in valid_paper_types:
        return jsonify({'error': f'无效的纸张材质，支持的类型: {", ".join(valid_paper_types)}'}), 400

    # 验证打印份数
    try:
        copies = int(copies)
        if copies < 1 or copies > 100:
            return jsonify({'error': '打印份数必须在1-100之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': '打印份数必须是数字'}), 400

    # 验证色彩模式
    if color_mode not in ['color', 'mono']:
        return jsonify({'error': '色彩模式无效，必须是 color 或 mono'}), 400

    # 验证双面设置
    if duplex not in ['one-sided', 'two-sided-long-edge', 'two-sided-short-edge']:
        return jsonify({'error': '双面设置无效'}), 400

    # 验证打印方向
    if orientation not in ['portrait', 'landscape']:
        return jsonify({'error': '打印方向无效，必须是 portrait 或 landscape'}), 400

    # 验证页面范围格式（可选）
    if page_range and page_range.strip():
        if not validate_page_range(page_range.strip()):
            return jsonify({'error': '页面范围格式无效，示例: 1-5,8,10-12'}), 400
        page_range = page_range.strip()

    job_id, success = submit_print_job(filepath, printer_name, color_mode, duplex, orientation, paper_size, paper_type, copies, page_range)
    
    if success:
        return jsonify({
            'success': True,
            'job_id': job_id,
            'job': print_jobs[job_id]
        })
    else:
        return jsonify({
            'success': False,
            'error': print_jobs[job_id]['message']
        }), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
def api_job_status(job_id):
    """获取任务状态"""
    if job_id in print_jobs:
        return jsonify({'job': print_jobs[job_id]})
    return jsonify({'error': '任务不存在'}), 404

@app.route('/api/jobs', methods=['GET'])
def api_all_jobs():
    """获取所有任务"""
    return jsonify({'jobs': list(print_jobs.values())})

@app.route('/api/jobs/<job_id>', methods=['DELETE'])
def api_cancel_job(job_id):
    """取消打印任务"""
    if job_id not in print_jobs:
        return jsonify({'error': '任务不存在'}), 404
    
    job = print_jobs[job_id]
    
    # 检查任务是否已经完成
    if job['status'] in ['completed', 'failed', 'error']:
        return jsonify({'error': '任务已经结束，无法取消'}), 400
    
    # 尝试取消CUPS任务
    if job['cups_job_id']:
        try:
            result = subprocess.run(
                ['cancel', job['cups_job_id']],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print_jobs[job_id]['status'] = 'cancelled'
                return jsonify({
                    'success': True,
                    'message': '打印任务已取消'
                })
            else:
                return jsonify({
                    'success': False,
                    'error': result.stderr
                }), 500
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    else:
        # 如果没有cups_job_id，标记为取消
        print_jobs[job_id]['status'] = 'cancelled'
        return jsonify({
            'success': True,
            'message': '任务已标记为取消'
        })

@app.route('/api/queue', methods=['GET'])
def api_queue():
    """获取打印队列"""
    queue = get_print_queue()
    return jsonify({'queue': queue})

@app.route('/api/printer-queue/<printer_name>', methods=['GET'])
def api_printer_queue(printer_name):
    """获取特定打印机的队列信息"""
    queue_info = get_printer_queue(printer_name)
    return jsonify(queue_info)

@app.route('/api/printer-tray/<printer_name>', methods=['GET'])
def api_printer_tray_info(printer_name):
    """获取打印机纸盒信息（纸张余量、大小、材质等）"""
    try:
        tray_info = {
            'printer': printer_name,
            'trays': []
        }

        # 判断打印机类型
        is_virtual = False
        is_ipp_printer = False
        printer_uri = None

        try:
            result = subprocess.run(
                ['lpstat', '-p', printer_name, '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )

            # 先查找与当前打印机名称匹配的device行
            import re
            matched_device_uri = None

            for line in result.stdout.split('\n'):
                # 匹配: device for PrinterName: URI
                match = re.search(r'device\s+for\s+' + re.escape(printer_name) + r':\s*(\S+)', line)
                if match:
                    matched_device_uri = match.group(1).strip()
                    break

            if matched_device_uri:
                # 根据匹配到的URI判断打印机类型
                if 'cups-pdf:' in matched_device_uri or 'file://' in matched_device_uri:
                    is_virtual = True
                elif matched_device_uri.startswith('ipp') or matched_device_uri.startswith('http') or matched_device_uri.startswith('ipps'):
                    is_ipp_printer = True
                    printer_uri = matched_device_uri
                    logger.info(f"提取到打印机URI: {printer_uri}")
        except Exception as e:
            logger.warning(f"检测打印机类型失败: {e}")

        if is_virtual:
            # 虚拟打印机，返回模拟的纸盒信息
            tray_info['trays'].append({
                'name': '默认纸盒',
                'type': '默认',
                'status_cn': '未知',
                'status': 'unknown',
                'media_ready': 'iso_a4_210x297mm',
                'note': '虚拟打印机不支持实时纸盒信息'
            })
            tray_info['source'] = '模拟数据（虚拟打印机）'

        elif is_ipp_printer and printer_uri and IPPTOOL_AVAILABLE:
            # IPP网络打印机，尝试通过ipptool获取真实纸盒信息
            logger.info(f"尝试通过ipptool获取打印机 {printer_name} 的纸盒信息: {printer_uri}")
            try:
                from ipp_client import get_tray_info_via_ipptool
                trays = get_tray_info_via_ipptool(printer_uri)
                if trays:
                    tray_info['trays'].extend(trays)
                    tray_info['source'] = f'ipptool（真实打印机）: {printer_uri}'
                else:
                    # ipptool获取失败，返回详细错误信息
                    logger.warning(f"通过ipptool获取纸盒信息失败，返回空列表")
                    tray_info['source'] = 'ipptool（无法获取数据）'
                    tray_info['error'] = f'通过ipptool从 {printer_uri} 获取纸盒信息成功，但返回空列表'
                    tray_info['details'] = '打印机可能不支持纸盒信息查询，或IPP端点不正确'
            except Exception as e:
                logger.error(f"通过ipptool获取纸盒信息失败: {e}")
                import traceback
                traceback.print_exc()
                tray_info['source'] = 'ipptool（查询失败）'
                tray_info['error'] = str(e)
                tray_info['details'] = traceback.format_exc()

        elif is_ipp_printer and printer_uri and not IPPTOOL_AVAILABLE:
            # ipptool不可用，返回模拟数据
            tray_info['trays'].append({
                'name': '默认纸盒',
                'type': '默认',
                'status_cn': '未知',
                'status': 'unknown',
                'media_ready': 'iso_a4_210x297mm',
                'note': 'ipptool不可用，无法获取实时纸盒信息'
            })
            tray_info['source'] = '模拟数据（ipptool不可用）'

        else:
            # 其他类型的打印机，返回模拟数据
            tray_info['trays'].append({
                'name': '默认纸盒',
                'type': '默认',
                'status_cn': '未知',
                'status': 'unknown',
                'media_ready': 'iso_a4_210x297mm',
                'note': '不支持实时纸盒信息查询'
            })
            tray_info['source'] = '模拟数据（不支持IPP协议）'

        return jsonify(tray_info)

    except Exception as e:
        logger.error(f"获取纸盒信息失败: {e}")
        return jsonify({'error': f'获取纸盒信息失败: {str(e)}'}), 500

@app.route('/api/printer-ink/<printer_name>', methods=['GET'])
def api_printer_ink_info(printer_name):
    """获取打印机墨盒信息（黑白和彩色墨盒余量）"""
    try:
        ink_info = {
            'printer': printer_name,
            'cartridges': []
        }

        # 判断打印机类型
        is_virtual = False
        is_ipp_printer = False
        printer_uri = None

        try:
            result = subprocess.run(
                ['lpstat', '-p', printer_name, '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )

            # 先查找与当前打印机名称匹配的device行
            import re
            matched_device_uri = None

            for line in result.stdout.split('\n'):
                # 匹配: device for PrinterName: URI
                match = re.search(r'device\s+for\s+' + re.escape(printer_name) + r':\s*(\S+)', line)
                if match:
                    matched_device_uri = match.group(1).strip()
                    break

            if matched_device_uri:
                # 根据匹配到的URI判断打印机类型
                if 'cups-pdf:' in matched_device_uri or 'file://' in matched_device_uri:
                    is_virtual = True
                elif matched_device_uri.startswith('ipp') or matched_device_uri.startswith('http') or matched_device_uri.startswith('ipps'):
                    is_ipp_printer = True
                    printer_uri = matched_device_uri
                    logger.info(f"提取到打印机URI: {printer_uri}")
        except Exception as e:
            logger.warning(f"检测打印机类型失败: {e}")

        if is_virtual:
            # 虚拟打印机（如CUPS-PDF），返回模拟的墨盒信息
            ink_info['cartridges'].extend([
                {
                    'name': '黑色墨盒',
                    'color': '#000000',
                    'type': 'ink-cartridge',
                    'level': 100
                },
                {
                    'name': '青色墨盒',
                    'color': '#00FFFF',
                    'type': 'ink-cartridge',
                    'level': 100
                },
                {
                    'name': '品红色墨盒',
                    'color': '#FF00FF',
                    'type': 'ink-cartridge',
                    'level': 100
                },
                {
                    'name': '黄色墨盒',
                    'color': '#FFFF00',
                    'type': 'ink-cartridge',
                    'level': 100
                }
            ])
            ink_info['source'] = '模拟数据（虚拟打印机）'

        elif is_ipp_printer and printer_uri and IPPTOOL_AVAILABLE:
            # IPP网络打印机，尝试通过ipptool获取真实墨盒信息
            logger.info(f"尝试通过ipptool获取打印机 {printer_name} 的墨盒信息: {printer_uri}")
            try:
                from ipp_client import get_ink_info_via_ipptool
                cartridges = get_ink_info_via_ipptool(printer_uri)
                if cartridges:
                    ink_info['cartridges'].extend(cartridges)
                    ink_info['source'] = f'ipptool（真实打印机）: {printer_uri}'
                else:
                    # ipptool获取失败，返回详细错误信息
                    logger.warning(f"通过ipptool获取墨盒信息失败，返回空列表")
                    ink_info['source'] = 'ipptool（无法获取数据）'
                    ink_info['error'] = f'通过ipptool从 {printer_uri} 获取墨盒信息成功，但返回空列表'
                    ink_info['details'] = '打印机可能不支持墨盒信息查询，或IPP端点不正确'
            except Exception as e:
                logger.error(f"通过ipptool获取墨盒信息失败: {e}")
                import traceback
                traceback.print_exc()
                ink_info['source'] = 'ipptool（查询失败）'
                ink_info['error'] = str(e)
                ink_info['details'] = traceback.format_exc()

        elif is_ipp_printer and printer_uri and not IPPTOOL_AVAILABLE:
            # ipptool不可用，返回模拟数据
            ink_info['cartridges'].extend([
                {
                    'name': '黑色墨盒',
                    'color': '#000000',
                    'type': 'ink-cartridge',
                    'level': 85
                },
                {
                    'name': '彩色墨盒',
                    'color': '#FF0000',
                    'type': 'ink-cartridge',
                    'level': 70
                }
            ])
            ink_info['source'] = '模拟数据（ipptool不可用）'
            ink_info['note'] = 'ipptool不可用，无法获取真实墨盒信息。请安装相关依赖或使用模拟数据。'

        else:
            # 其他类型的打印机，返回模拟数据
            ink_info['cartridges'].extend([
                {
                    'name': '黑色墨盒',
                    'color': '#000000',
                    'type': 'ink-cartridge',
                    'level': 85
                },
                {
                    'name': '彩色墨盒',
                    'color': '#FF0000',
                    'type': 'ink-cartridge',
                    'level': 70
                }
            ])
            ink_info['source'] = '模拟数据（不支持IPP协议）'
            ink_info['note'] = '如需获取真实墨盒信息，请使用支持IPP协议的网络打印机，或配置SNMP/打印机厂商API'

        return jsonify(ink_info)

    except Exception as e:
        logger.error(f"获取墨盒信息失败: {e}")
        return jsonify({'error': f'获取墨盒信息失败: {str(e)}'}), 500

@app.route('/api/printer-diagnose/<printer_name>', methods=['GET'])
def api_printer_diagnose(printer_name):
    """诊断打印机信息（调试用）"""
    try:
        diagnose_info = {
            'printer': printer_name,
            'timestamp': datetime.now().isoformat()
        }

        # 1. 获取打印机URI
        result = subprocess.run(
            ['lpstat', '-p', printer_name, '-v'],
            capture_output=True,
            text=True,
            timeout=5
        )

        diagnose_info['lpstat_output'] = result.stdout

        # 2. 提取URI
        import re
        printer_uri = None
        is_ipp_printer = False

        for line in result.stdout.split('\n'):
            match = re.search(r'device\s+for\s+' + re.escape(printer_name) + r':\s*(\S+)', line)
            if match:
                printer_uri = match.group(1).strip()
                diagnose_info['matched_uri'] = printer_uri
                diagnose_info['uri_type'] = 'matched'
                break

        if not printer_uri and 'ipp:' in result.stdout:
            diagnose_info['uri_type'] = 'fallback'
            for line in result.stdout.split('\n'):
                if 'device for' in line:
                    match = re.search(r'device\s+for\s+\S+:\s*(\S+)', line)
                    if match:
                        printer_uri = match.group(1).strip()
                        diagnose_info['fallback_uri'] = printer_uri
                        break

        diagnose_info['printer_uri'] = printer_uri

        # 3. 判断打印机类型
        if printer_uri:
            if 'cups-pdf:' in printer_uri or 'file://' in printer_uri:
                diagnose_info['printer_type'] = 'virtual'
            elif printer_uri.startswith('ipp') or printer_uri.startswith('http') or printer_uri.startswith('ipps'):
                diagnose_info['printer_type'] = 'ipp'
                is_ipp_printer = True
            else:
                diagnose_info['printer_type'] = 'other'
                diagnose_info['note'] = f'未知URI类型: {printer_uri[:20]}...'

        # 4. 检查IPP客户端
        diagnose_info['ipp_available'] = IPP_AVAILABLE

        # 5. 尝试IPP请求
        if is_ipp_printer and printer_uri and IPP_AVAILABLE:
            try:
                cartridges = get_ink_info_via_ipp(printer_uri, timeout=5)
                if cartridges:
                    diagnose_info['ipp_test'] = 'success'
                    diagnose_info['ipp_cartridges'] = cartridges
                else:
                    diagnose_info['ipp_test'] = 'no_data'
            except Exception as e:
                diagnose_info['ipp_test'] = 'error'
                diagnose_info['ipp_error'] = str(e)

        return jsonify(diagnose_info)

    except Exception as e:
        logger.error(f"诊断打印机失败: {e}")
        return jsonify({'error': f'诊断失败: {str(e)}'}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """访问上传的文件"""
    # 防止路径遍历攻击
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        return jsonify({'error': '无效的文件名'}), 400
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)

if __name__ == '__main__':
    print("=" * 60)
    print("Web打印服务启动中...")
    print("=" * 60)
    print(f"服务地址: http://localhost:5000")
    print(f"上传目录: {os.path.abspath(app.config['UPLOAD_FOLDER'])}")
    print("=" * 60)
    
    # 尝试获取可用打印机
    printers = get_printers()
    if printers:
        print(f"检测到 {len(printers)} 台打印机:")
        for p in printers:
            print(f"  - {p['name']}")
    else:
        print("警告: 未检测到可用打印机")
        print("请确保CUPS服务已启动并配置了网络打印机")
        print("安装方法: sudo apt-get install cups")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
