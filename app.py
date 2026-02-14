#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web打印服务 - 基于Python Flask + CUPS
支持文档/图片上传、打印设置、队列管理
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
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
    from ipp_client import IPPClient, get_ink_info_via_ipp
    IPP_AVAILABLE = True
except ImportError:
    IPP_AVAILABLE = False
    logging.warning("IPP客户端不可用，墨盒信息将返回模拟数据")

app = Flask(__name__)
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

def get_printer_homepage_url(printer_name, printer_uri=None):
    """
    获取打印机主页URL

    尝试多个常见路径，找到可访问的墨盒信息页面

    Args:
        printer_name: 打印机名称
        printer_uri: 打印机URI（可选）

    Returns:
        打印机主页URL，如果无法获取则返回None
    """
    import re
    from urllib.parse import urlparse

    # 如果未提供URI，从lpstat获取
    if not printer_uri:
        try:
            result = subprocess.run(
                ['lpstat', '-p', printer_name, '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'device\s+for\s+' + re.escape(printer_name) + r':\s*(\S+)', line)
                if match:
                    printer_uri = match.group(1).strip()
                    break
        except Exception as e:
            logger.warning(f"获取打印机URI失败: {e}")

    if not printer_uri:
        logger.warning(f"无法获取打印机 {printer_name} 的URI")
        return None

    # 从IPP URI中提取基础URL
    if printer_uri.startswith('ipp://'):
        url = printer_uri.replace('ipp://', 'http://')
    elif printer_uri.startswith('ipps://'):
        url = printer_uri.replace('ipps://', 'https://')
    elif printer_uri.startswith('http://'):
        url = printer_uri
    elif printer_uri.startswith('https://'):
        url = printer_uri
    else:
        url = 'http://' + printer_uri

    # 提取基础URL（协议+主机+端口）
    url_parts = urlparse(url)
    base_url = f"{url_parts.scheme}://{url_parts.netloc}"

    # 尝试多个常见路径（按优先级排序）
    common_paths = [
        '/index.html',                    # 通用
        '/home.html',                     # 通用
        '/main.html',                     # 通用
        '/status.html',                   # 通用状态页
        '/net/printer/status',            # Canon打印机常用
        '/net/printer/main.html',         # Canon打印机常用
        '/printer',                       # 简单路径
        '/web/guest/en/websys/webArch/mainPage.cgi',  # HP打印机
        '/hp/device/this.LCDispatcher?nav=hp.Print',  # HP打印机
        '/dev/home/devhome.html',         # Brother打印机
        '/index_status.html',             # 变体
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    logger.info(f"尝试获取打印机 {printer_name} 的主页，基础URL: {base_url}")

    # 导入requests（在函数内部导入以避免模块级导入问题）
    try:
        import requests
    except ImportError:
        logger.warning("requests模块未安装，无法测试路径")
        return base_url + '/index.html'

    # 尝试每个路径
    for path in common_paths:
        test_url = base_url + path
        logger.info(f"  尝试路径: {test_url}")

        try:
            response = requests.get(test_url, headers=headers, timeout=5, verify=False)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                # 检查是否是HTML内容
                if 'text/html' in content_type or not content_type:
                    content_length = len(response.text)
                    logger.info(f"  ✓ 找到可用主页: {test_url} ({content_length} 字节)")
                    # 检查是否包含墨盒相关信息
                    if 'ink' in response.text.lower() or 'toner' in response.text.lower():
                        logger.info(f"  ✓ 包含墨盒相关信息！")
                    return test_url
                else:
             