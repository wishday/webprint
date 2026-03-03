#!/usr/bin/env python3
"""
通过IPP协议获取打印机墨盒和纸盒信息
使用 ipptool 命令行工具提取信息
"""

import subprocess
import logging
import re

logger = logging.getLogger(__name__)

# 检查 ipptool 是否可用
def check_ipptool_available():
    """检查 ipptool 命令是否可用"""
    try:
        result = subprocess.run(
            ['which', 'ipptool'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

IPPTOOL_AVAILABLE = check_ipptool_available()

def get_ink_info_via_ipptool(printer_url):
    """
    使用 ipptool 获取墨盒信息

    Args:
        printer_url: 打印机URL，如 "ipp://192.168.1.100:631/ipp/print"

    Returns:
        墨盒信息列表，格式：
        [
            {
                'name': 'Black(PGBK)',
                'color': '#000000',
                'type': 'ink-cartridge',
                'level': 90
            },
            ...
        ]
    """
    if not IPPTOOL_AVAILABLE:
        logger.warning("ipptool 不可用，无法获取墨盒信息")
        return []

    try:
        # 使用 ipptool 获取打印机属性
        test_file = '/usr/share/cups/ipptool/get-printer-attributes.test'
        cmd = ['ipptool', '-tv', printer_url, test_file]

        logger.debug(f"执行命令: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            logger.error(f"ipptool 执行失败: {result.stderr}")
            return []

        # 解析输出
        output = result.stdout

        # 提取墨盒信息
        marker_names = _parse_ipp_attribute(output, 'marker-names')
        marker_colors = _parse_ipp_attribute(output, 'marker-colors')
        marker_types = _parse_ipp_attribute(output, 'marker-types')
        marker_levels = _parse_ipp_attribute(output, 'marker-levels')

        # 构建墨盒信息列表
        ink_cartridges = []
        for i in range(len(marker_names)):
            name = marker_names[i] if i < len(marker_names) else f'墨盒 {i+1}'
            color = marker_colors[i] if i < len(marker_colors) else 'unknown'
            level_type = marker_types[i] if i < len(marker_types) else 'unknown'
            level = marker_levels[i] if i < len(marker_levels) else 0

            # 过滤废墨盒
            if level_type == 'waste-ink':
                continue

            ink_cartridges.append({
                'name': name,
                'color': color,
                'type': level_type,
                'level': level
            })

        logger.debug(f"提取到 {len(ink_cartridges)} 个墨盒信息")
        return ink_cartridges

    except Exception as e:
        logger.error(f"获取墨盒信息失败: {e}")
        return []

def get_tray_info_via_ipptool(printer_url):
    """
    使用 ipptool 获取纸盒信息

    Args:
        printer_url: 打印机URL，如 "ipp://192.168.1.100:631/ipp/print"

    Returns:
        纸盒信息列表，格式：
        [
            {
                'name': 'auto',
                'type': 'auto',
                'status': 'ready',
                'status_cn': '可用',
                'media_ready': 'iso_a4_210x297mm'
            },
            ...
        ]
    """
    if not IPPTOOL_AVAILABLE:
        logger.warning("ipptool 不可用，无法获取纸盒信息")
        return []

    try:
        # 使用 ipptool 获取打印机属性
        test_file = '/usr/share/cups/ipptool/get-printer-attributes.test'
        cmd = ['ipptool', '-tv', printer_url, test_file]

        logger.debug(f"执行命令: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            logger.error(f"ipptool 执行失败: {result.stderr}")
            return []

        # 解析输出
        output = result.stdout

        # 提取纸盒信息
        media_sources = _parse_ipp_attribute(output, 'media-source-supported')

        # 提取 printer-input-tray
        printer_tray_info = _parse_printer_input_tray(output)

        # 提取 media-ready
        media_ready_match = re.search(r'media-ready\s*\([^)]+\)\s*=\s*([^\s]+)', output)
        media_ready = media_ready_match.group(1) if media_ready_match else None

        # 构建纸盒信息列表
        trays = []
        for i, tray_info in enumerate(printer_tray_info):
            name = tray_info.get('name', f'纸盒 {i+1}')
            tray_type = tray_info.get('type', media_sources[i] if i < len(media_sources) else 'unknown')
            status = tray_info.get('status', 'unknown')

            # 根据状态码映射中文状态
            status_map = {
                '3': '空',
                '4': '已装载',
                '5': '可用',
                '6': '移除'
            }
            status_cn = status_map.get(status, '未知')

            trays.append({
                'name': name,
                'type': tray_type,
                'status': status,
                'status_cn': status_cn,
                'media_ready': media_ready
            })

        logger.debug(f"提取到 {len(trays)} 个纸盒信息")
        return trays

    except Exception as e:
        logger.error(f"获取纸盒信息失败: {e}")
        return []

def _parse_ipp_attribute(output, attribute_name):
    """
    从 ipptool 输出中解析 IPP 属性

    Args:
        output: ipptool 输出文本
        attribute_name: 属性名称

    Returns:
        属性值列表
    """
    pattern = rf'{attribute_name}\s*\([^)]+\)\s*=\s*(.+)'
    match = re.search(pattern, output)

    if not match:
        logger.debug(f"未找到属性: {attribute_name}")
        return []

    values_str = match.group(1)

    # 分割值（按逗号）
    values = [v.strip() for v in values_str.split(',')]

    return values

def _parse_printer_input_tray(output):
    """
    从 ipptool 输出中解析 printer-input-tray

    Args:
        output: ipptool 输出文本

    Returns:
        纸盒信息列表
    """
    pattern = r'printer-input-tray\s*\([^)]+\)\s*=\s*(.+)'
    match = re.search(pattern, output)

    if not match:
        logger.debug("未找到 printer-input-tray 属性")
        return []

    values_str = match.group(1)

    # 分割多个纸盒（按 ;, 分隔）
    trays = []
    for tray_str in values_str.split(';,'):
        # 解析键值对
        tray_info = {}
        for kv in tray_str.split(';'):
            if '=' in kv:
                key, value = kv.split('=', 1)
                tray_info[key.strip()] = value.strip()
        trays.append(tray_info)

    return trays


# 测试函数
if __name__ == '__main__':
    # 示例：获取IPP打印机的墨盒信息
    printer_url = 'ipp://192.168.1.100:631/ipp/print'

    if not IPPTOOL_AVAILABLE:
        print("ipptool 不可用，请安装 CUPS")
    else:
        print("获取墨盒信息...")
        cartridges = get_ink_info_via_ipptool(printer_url)

        if cartridges:
            print("墨盒信息:")
            for cartridge in cartridges:
                print(f"  {cartridge['name']}: {cartridge['level']}%")
        else:
            print("无法获取墨盒信息")

        print("\n获取纸盒信息...")
        trays = get_tray_info_via_ipptool(printer_url)

        if trays:
            print("纸盒信息:")
            for tray in trays:
                print(f"  {tray['name']}: {tray['status_cn']}")
        else:
            print("无法获取纸盒信息")
