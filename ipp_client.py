#!/usr/bin/env python3
"""
通过IPP协议获取打印机墨盒信息
支持IPP协议的网络打印机
"""

import struct
import requests
import socket
import logging

logger = logging.getLogger(__name__)

# 检查requests库是否可用
try:
    import requests
    IPP_AVAILABLE = True
    logger.info("✅ requests库已安装，IPP客户端可用")
except ImportError:
    IPP_AVAILABLE = False
    logger.warning("⚠️  requests库未安装，IPP客户端不可用")

class IPPClient:
    """IPP协议客户端"""

    def __init__(self, printer_url, timeout=10):
        """
        初始化IPP客户端

        Args:
            printer_url: 打印机URL，如 "ipp://192.168.1.100:631/ipp/print"
            timeout: 超时时间（秒）
        """
        self.printer_url = printer_url
        self.timeout = timeout

    def _build_ipp_request(self, operation_id):
        """
        构建IPP请求

        Args:
            operation_id: IPP操作ID

        Returns:
            IPP二进制请求数据
        """
        # IPP版本号 (2.1)
        version = b'\x02\x01'

        # 操作ID (Get-Printer-Attributes = 0x000B)
        operation_id_bytes = struct.pack('!H', operation_id)

        # 请求ID
        request_id = struct.pack('!I', 1)

        # 操作属性组
        attributes_group_tag = b'\x01'
        charset = b'\x47\x00\x12attributes-charset\x00utf-8'
        language = b'\x48\x00\x1battributes-natural-language\x00en-us'

        # 打印机URI属性
        uri = f'uri:{self.printer_url}'.encode('utf-8')
        uri_len = len(uri)
        uri_bytes = b'\x45\x00\x0bprinter-uri\x00' + struct.pack('!H', uri_len) + uri

        # 请求的属性（marker-colors, marker-levels, marker-names）
        requested_attributes = b'\x44\x00\x14requested-attributes\x00' \
                               b'\x00\x14marker-colors,marker-levels,marker-names,marker-types'

        # 结束标签
        end_tag = b'\x03'

        # 组合所有部分
        ipp_request = (version + operation_id_bytes + request_id +
                       attributes_group_tag + charset + language + uri_bytes +
                       requested_attributes + end_tag)

        return ipp_request

    def _parse_ipp_response(self, ipp_response):
        """
        解析IPP响应

        Args:
            ipp_response: IPP二进制响应数据

        Returns:
            解析后的属性字典
        """
        try:
            # 跳过前8字节（版本号、操作ID、请求ID）
            pos = 8

            attributes = {}

            while pos < len(ipp_response):
                # 读取属性组标签
                group_tag = ipp_response[pos:pos+1]
                pos += 1

                # 结束标签
                if group_tag == b'\x03':
                    break

                # 读取属性
                while pos < len(ipp_response):
                    # 读取属性标签
                    tag = ipp_response[pos:pos+1]
                    pos += 1

                    # 如果是结束标签，跳出
                    if tag == b'\x03':
                        break

                    # 读取属性名称长度
                    name_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                    pos += 2

                    # 读取属性名称
                    name = ipp_response[pos:pos+name_len].decode('utf-8')
                    pos += name_len

                    # 读取属性值
                    if tag == b'\x21':  # textWithoutLanguage
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        value = ipp_response[pos:pos+value_len].decode('utf-8')
                        pos += value_len
                    elif tag == b'\x23':  # nameWithoutLanguage
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        value = ipp_response[pos:pos+value_len].decode('utf-8')
                        pos += value_len
                    elif tag == b'\x44':  # keyword
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        value = ipp_response[pos:pos+value_len].decode('utf-8')
                        pos += value_len
                    elif tag == b'\x35':  # enum
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        value = struct.unpack('!I', ipp_response[pos:pos+4])[0]
                        pos += 4
                    elif tag == b'\x22':  # octetString
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        value = ipp_response[pos:pos+value_len]
                        pos += value_len
                    else:
                        # 跳过未知类型
                        value_len = struct.unpack('!H', ipp_response[pos:pos+2])[0]
                        pos += 2
                        pos += value_len

                    attributes[name] = value

            return attributes

        except Exception as e:
            logger.error(f"解析IPP响应失败: {e}")
            return {}

    def get_printer_attributes(self):
        """
        获取打印机属性

        Returns:
            打印机属性字典
        """
        try:
            # 解析打印机URL
            if self.printer_url.startswith('ipp://'):
                url = self.printer_url.replace('ipp://', 'http://')
            elif self.printer_url.startswith('ipps://'):
                url = self.printer_url.replace('ipps://', 'https://')
            else:
                url = 'http://' + self.printer_url

            # 构建IPP请求
            ipp_request = self._build_ipp_request(0x000B)  # Get-Printer-Attributes

            # 发送IPP请求
            headers = {
                'Content-Type': 'application/ipp',
                'Accept': 'application/ipp'
            }

            response = requests.post(
                url,
                data=ipp_request,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                # 解析IPP响应
                attributes = self._parse_ipp_response(response.content)
                return attributes
            else:
                logger.error(f"IPP请求失败: HTTP {response.status_code}")
                return {}

        except Exception as e:
            logger.error(f"获取打印机属性失败: {e}")
            return {}

    def get_ink_levels(self):
        """
        获取墨盒余量

        Returns:
            墨盒信息列表，格式: [{'color': 'black', 'level': 85, 'status': 'OK'}, ...]
        """
        try:
            attributes = self.get_printer_attributes()

            if not attributes:
                return []

            # 解析墨盒信息
            cartridges = []

            # 获取墨盒颜色
            marker_colors = attributes.get('marker-colors', '')
            if isinstance(marker_colors, str):
                marker_colors = marker_colors.split(',')

            # 获取墨盒余量
            marker_levels = attributes.get('marker-levels', '')
            if isinstance(marker_levels, str):
                marker_levels = marker_levels.split(',')
            elif isinstance(marker_levels, list):
                marker_levels = [str(l) for l in marker_levels]

            # 获取墨盒名称
            marker_names = attributes.get('marker-names', '')
            if isinstance(marker_names, str):
                marker_names = marker_names.split(',')

            # 获取墨盒类型
            marker_types = attributes.get('marker-types', '')
            if isinstance(marker_types, str):
                marker_types = marker_types.split(',')

            # 组合墨盒信息
            for i in range(len(marker_colors)):
                try:
                    level = int(marker_levels[i]) if i < len(marker_levels) else 0
                    level = max(0, min(100, level))  # 限制在0-100范围内

                    # 确定状态
                    if level < 10:
                        status = '空'
                    elif level < 20:
                        status = '警告'
                    else:
                        status = '正常'

                    cartridge = {
                        'color': marker_colors[i].lower().strip(),
                        'color_name': self._get_color_name(marker_colors[i]),
                        'level': level,
                        'status': status
                    }

                    if i < len(marker_names):
                        cartridge['name'] = marker_names[i]

                    if i < len(marker_types):
                        cartridge['type'] = marker_types[i]

                    cartridges.append(cartridge)

                except (ValueError, IndexError) as e:
                    logger.warning(f"解析墨盒{ i}信息失败: {e}")
                    continue

            return cartridges

        except Exception as e:
            logger.error(f"获取墨盒余量失败: {e}")
            return []

    def _get_color_name(self, color):
        """
        获取颜色的中文名称

        Args:
            color: 颜色名称

        Returns:
            颜色的中文名称
        """
        color_map = {
            'black': '黑色',
            'cyan': '青色',
            'magenta': '品红色',
            'yellow': '黄色',
            'photo-black': '照片黑',
            'gray': '灰色',
            'photo-gray': '照片灰',
            'light-cyan': '浅青色',
            'light-magenta': '浅品红色',
        }

        return color_map.get(color.lower(), color)


def get_ink_info_via_ipp(printer_url, timeout=10):
    """
    通过IPP协议获取打印机墨盒信息

    Args:
        printer_url: 打印机IPP URL，如 "ipp://192.168.1.100:631/ipp/print"
        timeout: 超时时间（秒）

    Returns:
        墨盒信息列表
    """
    try:
        client = IPPClient(printer_url, timeout)
        cartridges = client.get_ink_levels()
        return cartridges

    except Exception as e:
        logger.error(f"通过IPP获取墨盒信息失败: {e}")
        return []


# 测试函数
if __name__ == '__main__':
    # 示例：获取IPP打印机的墨盒信息
    printer_url = 'ipp://192.168.1.100:631/ipp/print'
    cartridges = get_ink_info_via_ipp(printer_url)

    if cartridges:
        print("墨盒信息:")
        for cartridge in cartridges:
            print(f"  {cartridge['color_name']}: {cartridge['level'