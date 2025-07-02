import os
import requests
import base64
import json
import yaml
import logging
from urllib.parse import urlencode, quote
from typing import List, Dict, Optional, Any
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 确保输出目录存在且可写，否则切换到当前目录
OUTPUT_DIR = 'out-1'
try:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    test_file = os.path.join(OUTPUT_DIR, '.write_test')
    with open(test_file, 'w') as f:
        f.write('test')
    os.remove(test_file)
except Exception as e:
    logger.warning(f"输出目录不可写({OUTPUT_DIR})，切换到当前目录: {str(e)}")
    OUTPUT_DIR = os.path.join(os.getcwd(), 'out-1')
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        test_file = os.path.join(OUTPUT_DIR, '.write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except Exception as e2:
        logger.error(f"当前目录也不可写，节点将输出到标准输出: {str(e2)}")
        OUTPUT_DIR = None

# 协议类型列表
PROTOCOLS = ['vless', 'vmess', 'ss', 'ssr', 'hy', 'hy2', 'hysteria', 'hysteria2', 'trojan']

# 请求配置
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2


class NodeParser:
    """节点解析器类"""
    
    def __init__(self):
        self.protocol_nodes = {protocol: [] for protocol in PROTOCOLS}
    
    def read_subscription_urls(self) -> List[str]:
        """读取 url.txt 中的订阅链接"""
        url_txt_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../url.txt'))
        try:
            with open(url_txt_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"读取到 {len(urls)} 个订阅链接")
                return urls
        except FileNotFoundError:
            logger.error(f"订阅文件不存在: {url_txt_path}")
            return []
        except Exception as e:
            logger.error(f"读取订阅链接失败: {str(e)}")
            return []
    
    def fetch_subscription(self, url: str) -> Optional[str]:
        """获取订阅内容，带重试机制"""
        for attempt in range(MAX_RETRIES):
            try:
                logger.info(f"正在获取订阅 (尝试 {attempt + 1}/{MAX_RETRIES}): {url}")
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
                response.raise_for_status()
                return response.text
            except requests.exceptions.RequestException as e:
                logger.warning(f"  获取失败 (尝试 {attempt + 1}): {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"  所有重试都失败了: {url}")
        return None
    
    def parse_subscription(self, content: str) -> List[str]:
        """解析订阅内容，支持多种格式"""
        if not content or not content.strip():
            logger.warning("订阅内容为空")
            return []
        
        nodes = []
        original_content = content
        
        # 尝试 Base64 解码
        try:
            # 先将内容转为 ASCII 字节，忽略无法编码的字符
            b64_bytes = content.encode('ascii', errors='ignore')
            # 补齐 padding
            missing_padding = len(b64_bytes) % 4
            if missing_padding:
                b64_bytes += b'=' * (4 - missing_padding)
            decoded_content = base64.b64decode(b64_bytes).decode('utf-8', errors='ignore')
            content = decoded_content
            logger.debug("成功进行 Base64 解码")
        except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
            logger.debug(f"内容非 Base64 编码，使用原始内容，原因: {str(e)}")
            content = original_content
        
        # 尝试解析为 YAML (Clash 配置)
        try:
            yaml_data = yaml.safe_load(content)
            if isinstance(yaml_data, dict) and 'proxies' in yaml_data:
                nodes.extend(self._parse_clash_config(yaml_data))
                if nodes:
                    logger.debug(f"YAML 格式解析成功，获得 {len(nodes)} 个节点")
                    return nodes
        except yaml.YAMLError:
            logger.debug("内容非 YAML 格式")
        
        # 尝试解析为 JSON
        try:
            json_data = json.loads(content)
            if isinstance(json_data, dict):
                if 'proxies' in json_data:
                    nodes.extend(self._parse_clash_config(json_data))
                elif 'outbounds' in json_data:
                    nodes.extend(self._parse_v2ray_config(json_data))
                if nodes:
                    logger.debug(f"JSON 格式解析成功，获得 {len(nodes)} 个节点")
                    return nodes
        except json.JSONDecodeError:
            logger.debug("内容非 JSON 格式")
        
        # 按行解析 URI 格式
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            protocol = self._identify_protocol(line)
            if protocol:
                nodes.append(line)
        
        logger.debug(f"URI 格式解析完成，获得 {len(nodes)} 个节点")
        return nodes
    
    def _parse_clash_config(self, config: Dict[str, Any]) -> List[str]:
        """解析 Clash 配置文件中的代理节点"""
        nodes = []
        
        if not isinstance(config, dict) or 'proxies' not in config:
            logger.warning("无效的 Clash 配置格式")
            return nodes
        
        proxies = config['proxies']
        if not isinstance(proxies, list):
            logger.warning("Clash 配置中的 proxies 不是列表格式")
            return nodes
        
        for proxy in proxies:
            if not isinstance(proxy, dict):
                logger.warning("跳过无效的代理配置（非字典格式）")
                continue
            
            if 'type' not in proxy or 'name' not in proxy:
                logger.warning(f"跳过无效代理: 缺少 type 或 name 字段")
                continue
            
            try:
                uri = self._convert_clash_to_uri(proxy)
                if uri:
                    nodes.append(uri)
                else:
                    logger.warning(f"无法转换 Clash 代理: {proxy.get('name', '未知')}")
            except Exception as e:
                logger.error(f"转换 Clash 代理时出错: {proxy.get('name', '未知')}, 错误: {str(e)}")
        
        return nodes
    
    def _parse_v2ray_config(self, config: Dict[str, Any]) -> List[str]:
        """解析 V2Ray 配置中的 outbounds"""
        nodes = []
        
        if not isinstance(config, dict) or 'outbounds' not in config:
            logger.warning("无效的 V2Ray 配置格式")
            return nodes
        
        outbounds = config['outbounds']
        if not isinstance(outbounds, list):
            logger.warning("V2Ray 配置中的 outbounds 不是列表格式")
            return nodes
        
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                logger.warning("跳过无效的 outbound 配置（非字典格式）")
                continue
            
            if 'protocol' not in outbound:
                logger.warning("跳过无效 outbound: 缺少 protocol 字段")
                continue
            
            try:
                uri = self._convert_v2ray_to_uri(outbound)
                if uri:
                    nodes.append(uri)
                else:
                    logger.warning(f"无法转换 V2Ray outbound: {outbound.get('tag', '未知')}")
            except Exception as e:
                logger.error(f"转换 V2Ray outbound 时出错: {outbound.get('tag', '未知')}, 错误: {str(e)}")
        
        return nodes
    
    def _extract_clash_params(self, proxy: Dict[str, Any]) -> Dict[str, Any]:
        """从 Clash 配置中提取通用参数"""
        ws_headers = proxy.get('ws-headers', {})
        if not isinstance(ws_headers, dict):
            ws_headers = {}
        
        alpn = proxy.get('alpn', [])
        if isinstance(alpn, list):
            alpn = ','.join(alpn)
        elif alpn is None:
            alpn = ''
        
        return {
            'server': str(proxy.get('server', '')),
            'port': str(proxy.get('port', '')),
            'name': str(proxy.get('name', '')),
            'password': str(proxy.get('password') or proxy.get('pass') or proxy.get('psk', '')),
            'network': str(proxy.get('network', 'tcp')),
            'tls': str(proxy.get('tls', '')),
            'ws_path': str(proxy.get('ws-path', '')),
            'ws_host': str(ws_headers.get('Host', '')),
            'sni': str(proxy.get('sni', '')),
            'alpn': str(alpn)
        }
    
    def _extract_v2ray_params(self, outbound: Dict[str, Any]) -> Dict[str, Any]:
        """从 V2Ray 配置中提取通用参数"""
        settings = outbound.get('settings', {})
        stream_settings = outbound.get('streamSettings', {})
        
        # 获取服务器信息
        server_info = {}
        if 'servers' in settings and isinstance(settings['servers'], list) and settings['servers']:
            server_info = settings['servers'][0]
        elif 'vnext' in settings and isinstance(settings['vnext'], list) and settings['vnext']:
            server_info = settings['vnext'][0]
        
        # 获取 WebSocket 设置
        ws_settings = stream_settings.get('wsSettings', {})
        ws_headers = ws_settings.get('headers', {})
        if not isinstance(ws_headers, dict):
            ws_headers = {}
        
        # 获取 TLS 设置
        tls_settings = stream_settings.get('tlsSettings', {})
        reality_settings = stream_settings.get('realitySettings', {})
        
        alpn = tls_settings.get('alpn', [])
        if isinstance(alpn, list):
            alpn = ','.join(alpn)
        elif alpn is None:
            alpn = ''
        
        return {
            'server': str(server_info.get('address', '')),
            'port': str(server_info.get('port', '')),
            'name': str(outbound.get('tag', '')),
            'password': str(server_info.get('password') or server_info.get('pass') or server_info.get('psk', '')),
            'network': str(stream_settings.get('network', 'tcp')),
            'tls': str(stream_settings.get('security', '')),
            'ws_path': str(ws_settings.get('path', '')),
            'ws_host': str(ws_headers.get('Host', '')),
            'sni': str(tls_settings.get('sni', '') or reality_settings.get('sni', '')),
            'alpn': str(alpn)
        }
    
    def _convert_clash_to_uri(self, proxy: Dict[str, Any]) -> Optional[str]:
        """将 Clash 代理配置转换为 URI 格式"""
        if not isinstance(proxy.get('type'), str):
            return None

        proxy_type = proxy['type'].lower()
        if proxy_type not in PROTOCOLS:
            return None

        params = self._extract_clash_params(proxy)

        # 验证必要字段
        if not all([params['server'], params['port'], params['name']]):
            logger.debug(f"Clash 代理缺少必要字段: {params['name']}")
            return None

        try:
            if proxy_type == 'ss':
                return self._build_ss_uri(params, proxy)
            elif proxy_type == 'ssr':
                return self._build_ssr_uri(params, proxy)
            elif proxy_type == 'vmess':
                return self._build_vmess_uri(params, proxy)
            elif proxy_type == 'vless':
                return self._build_vless_uri(params, proxy)
            elif proxy_type in ['trojan', 'hy', 'hy2']:
                return self._build_trojan_like_uri(proxy_type, params)
            elif proxy_type == 'hysteria2':
                return self._build_hysteria2_uri(params, proxy)
            elif proxy_type == 'hysteria':
                return self._build_hysteria_uri(params, proxy)
        except Exception as e:
            logger.error(f"构建 {proxy_type} URI 时出错: {str(e)}")
            return None

        return None
    
    def _convert_v2ray_to_uri(self, outbound: Dict[str, Any]) -> Optional[str]:
        """将 V2Ray outbound 配置转换为 URI 格式"""
        if not isinstance(outbound.get('protocol'), str):
            return None

        protocol = outbound['protocol'].lower()
        if protocol == 'shadowsocks':
            protocol = 'ss'  # 统一协议名称

        if protocol not in PROTOCOLS:
            return None

        params = self._extract_v2ray_params(outbound)

        # 验证必要字段
        if not all([params['server'], params['port'], params['name']]):
            logger.debug(f"V2Ray outbound 缺少必要字段: {params['name']}")
            return None

        try:
            if protocol == 'vmess':
                return self._build_vmess_uri_v2ray(params, outbound)
            elif protocol == 'vless':
                return self._build_vless_uri_v2ray(params, outbound)
            elif protocol == 'ss':
                return self._build_ss_uri_v2ray(params, outbound)
            elif protocol in ['trojan', 'hy', 'hy2']:
                return self._build_trojan_like_uri(protocol, params)
            elif protocol == 'hysteria2':
                return self._build_hysteria2_uri(params, outbound)
            elif protocol == 'hysteria':
                return self._build_hysteria_uri(params, outbound)
        except Exception as e:
            logger.error(f"构建 {protocol} URI 时出错: {str(e)}")
            return None

        return None
    
    def _build_ss_uri(self, params: Dict[str, Any], proxy: Dict[str, Any]) -> Optional[str]:
        """构建 Shadowsocks URI"""
        cipher = proxy.get('cipher', '')
        if not params['password'] or not cipher:
            return None
        
        userinfo = base64.b64encode(f"{cipher}:{params['password']}".encode()).decode().rstrip('=')
        return f"ss://{userinfo}@{params['server']}:{params['port']}#{quote(params['name'])}"
    
    def _build_ss_uri_v2ray(self, params: Dict[str, Any], outbound: Dict[str, Any]) -> Optional[str]:
        """构建 V2Ray Shadowsocks URI"""
        settings = outbound.get('settings', {})
        servers = settings.get('servers', [])
        if not servers:
            return None
        
        server = servers[0]
        method = server.get('method', '')
        if not params['password'] or not method:
            return None
        
        userinfo = base64.b64encode(f"{method}:{params['password']}".encode()).decode().rstrip('=')
        return f"ss://{userinfo}@{params['server']}:{params['port']}#{quote(params['name'])}"
    
    def _build_ssr_uri(self, params: Dict[str, Any], proxy: Dict[str, Any]) -> Optional[str]:
        """构建 ShadowsocksR URI"""
        required_fields = ['cipher', 'protocol', 'obfs']
        if not all(proxy.get(field) for field in required_fields) or not params['password']:
            return None
        
        # 构建主要部分
        main_part = f"{params['server']}:{params['port']}:{proxy['protocol']}:{proxy['cipher']}:{proxy['obfs']}:{base64.b64encode(params['password'].encode()).decode().rstrip('=')}"
        
        # 构建参数部分
        param_dict = {
            'obfsparam': base64.b64encode(str(proxy.get('obfs-param', '')).encode()).decode().rstrip('='),
            'protoparam': base64.b64encode(str(proxy.get('protocol-param', '')).encode()).decode().rstrip('='),
            'remarks': base64.b64encode(params['name'].encode()).decode().rstrip('=')
        }
        param_str = '&'.join([f"{k}={v}" for k, v in param_dict.items() if v])
        
        # 整体编码
        full_str = f"{main_part}/?{param_str}" if param_str else main_part
        encoded = base64.b64encode(full_str.encode()).decode().rstrip('=')
        
        return f"ssr://{encoded}"
    
    def _build_vmess_uri(self, params: Dict[str, Any], proxy: Dict[str, Any]) -> Optional[str]:
        """构建 VMess URI"""
        uuid = proxy.get('uuid', '')
        if not uuid:
            return None
        
        vmess_obj = {
            "v": "2",
            "ps": params['name'],
            "add": params['server'],
            "port": params['port'],
            "id": uuid,
            "aid": str(proxy.get('alterId', 0)),
            "net": params['network'],
            "type": str(proxy.get('type', 'none')),
            "host": params['ws_host'],
            "path": params['ws_path'],
            "tls": "tls" if params['tls'] == 'tls' else "",
            "sni": params['sni'],
            "alpn": params['alpn']
        }
        
        vmess_str = base64.b64encode(json.dumps(vmess_obj, separators=(',', ':')).encode()).decode().rstrip('=')
        return f"vmess://{vmess_str}"
    
    def _build_vmess_uri_v2ray(self, params: Dict[str, Any], outbound: Dict[str, Any]) -> Optional[str]:
        """构建 V2Ray VMess URI"""
        settings = outbound.get('settings', {})
        vnext = settings.get('vnext', [])
        if not vnext:
            return None
        
        server = vnext[0]
        users = server.get('users', [])
        if not users:
            return None
        
        user = users[0]
        uuid = user.get('id', '')
        if not uuid:
            return None
        
        stream_settings = outbound.get('streamSettings', {})
        tcp_settings = stream_settings.get('tcpSettings', {})
        header = tcp_settings.get('header', {})
        
        vmess_obj = {
            "v": "2",
            "ps": params['name'],
            "add": params['server'],
            "port": params['port'],
            "id": uuid,
            "aid": str(user.get('alterId', 0)),
            "net": params['network'],
            "type": str(header.get('type', 'none')),
            "host": params['ws_host'],
            "path": params['ws_path'],
            "tls": "tls" if params['tls'] == 'tls' else "",
            "sni": params['sni'],
            "alpn": params['alpn']
        }
        
        vmess_str = base64.b64encode(json.dumps(vmess_obj, separators=(',', ':')).encode()).decode().rstrip('=')
        return f"vmess://{vmess_str}"
    
    def _build_vless_uri(self, params: Dict[str, Any], proxy: Dict[str, Any]) -> Optional[str]:
        """构建 VLESS URI"""
        uuid = proxy.get('uuid', '')
        if not uuid:
            return None
        
        uri_params = {
            'type': params['network'],
            'security': params['tls'],
            'path': params['ws_path'],
            'host': params['ws_host'],
            'headerType': str(proxy.get('header-type', '')),
            'flow': str(proxy.get('flow', '')),
            'sni': params['sni'],
            'alpn': params['alpn']
        }
        
        # 过滤空值
        filtered_params = {k: v for k, v in uri_params.items() if v}
        params_str = urlencode(filtered_params)
        
        return f"vless://{uuid}@{params['server']}:{params['port']}?{params_str}#{quote(params['name'])}"
    
    def _build_vless_uri_v2ray(self, params: Dict[str, Any], outbound: Dict[str, Any]) -> Optional[str]:
        """构建 V2Ray VLESS URI"""
        settings = outbound.get('settings', {})
        vnext = settings.get('vnext', [])
        if not vnext:
            return None
        
        server = vnext[0]
        users = server.get('users', [])
        if not users:
            return None
        
        user = users[0]
        uuid = user.get('id', '')
        if not uuid:
            return None
        
        stream_settings = outbound.get('streamSettings', {})
        tcp_settings = stream_settings.get('tcpSettings', {})
        header = tcp_settings.get('header', {})
        
        uri_params = {
            'type': params['network'],
            'security': params['tls'],
            'path': params['ws_path'],
            'host': params['ws_host'],
            'headerType': str(header.get('type', '')),
            'flow': str(user.get('flow', '')),
            'sni': params['sni'],
            'alpn': params['alpn']
        }
        
        # 过滤空值
        filtered_params = {k: v for k, v in uri_params.items() if v}
        params_str = urlencode(filtered_params)
        
        return f"vless://{uuid}@{params['server']}:{params['port']}?{params_str}#{quote(params['name'])}"
    
    def _build_trojan_like_uri(self, protocol: str, params: Dict[str, Any]) -> Optional[str]:
        """构建 Trojan/Hysteria 类似的 URI"""
        if not params['password']:
            return None
        
        uri_params = {
            'security': params['tls'],
            'type': params['network'],
            'path': params['ws_path'],
            'host': params['ws_host'],
            'sni': params['sni'],
            'alpn': params['alpn']
        }
        
        # 过滤空值
        filtered_params = {k: v for k, v in uri_params.items() if v}
        params_str = urlencode(filtered_params)
        
        return f"{protocol}://{quote(params['password'])}@{params['server']}:{params['port']}?{params_str}#{quote(params['name'])}"
    
    def _build_hysteria2_uri(self, params: Dict[str, Any], proxy_or_outbound: Dict[str, Any]) -> Optional[str]:
        """构建 hysteria2 URI"""
        # 兼容 Clash/Outbound
        password = params.get('password') or proxy_or_outbound.get('password') or proxy_or_outbound.get('auth-str', '')
        if not password:
            return None

        # 兼容 Clash 配置和 V2Ray 配置
        obfs = proxy_or_outbound.get('obfs', '')
        obfs_param = proxy_or_outbound.get('obfs-param', '')
        alpn = params.get('alpn', '')
        sni = params.get('sni', '')
        protocol = proxy_or_outbound.get('protocol', '')
        upmbps = proxy_or_outbound.get('up', '') or proxy_or_outbound.get('upmbps', '')
        downmbps = proxy_or_outbound.get('down', '') or proxy_or_outbound.get('downmbps', '')
        insecure = proxy_or_outbound.get('insecure', '')

        uri_params = {
            'obfs': obfs,
            'obfsParam': obfs_param,
            'alpn': alpn,
            'sni': sni,
            'protocol': protocol,
            'upmbps': upmbps,
            'downmbps': downmbps,
            'insecure': str(insecure).lower() if isinstance(insecure, bool) else insecure,
        }
        filtered_params = {k: v for k, v in uri_params.items() if v}
        params_str = urlencode(filtered_params)

        return f"hysteria2://{quote(password)}@{params['server']}:{params['port']}?{params_str}#{quote(params['name'])}"
    
    def _build_hysteria_uri(self, params: Dict[str, Any], proxy_or_outbound: Dict[str, Any]) -> Optional[str]:
        """构建 hysteria URI"""
        # 兼容 Clash/Outbound
        password = params.get('password') or proxy_or_outbound.get('password') or proxy_or_outbound.get('auth-str', '')
        if not password:
            return None

        obfs = proxy_or_outbound.get('obfs', '')
        obfs_param = proxy_or_outbound.get('obfs-param', '')
        alpn = params.get('alpn', '')
        sni = params.get('sni', '')
        protocol = proxy_or_outbound.get('protocol', '')
        upmbps = proxy_or_outbound.get('up', '') or proxy_or_outbound.get('upmbps', '')
        downmbps = proxy_or_outbound.get('down', '') or proxy_or_outbound.get('downmbps', '')
        insecure = proxy_or_outbound.get('insecure', '')

        uri_params = {
            'obfs': obfs,
            'obfsParam': obfs_param,
            'alpn': alpn,
            'sni': sni,
            'protocol': protocol,
            'upmbps': upmbps,
            'downmbps': downmbps,
            'insecure': str(insecure).lower() if isinstance(insecure, bool) else insecure,
        }
        filtered_params = {k: v for k, v in uri_params.items() if v}
        params_str = urlencode(filtered_params)

        return f"hysteria://{quote(password)}@{params['server']}:{params['port']}?{params_str}#{quote(params['name'])}"
    
    def _identify_protocol(self, node: str) -> Optional[str]:
        """识别节点的协议类型"""
        if not isinstance(node, str):
            return None
        
        # 使用正则表达式匹配协议
        pattern = r'^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/'
        match = re.match(pattern, node)
        
        if match:
            protocol = match.group(1).lower()
            if protocol in PROTOCOLS:
                return protocol
        
        return None
    
    def classify_and_save_nodes(self, all_nodes: List[str]) -> None:
        """按协议分类节点并保存到文件"""
        logger.info(f"开始分类 {len(all_nodes)} 个节点")
        
        # 去重
        unique_nodes = list(set(all_nodes))
        logger.info(f"去重后剩余 {len(unique_nodes)} 个节点")
        
        # 按协议分类
        for node in unique_nodes:
            protocol = self._identify_protocol(node)
            if protocol:
                self.protocol_nodes[protocol].append(node)
            else:
                logger.debug(f"无法识别协议的节点: {node[:50]}...")
        
        # 保存到文件或输出到标准输出
        total_saved = 0
        for protocol, nodes in self.protocol_nodes.items():
            if nodes:
                if OUTPUT_DIR:
                    output_file = os.path.join(OUTPUT_DIR, f"{protocol}.txt")
                    try:
                        with open(output_file, 'w', encoding='utf-8') as f:
                            for node in nodes:
                                f.write(f"{node}\n")
                        logger.info(f"已保存 {len(nodes)} 个 {protocol.upper()} 节点到 {output_file}")
                        total_saved += len(nodes)
                    except Exception as e:
                        logger.error(f"保存 {protocol} 节点失败: {str(e)}")
                else:
                    logger.warning(f"无法写入文件，输出 {protocol.upper()} 节点到标准输出：")
                    for node in nodes:
                        print(node)
                    total_saved += len(nodes)
        
        logger.info(f"总共保存了 {total_saved} 个节点")
        
        # 输出统计信息
        logger.info("=" * 50)
        logger.info("节点统计:")
        for protocol in PROTOCOLS:
            count = len(self.protocol_nodes[protocol])
            if count > 0:
                logger.info(f"  {protocol.upper()}: {count} 个")
        logger.info("=" * 50)
    
    def run(self) -> None:
        """主运行函数"""
        logger.info("开始获取和解析订阅节点")
        
        # 读取订阅链接
        subscription_urls = self.read_subscription_urls()
        if not subscription_urls:
            logger.error("没有找到有效的订阅链接")
            return
        
        # 获取和解析所有订阅
        all_nodes = []
        successful_subscriptions = 0
        
        for i, url in enumerate(subscription_urls, 1):
            logger.info(f"处理订阅 {i}/{len(subscription_urls)}")
            
            content = self.fetch_subscription(url)
            if content:
                nodes = self.parse_subscription(content)
                logger.info(f"  从订阅中解析到 {len(nodes)} 个节点")
                all_nodes.extend(nodes)
                successful_subscriptions += 1
            else:
                logger.warning(f"  跳过失败的订阅: {url}")
        
        logger.info(f"成功处理 {successful_subscriptions}/{len(subscription_urls)} 个订阅")
        logger.info(f"总共获取到 {len(all_nodes)} 个节点")
        
        if all_nodes:
            # 分类并保存节点
            self.classify_and_save_nodes(all_nodes)
        else:
            logger.warning("没有获取到任何节点")


def main():
    """主函数"""
    try:
        parser = NodeParser()
        parser.run()
    except KeyboardInterrupt:
        logger.info("用户中断了程序")
    except Exception as e:
        logger.error(f"程序运行时发生错误: {str(e)}", exc_info=True)


if __name__ == "__main__":
    main()
