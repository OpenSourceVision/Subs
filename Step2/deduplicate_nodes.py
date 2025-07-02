import os
import base64
import json
import hashlib
from urllib.parse import urlparse, parse_qs

# 输入和输出目录
input_dir = 'out-1'
output_dir = 'out-2'

# 确保输出目录存在
os.makedirs(output_dir, exist_ok=True)

# 协议类型列表
protocols = ['vless', 'vmess', 'ss', 'ssr', 'hysteria', 'hysteria2', 'trojan']

# 读取指定协议的节点
def read_nodes(protocol):
    input_file = os.path.join(input_dir, f"{protocol}.txt")
    if not os.path.exists(input_file):
        return []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# 解析vmess节点
def parse_vmess(node):
    if not node.startswith('vmess://'):
        return None
    
    try:
        # 移除vmess://前缀并解码
        encoded_str = node[8:]
        decoded_str = base64.b64decode(encoded_str).decode('utf-8')
        vmess_info = json.loads(decoded_str)
        
        # 提取关键信息用于去重
        return {
            'protocol': 'vmess',
            'server': vmess_info.get('add', ''),
            'port': vmess_info.get('port', ''),
            'id': vmess_info.get('id', ''),
            'aid': vmess_info.get('aid', 0),
            'net': vmess_info.get('net', ''),
            'path': vmess_info.get('path', ''),
            'host': vmess_info.get('host', ''),
            'tls': vmess_info.get('tls', ''),
            'original': node
        }
    except:
        return None

# 解析vless节点
def parse_vless(node):
    if not node.startswith('vless://'):
        return None
    
    try:
        # 移除vless://前缀
        uri = node[8:]
        # 分离UUID和其他部分
        if '@' in uri:
            uuid, server_part = uri.split('@', 1)
        else:
            return None
        
        # 分离服务器地址和端口
        if ':' in server_part:
            server_and_port, remaining = server_part.split(':', 1)
            if '/' in remaining:
                port, path_part = remaining.split('/', 1)
                path = '/' + path_part
            else:
                port_parts = remaining.split('?', 1)
                port = port_parts[0]
                path = ''
        else:
            return None
        
        # 解析查询参数
        params = {}
        if '?' in remaining:
            query_part = remaining.split('?', 1)[1]
            if '#' in query_part:
                query_part = query_part.split('#', 1)[0]
            
            for param in query_part.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
        
        return {
            'protocol': 'vless',
            'server': server_and_port,
            'port': port,
            'id': uuid,
            'type': params.get('type', ''),
            'security': params.get('security', ''),
            'path': params.get('path', path),
            'host': params.get('host', ''),
            'original': node
        }
    except:
        return None

# 解析ss节点
def parse_ss(node):
    if not node.startswith('ss://'):
        return None
    
    try:
        # 移除ss://前缀
        uri = node[5:]
        
        # 处理有@和没有@的两种格式
        if '@' in uri:
            # 格式: ss://BASE64(method:password)@server:port#tag
            userinfo, server_part = uri.split('@', 1)
            
            # 处理BASE64编码的userinfo
            try:
                userinfo = base64.b64decode(userinfo).decode('utf-8')
                method, password = userinfo.split(':', 1)
            except:
                # 如果不是BASE64编码，尝试直接解析
                method, password = userinfo.split(':', 1)
            
            # 解析服务器和端口
            if '#' in server_part:
                server_and_port, tag = server_part.split('#', 1)
            else:
                server_and_port = server_part
                tag = ''
            
            if ':' in server_and_port:
                server, port = server_and_port.split(':', 1)
            else:
                return None
        else:
            # 格式: ss://BASE64(method:password@server:port)#tag
            if '#' in uri:
                encoded_part, tag = uri.split('#', 1)
            else:
                encoded_part = uri
                tag = ''
            
            try:
                decoded = base64.b64decode(encoded_part).decode('utf-8')
                if '@' in decoded and ':' in decoded:
                    method_and_password, server_and_port = decoded.split('@', 1)
                    method, password = method_and_password.split(':', 1)
                    server, port = server_and_port.split(':', 1)
                else:
                    return None
            except:
                return None
        
        return {
            'protocol': 'ss',
            'server': server,
            'port': port,
            'method': method,
            'password': password,
            'tag': tag,
            'original': node
        }
    except:
        return None

# 解析ssr节点
def parse_ssr(node):
    if not node.startswith('ssr://'):
        return None

    try:
        # 移除ssr://前缀并解码
        encoded_str = node[6:]
        # 只取 ? 之前的部分
        if '?' in encoded_str:
            main_part, query_part = encoded_str.split('?', 1)
        else:
            main_part = encoded_str
            query_part = ''
        decoded_str = base64.b64decode(main_part + '=' * (-len(main_part) % 4)).decode('utf-8')
        # 解析主要部分
        parts = decoded_str.split(':')
        if len(parts) < 6:
            return None
        server = parts[0]
        port = parts[1]
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_and_params = ':'.join(parts[5:])
        if '/' in password_and_params:
            password_base64, params = password_and_params.split('/', 1)
        else:
            password_base64 = password_and_params
            params = ''
        # 解码密码
        try:
            password = base64.b64decode(password_base64 + '=' * (-len(password_base64) % 4)).decode('utf-8')
        except:
            password = password_base64
        # 解析参数（ssr参数部分不是base64，是url编码）
        param_dict = {}
        if params:
            for param in params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = value
        # 解析 query_part（部分实现可能会有）
        if query_part:
            for param in query_part.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    param_dict[key] = value
        return {
            'protocol': 'ssr',
            'server': server,
            'port': port,
            'ssr_protocol': protocol,
            'method': method,
            'obfs': obfs,
            'password': password,
            'obfs_param': param_dict.get('obfsparam', ''),
            'protocol_param': param_dict.get('protoparam', ''),
            'remarks': param_dict.get('remarks', ''),
            'original': node
        }
    except:
        return None

# 解析 hysteria 节点
def parse_hysteria(node):
    if not node.startswith('hysteria://'):
        return None
    protocol = 'hysteria'
    uri = node[11:]
    try:
        # hysteria://host:port?...params...
        # 先分离 host:port 和参数部分
        if '?' in uri:
            host_port, query = uri.split('?', 1)
        else:
            host_port = uri
            query = ''
        # 处理 tag
        tag = ''
        if '#' in query:
            query, tag = query.split('#', 1)
        # 解析 host 和 port
        if ':' in host_port:
            server, port = host_port.split(':', 1)
        else:
            return None
        # 解析参数
        params = {}
        auth = ''
        if query:
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
                    if k == 'auth':
                        auth = v
        return {
            'protocol': protocol,
            'server': server,
            'port': port,
            'auth': auth,
            'params': params,
            'tag': tag,
            'original': node
        }
    except:
        return None

# 解析 hysteria2 节点
def parse_hysteria2(node):
    if not node.startswith('hysteria2://'):
        return None
    protocol = 'hysteria2'
    uri = node[12:]
    try:
        if '@' in uri:
            auth, server_part = uri.split('@', 1)
        else:
            return None
        if ':' in server_part:
            server, port_and_rest = server_part.split(':', 1)
        else:
            return None
        port = port_and_rest
        params = {}
        tag = ''
        if '?' in port_and_rest:
            port, rest = port_and_rest.split('?', 1)
            if '#' in rest:
                query, tag = rest.split('#', 1)
            else:
                query = rest
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
        elif '#' in port_and_rest:
            port, tag = port_and_rest.split('#', 1)
        return {
            'protocol': protocol,
            'server': server,
            'port': port,
            'auth': auth,
            'params': params,
            'tag': tag,
            'original': node
        }
    except:
        return None

# 解析trojan节点
def parse_trojan(node):
    if not node.startswith('trojan://'):
        return None
    try:
        # trojan://password@server:port?params#tag
        uri = node[9:]
        if '@' in uri:
            password, server_part = uri.split('@', 1)
        else:
            return None
        if ':' in server_part:
            server, port_and_rest = server_part.split(':', 1)
        else:
            return None
        port = port_and_rest
        params = {}
        tag = ''
        if '?' in port_and_rest:
            port, rest = port_and_rest.split('?', 1)
            if '#' in rest:
                query, tag = rest.split('#', 1)
            else:
                query = rest
            for param in query.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k] = v
        elif '#' in port_and_rest:
            port, tag = port_and_rest.split('#', 1)
        return {
            'protocol': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'params': params,
            'tag': tag,
            'original': node
        }
    except:
        return None

# 解析节点
def parse_node(node):
    if node.startswith('vmess://'):
        return parse_vmess(node)
    elif node.startswith('vless://'):
        return parse_vless(node)
    elif node.startswith('ss://'):
        return parse_ss(node)
    elif node.startswith('ssr://'):
        return parse_ssr(node)
    elif node.startswith('hysteria2://'):
        return parse_hysteria2(node)
    elif node.startswith('hysteria://'):
        return parse_hysteria(node)
    elif node.startswith('trojan://'):
        return parse_trojan(node)
    return None

# 生成节点的唯一标识
def generate_node_key(node_info):
    if not node_info:
        return None

    protocol = node_info.get('protocol', '')

    if protocol == 'vmess':
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('id', ''),
            str(node_info.get('aid', '')),
            node_info.get('net', ''),
            node_info.get('path', ''),
            node_info.get('host', ''),
            node_info.get('tls', '')
        ]
    elif protocol == 'vless':
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('id', ''),
            node_info.get('type', ''),
            node_info.get('security', ''),
            node_info.get('path', ''),
            node_info.get('host', '')
        ]
    elif protocol == 'ss':
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('method', ''),
            node_info.get('password', '')
        ]
    elif protocol == 'ssr':
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('ssr_protocol', ''),
            node_info.get('method', ''),
            node_info.get('obfs', ''),
            node_info.get('password', ''),
            node_info.get('obfs_param', ''),
            node_info.get('protocol_param', '')
        ]
    elif protocol in ['hysteria', 'hysteria2']:
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('auth', '')
        ]
        params = node_info.get('params', {})
        for key in sorted(params.keys()):
            key_parts.append(f"{key}={params[key]}")
    elif protocol == 'trojan':
        key_parts = [
            node_info.get('server', ''),
            str(node_info.get('port', '')),
            node_info.get('password', '')
        ]
        params = node_info.get('params', {})
        for key in sorted(params.keys()):
            key_parts.append(f"{key}={params[key]}")
    else:
        return None

    key_str = '|'.join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()

# 主函数
def main():
    # 处理每种协议的节点
    for protocol in protocols:
        print(f"处理 {protocol} 协议节点...")

        # 读取节点
        nodes = read_nodes(protocol)
        if not nodes:
            print(f"  没有找到 {protocol} 协议节点")
            continue

        print(f"  读取到 {len(nodes)} 个节点")

        # 去重
        unique_nodes = {}
        for node in nodes:
            node_info = parse_node(node)
            # hysteria2 和 hysteria 分别处理，互不影响
            if node_info and node_info.get('protocol') == protocol:
                node_key = generate_node_key(node_info)
                if node_key and node_key not in unique_nodes:
                    unique_nodes[node_key] = node_info['original']

        print(f"  去重后剩余 {len(unique_nodes)} 个节点")

        # 输出到文件
        if unique_nodes:
            output_file = os.path.join(output_dir, f"{protocol}.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                for node in unique_nodes.values():
                    f.write(f"{node}\n")
            print(f"  已保存到 {output_file}")

if __name__ == "__main__":
    main()
