import os
import base64
import json
import re
from urllib.parse import urlparse, parse_qs, quote, unquote

# 输入和输出目录
input_dir = 'out-2'
output_dir = 'out-3'

# 确保输出目录存在
os.makedirs(output_dir, exist_ok=True)

# 协议类型列表，拆分 hysteria2 和 hysteria
protocols = ['vless', 'trojan', 'ss', 'hysteria2', 'hysteria']

# 读取指定协议的节点
def read_nodes(protocol):
    input_file = os.path.join(input_dir, f"{protocol}.txt")
    if not os.path.exists(input_file):
        return []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# 重命名vmess节点
def rename_vmess(node, index):
    if not node.startswith('vmess://'):
        return node
    
    try:
        # 移除vmess://前缀并解码
        encoded_str = node[8:]
        decoded_str = base64.b64decode(encoded_str).decode('utf-8')
        vmess_info = json.loads(decoded_str)
        
        # 修改节点名称为3位数序号
        vmess_info['ps'] = f"{index:03d}"
        
        # 重新编码
        new_encoded_str = base64.b64encode(json.dumps(vmess_info).encode()).decode()
        return f"vmess://{new_encoded_str}"
    except:
        return node

# 重命名vless节点
def rename_vless(node, index):
    if not node.startswith('vless://'):
        return node
    
    try:
        # 处理节点名称部分（位于#后面）
        if '#' in node:
            base_part, _ = node.split('#', 1)
            return f"{base_part}#{index:03d}"
        else:
            return f"{node}#{index:03d}"
    except:
        return node

# 重命名ss节点
def rename_ss(node, index):
    # 只处理 ss://，不处理 ssr://
    if not (node.startswith('ss://') and not node.startswith('ssr://')):
        return node
    try:
        # 处理节点名称部分（位于#后面）
        if '#' in node:
            base_part, _ = node.split('#', 1)
            return f"{base_part}#{index:03d}"
        else:
            return f"{node}#{index:03d}"
    except:
        return node

# 重命名ssr节点
def rename_ssr(node, index):
    # 只处理 ssr://
    if not node.startswith('ssr://'):
        return node
    try:
        # 移除ssr://前缀并解码
        encoded_str = node[6:]
        # 处理可能存在的查询参数
        if '?' in encoded_str:
            main_part, query_part = encoded_str.split('?', 1)
        else:
            main_part = encoded_str
            query_part = ''
        # 解码主要部分
        decoded_str = base64.b64decode(main_part).decode('utf-8')
        # 解析主要部分
        parts = decoded_str.split(':')  
        if len(parts) < 6:
            return node
        # 重新构建remarks参数
        if query_part:
            try:
                decoded_params = base64.b64decode(query_part).decode('utf-8')
                param_dict = {}
                for param in decoded_params.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        param_dict[key] = value
                # 更新remarks
                param_dict['remarks'] = f"{index:03d}"
                # 重新编码参数
                new_params = '&'.join([f"{k}={v}" for k, v in param_dict.items()])
                new_query_part = base64.b64encode(new_params.encode()).decode()
                return f"ssr://{main_part}?{new_query_part}"
            except:
                # 如果解析失败，保持原样
                return node
        else:
            # 如果没有查询参数，添加一个包含remarks的查询参数
            new_params = f"remarks={index:03d}"
            new_query_part = base64.b64encode(new_params.encode()).decode()
            return f"ssr://{main_part}?{new_query_part}"
    except:
        return node

# 重命名trojan节点
def rename_trojan(node, index):
    if not node.startswith('trojan://'):
        return node
    try:
        # 处理节点名称部分（位于#后面）
        if '#' in node:
            base_part, _ = node.split('#', 1)
            return f"{base_part}#{index:03d}"
        else:
            return f"{node}#{index:03d}"
    except:
        return node

# 重命名hysteria2节点
def rename_hysteria2(node, index):
    if not node.startswith('hysteria2://'):
        return node
    try:
        # 处理节点名称部分（位于#后面）
        if '#' in node:
            base_part, _ = node.split('#', 1)
            return f"{base_part}#{index:03d}"
        else:
            return f"{node}#{index:03d}"
    except:
        return node

# 重命名hysteria节点
def rename_hysteria(node, index):
    if not node.startswith('hysteria://'):
        return node
    try:
        # 处理节点名称部分（位于#后面）
        if '#' in node:
            base_part, _ = node.split('#', 1)
            return f"{base_part}#{index:03d}"
        else:
            return f"{node}#{index:03d}"
    except:
        return node

# 重命名节点
def rename_node(node, protocol, index):
    if protocol == 'vmess':
        return rename_vmess(node, index)
    elif protocol == 'vless':
        return rename_vless(node, index)
    elif protocol == 'ss':
        return rename_ss(node, index)
    elif protocol == 'ssr':
        return rename_ssr(node, index)
    elif protocol == 'trojan':
        return rename_trojan(node, index)
    elif protocol == 'hysteria2':
        return rename_hysteria2(node, index)
    elif protocol == 'hysteria':
        return rename_hysteria(node, index)
    return node

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
        
        # 重命名节点
        renamed_nodes = []
        for i, node in enumerate(nodes, 1):
            renamed_node = rename_node(node, protocol, i)
            renamed_nodes.append(renamed_node)
        
        # 输出到文件
        output_file = os.path.join(output_dir, f"{protocol}.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            for node in renamed_nodes:
                f.write(f"{node}\n")
        print(f"  已将重命名后的节点保存到 {output_file}")

if __name__ == "__main__":
    main()