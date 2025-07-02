# 订阅节点处理工具

本项目是一个用 Python 编写的多协议订阅节点处理工具，支持自动拉取、去重、重命名节点.

## 功能特性

- 支持多种协议：vless、vmess、ss、ssr、hysteria2、hysteria、trojan 等
- 支持从多个订阅链接批量拉取节点
- 自动识别并分类不同协议的节点
- 节点去重，避免重复
- 节点重命名（序号格式），便于管理
- 支持多种订阅格式（Base64、YAML、JSON、URI）

## 目录结构（按工作流顺序）

```
├── url.txt                    # 订阅链接列表
├── url/
│   └── deduplicate.py         # url.txt 去重脚本
├── Step1/
│   └── fetch_nodes.py         # 拉取并分类节点
├── Step2/
│   └── deduplicate_nodes.py   # 节点去重
├── Step3/
│   └── rename_nodes.py        # 节点重命名
├── out-1/                     # 拉取并分类后的节点
├── out-2/                     # 去重后的节点
└── out-3/                     # 重命名后的节点
```

## 快速开始

### 1. 环境准备

- Python 3.6 及以上
- 安装依赖：

```bash
pip install requests pyyaml
```

### 2. 配置订阅链接

将你的订阅链接一行一个写入 `url.txt` 文件。

### 3. 拉取并分类节点

```bash
cd Step1
python fetch_nodes.py
```
节点将被拉取并按协议类型保存到 `out-1` 目录。

### 4. 节点去重

```bash
cd ../Step2
python deduplicate_nodes.py
```
去重结果输出到 `out-2` 目录。

### 5. 节点重命名

```bash
cd ../Step3
python rename_nodes.py
```
重命名后的节点输出到 `out-3` 目录。

## 自动化（GitHub Actions）

本项目已集成 GitHub Actions 自动化流程，支持定时和手动触发自动拉取、去重、重命名节点。

## 注意事项

- `url.txt` 中请填写有效的订阅链接，每行一个
- 网络需畅通以保证订阅拉取成功
- 若某协议无节点，则不会生成对应输出文件
- 支持 Clash/YAML、Base64、URI 等多种格式自动识别


---
**免责声明：** 本项目仅用于学习和交流，请勿用于任何非法用途。