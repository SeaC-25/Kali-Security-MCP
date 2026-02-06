# 🐧 Kali服务器依赖环境配置指南

## 📋 概述

本文档详细说明如何在Kali Linux服务器上配置KaliMCP所需的完整依赖环境，包括所有渗透测试工具、Web安全工具和服务配置。

## 🔧 基础环境要求

### 系统要求
- **操作系统**: Kali Linux 2024.x (推荐最新版本)
- **内存**: 至少4GB RAM (推荐8GB+)
- **存储**: 至少20GB可用空间
- **网络**: 稳定的网络连接

### 网络配置
```bash
# 配置静态IP (如果需要)
sudo nano /etc/network/interfaces

# 示例配置
auto eth0
iface eth0 inet static
address 192.168.102.66
netmask 255.255.255.0
gateway 192.168.102.1
dns-nameservers 8.8.8.8 8.8.4.4
```

## 🐍 Python环境配置

### 1. Python基础环境
```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 确保Python3和pip可用
sudo apt install python3 python3-pip python3-venv python3-dev -y

# 验证Python版本
python3 --version
pip3 --version
```

### 2. 核心Python依赖
```bash
# 升级pip
python3 -m pip install --upgrade pip

# Flask Web框架
pip3 install Flask Flask-SocketIO

# HTTP客户端库
pip3 install requests urllib3

# 系统交互库
pip3 install psutil subprocess32

# JSON和数据处理
pip3 install jsonschema pyyaml

# 异步和WebSocket支持
pip3 install python-socketio eventlet gevent gevent-websocket

# 日志和调试
pip3 install colorlog
```

## 🔍 渗透测试工具

### 1. 网络扫描工具
```bash
# Nmap (通常已预装)
sudo apt install nmap -y

# Masscan - 高速端口扫描
sudo apt install masscan -y

# Zmap - 网络扫描
sudo apt install zmap -y

# Netdiscover - 网络发现
sudo apt install netdiscover -y

# fping - 快速ping扫描
sudo apt install fping -y

# arp-scan - ARP扫描
sudo apt install arp-scan -y
```

### 2. Web应用扫描工具
```bash
# Gobuster - 目录暴力破解
sudo apt install gobuster -y

# Dirb - Web目录扫描
sudo apt install dirb -y

# Nikto - Web漏洞扫描
sudo apt install nikto -y

# SQLmap - SQL注入工具
sudo apt install sqlmap -y

# Wfuzz - Web模糊测试
sudo apt install wfuzz -y

# Feroxbuster - 快速目录扫描
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb
sudo dpkg -i feroxbuster_amd64.deb

# FFUF - Web模糊测试
sudo apt install ffuf -y

# WhatWeb - Web技术识别
sudo apt install whatweb -y

# Wafw00f - WAF检测
sudo apt install wafw00f -y

# WPScan - WordPress扫描
sudo apt install wpscan -y

# Joomscan - Joomla扫描 (需要手动安装)
git clone https://github.com/OWASP/joomscan.git
cd joomscan
sudo chmod +x joomscan.pl
sudo ln -s $(pwd)/joomscan.pl /usr/local/bin/joomscan
cd ..
```

### 3. 密码攻击工具
```bash
# Hydra - 暴力破解
sudo apt install hydra -y

# John the Ripper - 密码破解
sudo apt install john -y

# Hashcat - GPU密码破解
sudo apt install hashcat -y

# Medusa - 暴力破解
sudo apt install medusa -y

# Patator - 多协议暴力破解
sudo apt install patator -y

# Ncrack - 网络认证破解
sudo apt install ncrack -y

# Crowbar - 暴力破解
sudo apt install crowbar -y

# Brutespray - 从Nmap输出进行暴力破解
sudo apt install brutespray -y
```

### 4. 网络分析工具
```bash
# Wireshark/Tshark - 流量分析
sudo apt install wireshark tshark -y

# Tcpdump - 数据包捕获
sudo apt install tcpdump -y

# Ngrep - 网络grep
sudo apt install ngrep -y

# Ettercap - MITM攻击
sudo apt install ettercap-text-only -y

# Bettercap - 网络攻击框架
sudo apt install bettercap -y

# Responder - LLMNR/NBT-NS中毒
sudo apt install responder -y

# Dsniff - 网络嗅探
sudo apt install dsniff -y
```

### 5. 漏洞扫描工具
```bash
# Nuclei - 现代漏洞扫描器
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 或使用二进制安装
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.4_linux_amd64.zip
unzip nuclei_2.9.4_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei

# 更新Nuclei模板
nuclei -update-templates

# OpenVAS - 综合漏洞扫描 (可选)
sudo apt install openvas -y
```

## 🌐 Web和域名工具

### 1. 子域名枚举工具
```bash
# Sublist3r - 子域名枚举
sudo apt install sublist3r -y

# Subfinder - 快速子域名发现
wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
sudo mv subfinder /usr/local/bin/
sudo chmod +x /usr/local/bin/subfinder

# Amass - 综合信息收集
sudo apt install amass -y

# Fierce - DNS扫描
sudo apt install fierce -y

# DNSenum - DNS枚举
sudo apt install dnsenum -y

# DNSrecon - DNS侦察
sudo apt install dnsrecon -y

# DNSmap - DNS映射
sudo apt install dnsmap -y
```

### 2. HTTP探测工具
```bash
# HTTPx - HTTP探测
wget https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.3.7_linux_amd64.zip
unzip httpx_1.3.7_linux_amd64.zip
sudo mv httpx /usr/local/bin/
sudo chmod +x /usr/local/bin/httpx

# Curl - HTTP客户端
sudo apt install curl -y

# Wget - 文件下载
sudo apt install wget -y
```

## 📊 信息收集工具

### 1. OSINT工具
```bash
# theHarvester - 信息收集
sudo apt install theharvester -y

# Recon-ng - 侦察框架
sudo apt install recon-ng -y

# Sherlock - 用户名枚举
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip3 install -r requirements.txt
sudo chmod +x sherlock.py
sudo ln -s $(pwd)/sherlock.py /usr/local/bin/sherlock
cd ..

# Maltego - 情报分析 (可选)
# 需要从官网下载安装
```

### 2. 枚举工具
```bash
# Enum4linux - SMB枚举
sudo apt install enum4linux -y

# SMBclient - SMB客户端
sudo apt install smbclient -y

# SNMP工具
sudo apt install snmp snmp-mibs-downloader -y

# LDAP工具
sudo apt install ldap-utils -y
```

## 🔧 系统工具

### 1. 编译和开发工具
```bash
# 基础编译环境
sudo apt install build-essential -y

# Git版本控制
sudo apt install git -y

# Vim/Nano编辑器
sudo apt install vim nano -y

# Screen/Tmux终端复用
sudo apt install screen tmux -y
```

### 2. 调试和分析工具
```bash
# GDB调试器
sudo apt install gdb -y

# Strace系统调用跟踪
sudo apt install strace -y

# Ltrace库调用跟踪
sudo apt install ltrace -y

# Objdump反汇编
sudo apt install binutils -y

# Strings字符串提取
sudo apt install binutils -y

# File文件类型检测
sudo apt install file -y

# Hexdump十六进制转储
sudo apt install bsdmainutils -y
```

## 🔒 无线网络工具 (可选)

```bash
# Aircrack-ng套件
sudo apt install aircrack-ng -y

# Reaver WPS攻击
sudo apt install reaver -y

# Bully WPS攻击
sudo apt install bully -y

# Pixiewps WPS PIN恢复
sudo apt install pixiewps -y

# Wifiphisher WiFi钓鱼
sudo apt install wifiphisher -y

# 蓝牙工具
sudo apt install bluez bluez-tools -y
sudo apt install btscanner -y
sudo apt install bluesnarfer -y
```

## 🎯 DoS测试工具

```bash
# Slowhttptest HTTP DoS
sudo apt install slowhttptest -y

# Hping3 数据包生成
sudo apt install hping3 -y

# T50 数据包注入
sudo apt install t50 -y
```

## 🔍 逆向分析工具

```bash
# Radare2 - 逆向分析框架
sudo apt install radare2 -y

# Binwalk - 固件分析
sudo apt install binwalk -y

# Strings - 字符串提取
sudo apt install binutils -y

# Hexedit - 十六进制编辑
sudo apt install hexedit -y

# Ghidra - NSA逆向工具 (需要Java)
sudo apt install openjdk-11-jdk -y
# Ghidra需要手动下载安装
```

## 📝 字典文件

### 1. 常用字典
```bash
# SecLists字典集合
sudo apt install seclists -y

# 或手动安装最新版本
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Wordlists
sudo apt install wordlists -y

# 解压rockyou字典
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

### 2. 自定义字典目录
```bash
# 创建自定义字典目录
sudo mkdir -p /usr/share/wordlists/custom

# 设置权限
sudo chmod -R 755 /usr/share/wordlists/
```

## ⚙️ 服务配置

### 1. 系统服务优化
```bash
# 禁用不必要的服务
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth

# 启用SSH (如果需要)
sudo systemctl enable ssh
sudo systemctl start ssh

# 配置防火墙
sudo ufw enable
sudo ufw allow 5000  # KaliMCP API端口
sudo ufw allow ssh
```

### 2. 文件描述符限制
```bash
# 增加文件描述符限制
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
```

## 🔄 数据库配置 (可选)

### 1. PostgreSQL (Metasploit等)
```bash
# 安装PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# 启动并启用服务
sudo systemctl enable postgresql
sudo systemctl start postgresql

# 初始化Metasploit数据库 (如果需要)
sudo msfdb init
```

### 2. MySQL/MariaDB (可选)
```bash
# 安装MariaDB
sudo apt install mariadb-server mariadb-client -y

# 安全配置
sudo mysql_secure_installation
```

## 📊 监控和日志

### 1. 系统监控
```bash
# htop - 系统监控
sudo apt install htop -y

# iotop - I/O监控
sudo apt install iotop -y

# nethogs - 网络监控
sudo apt install nethogs -y
```

### 2. 日志配置
```bash
# 配置logrotate
sudo nano /etc/logrotate.d/kalimcp

# 示例配置
/var/log/kalimcp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    create 644 www-data www-data
}
```

## 🧪 环境验证

### 1. 工具验证脚本
```bash
#!/bin/bash
# 创建验证脚本
cat << 'EOF' > check_tools.sh
#!/bin/bash

echo "=== KaliMCP 工具环境检查 ==="

# 网络扫描工具
echo "检查网络扫描工具..."
command -v nmap >/dev/null 2>&1 && echo "✓ nmap" || echo "✗ nmap"
command -v masscan >/dev/null 2>&1 && echo "✓ masscan" || echo "✗ masscan"
command -v zmap >/dev/null 2>&1 && echo "✓ zmap" || echo "✗ zmap"

# Web扫描工具
echo "检查Web扫描工具..."
command -v gobuster >/dev/null 2>&1 && echo "✓ gobuster" || echo "✗ gobuster"
command -v dirb >/dev/null 2>&1 && echo "✓ dirb" || echo "✗ dirb"
command -v nikto >/dev/null 2>&1 && echo "✓ nikto" || echo "✗ nikto"
command -v sqlmap >/dev/null 2>&1 && echo "✓ sqlmap" || echo "✗ sqlmap"
command -v nuclei >/dev/null 2>&1 && echo "✓ nuclei" || echo "✗ nuclei"

# 密码攻击工具
echo "检查密码攻击工具..."
command -v hydra >/dev/null 2>&1 && echo "✓ hydra" || echo "✗ hydra"
command -v john >/dev/null 2>&1 && echo "✓ john" || echo "✗ john"
command -v hashcat >/dev/null 2>&1 && echo "✓ hashcat" || echo "✗ hashcat"

# Python环境
echo "检查Python环境..."
python3 -c "import flask; print('✓ Flask')" 2>/dev/null || echo "✗ Flask"
python3 -c "import requests; print('✓ requests')" 2>/dev/null || echo "✗ requests"
python3 -c "import socketio; print('✓ socketio')" 2>/dev/null || echo "✗ socketio"

# 字典文件
echo "检查字典文件..."
[ -f /usr/share/wordlists/dirb/common.txt ] && echo "✓ dirb wordlists" || echo "✗ dirb wordlists"
[ -f /usr/share/wordlists/rockyou.txt ] && echo "✓ rockyou.txt" || echo "✗ rockyou.txt"

echo "=== 检查完成 ==="
EOF

chmod +x check_tools.sh
./check_tools.sh
```

### 2. 服务测试
```bash
# 测试Python Flask应用
python3 -c "
from flask import Flask
app = Flask(__name__)
print('Flask应用测试成功')
"

# 测试网络工具
nmap --version
nuclei -version
sqlmap --version
```

## 🚀 性能优化

### 1. 系统优化
```bash
# 内核参数优化
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf

# 应用配置
sudo sysctl -p
```

### 2. 并发优化
```bash
# 增加进程和线程限制
echo "DefaultLimitNOFILE=65536" | sudo tee -a /etc/systemd/system.conf
echo "DefaultLimitNPROC=32768" | sudo tee -a /etc/systemd/system.conf

# 重载systemd配置
sudo systemctl daemon-reload
```

## 🔧 故障排除

### 1. 常见问题
```bash
# 权限问题
sudo chown -R $USER:$USER /home/$USER
sudo chmod -R 755 /usr/local/bin/

# 包依赖问题
sudo apt --fix-broken install
sudo apt autoremove

# Python包问题
pip3 install --user --upgrade pip
pip3 install --user --force-reinstall package_name
```

### 2. 日志检查
```bash
# 系统日志
sudo journalctl -xe

# 服务状态
sudo systemctl status service_name

# 网络连接
ss -tulpn
netstat -tulpn
```

## 📝 维护清单

### 定期更新
```bash
#!/bin/bash
# 系统更新脚本
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
sudo apt autoclean

# 更新工具
nuclei -update-templates
wpscan --update
```

### 备份重要配置
```bash
# 备份脚本
tar -czf kali-config-backup-$(date +%Y%m%d).tar.gz \
  /etc/hosts \
  /etc/network/interfaces \
  /usr/local/bin/ \
  ~/.bashrc \
  ~/.profile
```

## 📊 资源监控

### 1. 系统资源
```bash
# 内存使用
free -h

# 磁盘空间
df -h

# CPU负载
uptime
htop
```

### 2. 网络监控
```bash
# 网络连接
ss -s
nethogs

# 带宽使用
iftop
```

---

**✅ 完成以上配置后，你的Kali Linux服务器就具备了完整的KaliMCP运行环境！**

**🎯 下一步**: 启动 `kali_server.py` 服务，并确保防火墙允许端口5000的访问。