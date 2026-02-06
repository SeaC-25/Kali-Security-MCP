# Kali MCP Docker 镜像
# 智能化渗透测试MCP服务器 v2.0
#
# 构建: docker build -t kali-mcp -f docker/Dockerfile .
# 运行: docker run -it --rm kali-mcp

FROM kalilinux/kali-rolling

LABEL maintainer="Kali MCP Team"
LABEL version="2.0.0"
LABEL description="Intelligent penetration testing MCP server"

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV KALI_MCP_DATA_DIR=/data

# 更新系统并安装基础工具
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装核心安全工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 网络侦察
    nmap \
    masscan \
    netcat-openbsd \
    tcpdump \
    wireshark-common \
    # Web安全
    gobuster \
    dirb \
    nikto \
    sqlmap \
    wfuzz \
    # 漏洞扫描
    nuclei \
    # 密码攻击
    hydra \
    john \
    hashcat \
    medusa \
    ncrack \
    # DNS工具
    dnsutils \
    dnsrecon \
    dnsenum \
    # OSINT
    theharvester \
    whois \
    # 漏洞利用
    metasploit-framework \
    exploitdb \
    # PWN/逆向
    binwalk \
    checksec \
    radare2 \
    gdb \
    # 无线
    aircrack-ng \
    # SMB
    enum4linux \
    smbclient \
    # 其他
    wordlists \
    seclists \
    && rm -rf /var/lib/apt/lists/*

# 安装可选工具 (可能不可用)
RUN apt-get update && apt-get install -y --no-install-recommends \
    subfinder \
    amass \
    feroxbuster \
    ffuf \
    whatweb \
    wpscan \
    responder \
    bettercap \
    || true && \
    rm -rf /var/lib/apt/lists/*

# 创建工作目录
WORKDIR /app

# 复制requirements并安装Python依赖
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt || \
    pip3 install --no-cache-dir mcp flask flask-cors jinja2

# 复制项目文件
COPY kali_mcp/ /app/kali_mcp/
COPY mcp_server.py /app/
COPY fast_config.py /app/
COPY connection_pool.py /app/

# 创建数据目录
RUN mkdir -p /data/learning /data/reports /data/cache /data/logs

# 设置权限
RUN chmod +x /app/kali_mcp/main.py

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -m kali_mcp.main --health-check || exit 1

# 暴露端口
EXPOSE 8080

# 默认命令
CMD ["python3", "-m", "kali_mcp.main"]
