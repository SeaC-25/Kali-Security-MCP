<div align="center">

# 🚀 PwnPasi

**Professional Automated Binary Exploitation Framework**

[![Version](https://img.shields.io/badge/version-3.0-blue.svg)](https://github.com/heimao-box/pwnpasi)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/heimao-box/pwnpasi)


</div>

---

## 🎯 What is PwnPasi?

PwnPasi is a **cutting-edge automated binary exploitation framework** designed for CTF competitions and security research, PwnPasi transforms complex binary exploitation into an automated, streamlined process.

### ✨ Key Features

🔍 **Smart Vulnerability Detection**
- Automatic stack overflow detection with dynamic padding calculation
- Format string vulnerability identification and exploitation
- Binary protection analysis (RELRO, Stack Canary, NX, PIE)
- Assembly code analysis for vulnerable function detection

⚡ **Advanced Exploitation Techniques**
- **ret2system**: Direct system function calls
- **ret2libc**: ASLR bypass through libc address leaking
- **ROP Chain Construction**: Automated gadget discovery and chaining
- **Syscall Exploitation**: execve system call chains
- **Shellcode Injection**: RWX segment exploitation
- **Stack Canary Bypass**: Format string canary leaking
- **PIE Bypass**: Position Independent Executable circumvention

🏗️ **Multi-Architecture Support**
- **x86 (32-bit)**: Complete 32-bit exploitation chains
- **x86_64 (64-bit)**: Full 64-bit exploitation support
- **Auto-detection**: Intelligent architecture recognition

🌐 **Flexible Deployment**
- **Local Mode**: Direct binary file exploitation
- **Remote Mode**: Network service targeting
- **Hybrid Approach**: Seamless local-to-remote transition

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/heimao-box/pwnpasi.git
cd pwnpasi

# Run the automated setup
python setup.py
```

The setup script will automatically:
- Install system dependencies (Kali/Debian)
- Set up Python packages (pwntools, LibcSearcher, ropper)
- Configure the environment
- Add pwnpasi to system PATH (optional)

### Basic Usage

```bash
# Analyze local binary
python pwnpasi.py -l ./target_binary

# Remote exploitation
python pwnpasi.py -l ./binary -ip 192.168.1.100 -p 9999

# Custom libc and padding
python pwnpasi.py -l ./binary -libc ./libc-2.19.so -f 112
```

---

## 💡 Usage Examples

### 🎪 Local Binary Analysis
```bash
# Comprehensive local analysis
python pwnpasi.py -l ./vuln_binary
```

### 🌍 Remote Service Exploitation
```bash
# Target remote CTF service
python pwnpasi.py -l ./local_binary -ip ctf.example.com -p 31337
```

### 🔧 Advanced Configuration
```bash
# Specify custom libc and manual padding
python pwnpasi.py -l ./binary -libc /lib/x86_64-linux-gnu/libc.so.6 -f 88 -v
```

---

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|----------|
| `-l, --local` | Target binary file (required) | `-l ./vuln_app` |
| `-ip, --ip` | Remote target IP address | `-ip 192.168.1.100` |
| `-p, --port` | Remote target port | `-p 9999` |
| `-libc, --libc` | Custom libc file path | `-libc ./libc-2.27.so` |
| `-f, --fill` | Manual overflow padding size | `-f 112` |
| `-v, --verbose` | Enable verbose output | `-v` |

---

## 🛠️ Technical Arsenal

### Core Dependencies
- **pwntools** - The ultimate CTF framework
- **LibcSearcher** - Libc database and version detection
- **ropper** - Advanced ROP gadget discovery
- **checksec** - Binary security feature analysis

### System Tools Integration
- **objdump** - Assembly analysis and disassembly
- **strings** - String extraction and analysis
- **ldd** - Dynamic library dependency mapping
- **gdb** - Advanced debugging capabilities

---

## 🎨 Output Preview



https://github.com/user-attachments/assets/1395d646-eeeb-4342-8b93-e05eed282b92



---

## 🏆 Why Choose PwnPasi?

### 🎯 **Precision & Automation**
No more manual gadget hunting or address calculation. PwnPasi automates the entire exploitation pipeline with surgical precision.

### 🚀 **Speed & Efficiency**
From vulnerability detection to shell acquisition in seconds, not hours. Perfect for time-critical CTF scenarios.

### 🧠 **Intelligence & Adaptability**
Smart fallback mechanisms ensure maximum success rate across different binary configurations and protection schemes.

---

## 🤝 Contributing

We welcome contributions! Whether it's:
- 🐛 Bug reports and fixes
- ✨ New exploitation techniques
- 📚 Documentation improvements
- 🔧 Performance optimizations

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

PwnPasi is designed for **educational purposes** and **authorized security testing** only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers assume no liability for misuse of this tool.

---

<div align="center">

**Made with ❤️ by Ba1_Ma0**

*Star ⭐ this repo if PwnPasi helped you pwn some binaries!*

</div>
