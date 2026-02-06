# PWN 攻击命令

**用法**: `/pwn $ARGUMENTS`
**参数**: `BINARY [REMOTE]` - 二进制文件路径，可选远程目标(ip:port)

---

## 执行流程

自动化PWN二进制利用：

### 1. 解析参数
从 `$ARGUMENTS` 中提取 BINARY 路径和可选的 REMOTE 目标

### 2. 二进制分析

**基础检查**:
```
# 快速PWN漏洞检查
quick_pwn_check(binary_path=BINARY)
```

输出信息：
- 文件类型和架构
- 保护机制 (RELRO, Stack Canary, NX, PIE)
- 危险函数检测 (gets, strcpy, sprintf等)
- 利用难度评估

### 3. 深度分析

```
# 自动逆向分析
auto_reverse_analyze(binary_path=BINARY)

# Radare2详细分析
radare2_analyze_binary(binary_path=BINARY)
```

### 4. 自动化利用

**本地利用**:
```
pwnpasi_auto_pwn(
    binary_path=BINARY,
    verbose=True
)
```

**远程利用** (如果提供REMOTE):
```
# 解析 ip:port
pwnpasi_auto_pwn(
    binary_path=BINARY,
    remote_ip=IP,
    remote_port=PORT,
    verbose=True
)
```

### 5. 综合攻击

```
# 尝试多种利用方法
pwn_comprehensive_attack(
    binary_path=BINARY,
    attack_methods=["pwnpasi_auto", "ret2libc", "rop_chain", "format_string"],
    remote_target=REMOTE if 提供 else "",
    timeout=300
)
```

### 6. CTF PWN求解

```
# CTF专用PWN求解器
ctf_pwn_solver(
    target=BINARY,
    challenge_info={"category": "pwn", "binary_path": BINARY},
    time_limit="30min"
)
```

### 7. 输出结果
- 漏洞类型和位置
- 利用方法
- 成功获取的Shell
- 可复用的exploit脚本

---

## 示例

- `/pwn /tmp/vuln_binary` - 分析并利用本地二进制
- `/pwn ./challenge 192.168.1.100:9999` - 远程PWN攻击
- `/pwn /ctf/pwn1` - CTF PWN题目
