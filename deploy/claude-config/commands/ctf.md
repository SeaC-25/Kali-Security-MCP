# CTF 快速解题命令

**用法**: `/ctf $ARGUMENTS`
**参数**: `TARGET [CATEGORY]` - 目标URL/IP，可选分类(web/pwn/crypto/misc/reverse/auto)

---

## 执行流程

根据提供的参数 `$ARGUMENTS` 执行CTF解题：

### 1. 启用CTF模式
```
enable_ctf_mode()
```

### 2. 解析参数
- 从 `$ARGUMENTS` 中提取 TARGET 和 CATEGORY
- 如果未指定CATEGORY，使用 `auto` 自动检测

### 3. 根据分类选择解题策略

**Web题目** (category=web 或检测到HTTP服务):
```
ctf_web_comprehensive_solver(
    target=TARGET,
    challenge_info={"category": "web", "description": "CTF Web Challenge"},
    time_limit="30min"
)
```

**PWN题目** (category=pwn 或检测到二进制文件):
```
quick_pwn_check(binary_path=TARGET)
ctf_pwn_solver(
    target=TARGET,
    challenge_info={"category": "pwn"},
    time_limit="30min"
)
```

**密码学题目** (category=crypto):
```
ctf_crypto_solver(
    target=TARGET,
    challenge_info={"category": "crypto"},
    time_limit="30min"
)
```

**Misc题目** (category=misc):
```
ctf_misc_solver(
    target=TARGET,
    challenge_info={"category": "misc"},
    time_limit="30min"
)
```

**逆向题目** (category=reverse):
```
auto_reverse_analyze(binary_path=TARGET)
ctf_reverse_solver(binary_path=TARGET)
```

**自动检测** (category=auto 或未指定):
```
ctf_auto_detect_solver(
    target=TARGET,
    challenge_info={},
    time_limit="30min"
)
```

### 4. 提取Flag
```
get_detected_flags()
```

### 5. 生成解题报告
- 总结攻击路径
- 列出发现的所有Flag
- 提供可复现的PoC脚本

---

## 示例

- `/ctf http://challenge.ctf.com:8080` - 自动检测并解题
- `/ctf http://web.ctf.com web` - 明确指定Web题目
- `/ctf /tmp/pwn_binary pwn` - PWN二进制题目
- `/ctf encrypted.txt crypto` - 密码学题目
