#!/usr/bin/env python3
"""批量修复kali_client引用"""

import re

with open('mcp_server.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 替换模式
replacements = [
    # API调用返回错误消息
    (r'return kali_client\.safe_get\([^)]+\)', 
     'return {"success": False, "error": "本地执行模式，无需API调用"}'),
    
    (r'return kali_client\.safe_post\([^)]+\)', 
     'return {"success": False, "error": "本地执行模式，无需API调用"}'),
    
    (r'return kali_client\._execute_with_fallback\([^)]+\)', 
     'return {"success": False, "error": "本地执行模式，请使用对应的MCP工具"}'),
    
    (r'return kali_client\.check_health\(\)', 
     'return {"success": True, "status": "本地执行模式", "message": "无需健康检查"}'),
    
    # 删除kali_server_url赋值
    (r'kali_server_url = getattr\(kali_client, \'base_url\', None\)',
     'kali_server_url = None  # 本地执行模式'),
    
    # 删除async调用中的kali_client
    (r'await kali_client\.safe_post\([^)]+\)',
     '{"success": False, "error": "本地执行模式"}'),
]

for pattern, replacement in replacements:
    content = re.sub(pattern, replacement, content)

with open('mcp_server.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ 已批量修复kali_client引用")

# 统计剩余引用
remaining = content.count('kali_client')
print(f"📊 剩余 kali_client 引用: {remaining}")

