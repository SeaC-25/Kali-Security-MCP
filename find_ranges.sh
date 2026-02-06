#!/bin/bash

echo "=== 查找需要删除的函数范围 ==="

# 1. radare2_analyze_binary (7119)
echo "1. radare2_analyze_binary (错误的IDA实现)"
awk '/^    @mcp\.tool\(\)/ && NR < 7119 { last_decorator = NR }
     NR == 7119 { start = last_decorator }
     /^    @mcp\.tool\(\)/ && NR > 7119 && start { print "   行 " start " - " NR-1; exit }' mcp_server.py

# 2. pwnpasi_auto_pwn (8217)
echo "2. pwnpasi_auto_pwn (Windows路径版本)"
awk '/^    @mcp\.tool\(\)/ && NR < 8217 { last_decorator = NR }
     NR == 8217 { start = last_decorator }
     /^    @mcp\.tool\(\)/ && NR > 8217 && start { print "   行 " start " - " NR-1; exit }' mcp_server.py

# 3. pwn_comprehensive_attack (8427)
echo "3. pwn_comprehensive_attack (调用未定义函数)"
awk '/^    @mcp\.tool\(\)/ && NR < 8427 { last_decorator = NR }
     NR == 8427 { start = last_decorator }
     /^    @mcp\.tool\(\)/ && NR > 8427 && start { print "   行 " start " - " NR-1; exit }' mcp_server.py

# 4. ctf_pwn_solver (8810)
echo "4. ctf_pwn_solver (重复版本)"
awk '/^    @mcp\.tool\(\)/ && NR < 8810 { last_decorator = NR }
     NR == 8810 { start = last_decorator }
     /^    @mcp\.tool\(\)/ && NR > 8810 && start { print "   行 " start " - " NR-1; exit }
     END { if(start) print "   行 " start " - EOF" }' mcp_server.py

