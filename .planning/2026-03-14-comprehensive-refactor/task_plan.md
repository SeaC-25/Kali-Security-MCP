# Kali MCP 全面重构计划 v6.0

> 日期: 2026-03-14
> 目标: 全面提升智能化和渗透能力

## 重构目标

1. **消灭 elif 地狱** — 将 local_executor.py 的 100+ elif 分支重构为声明式工具注册表
2. **结构化输出解析** — 替代 5000 字符截断的原始文本，为关键工具添加智能结果解析
3. **安全模型修复** — 修复域名匹配漏洞、区分 compliance/full 档位
4. **智能决策闭环** — 工具执行 → 结构化解析 → 上下文更新 → 智能下一步决策
5. **全局状态治理** — 会话 TTL、自动清理、内存管理

## 实施阶段

### Phase 1: 声明式工具注册表 (核心重构)

**新建文件**: `kali_mcp/core/tool_registry.py`

- `ToolParam` 数据类: 参数定义 (name, flag, required, default, sanitize_mode, position)
- `ToolSpec` 数据类: 工具规格 (binary, params, base_args, timeout, output_parser, target_param)
- `TOOL_REGISTRY`: 所有 67+ 工具的声明式注册表
- `build_command(tool_name, data)`: 通用命令构建器，替代 elif 链

### Phase 2: 结构化输出解析器

**新建文件**: `kali_mcp/core/output_parsers.py`

- `NmapParser`: 解析端口、服务、版本、OS
- `GobusterParser`: 解析发现的路径和状态码
- `NucleiParser`: 解析漏洞发现（JSON行）
- `SqlmapParser`: 解析注入点和数据库信息
- `SubfinderParser`: 解析子域名列表
- `GenericParser`: 通用文本解析 + Flag 检测
- 每个解析器返回结构化 `ParsedResult` 对象

### Phase 3: 安全模型修复

**修改文件**: `kali_mcp/security/engagement.py`
- 修复 `_in_scope` 域名匹配: 使用 `.split('.')` 精确层级比较

**修改文件**: `kali_mcp/security/tool_profile.py`
- 区分 compliance 和 full: compliance 禁用 apt/deep_test/pwn

### Phase 4: 智能决策闭环增强

**修改文件**: `kali_mcp/core/local_executor.py`
- 集成 tool_registry 的 `build_command()`
- 集成 output_parsers 的结构化解析
- 执行结果包含 `parsed_result` 字段
- 事件总线广播结构化数据而非截断文本

### Phase 5: 全局状态治理

**修改文件**: `mcp_server.py`
- 添加会话 TTL (默认 1 小时)
- 添加定期清理任务
- 限制最大并发会话数

## 文件变更清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `kali_mcp/core/tool_registry.py` | 新建 | 声明式工具注册表 + 命令构建器 |
| `kali_mcp/core/output_parsers.py` | 新建 | 结构化输出解析器 |
| `kali_mcp/core/local_executor.py` | 重构 | 替换 elif 链，集成新系统 |
| `kali_mcp/security/engagement.py` | 修复 | 域名匹配安全漏洞 |
| `kali_mcp/security/tool_profile.py` | 增强 | compliance/full 区分 |
| `mcp_server.py` | 增强 | 状态管理 + 清理 |

## 向后兼容性

- `execute_tool_with_data()` 接口不变
- `ALLOWED_TOOLS` 集合自动从 TOOL_REGISTRY 生成
- 现有 MCP 工具函数无需修改
- 测试应继续通过
