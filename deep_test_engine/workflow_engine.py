"""
多步骤测试工作流引擎
======================

支持复杂多步骤测试流程：
- 工作流定义和执行
- 状态转换管理
- 变量提取和传递
- 条件分支执行
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import uuid

from .models import (
    WorkflowStep, WorkflowDefinition, HTTPRequest, HTTPResponse
)

logger = logging.getLogger(__name__)


class WorkflowEngine:
    """
    多步骤测试工作流引擎

    功能：
    - 定义和管理测试工作流
    - 执行多步骤测试序列
    - 变量提取和传递
    - 条件分支控制
    """

    def __init__(self, http_engine=None):
        """
        初始化工作流引擎

        Args:
            http_engine: HTTP交互引擎实例
        """
        self.http_engine = http_engine
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.execution_history: List[Dict[str, Any]] = []

        # 内置工作流模板
        self._init_builtin_workflows()

    def _init_builtin_workflows(self):
        """初始化内置工作流模板"""
        # 认证绕过测试工作流
        self.workflows['auth_bypass'] = WorkflowDefinition(
            name="认证绕过测试",
            description="测试各种认证绕过技术",
            steps=[
                WorkflowStep(
                    name="direct_access",
                    action="http_request",
                    params={"method": "GET", "url": "{protected_url}"},
                    on_success="check_auth_required",
                    on_failure="end_failure",
                    extract_vars={"initial_status": "status_code"}
                ),
                WorkflowStep(
                    name="check_auth_required",
                    action="condition",
                    params={"condition": "{initial_status} in [401, 403, 302]"},
                    on_success="try_bypass_methods",
                    on_failure="already_accessible"
                ),
                WorkflowStep(
                    name="try_bypass_methods",
                    action="parallel_requests",
                    params={
                        "requests": [
                            {"method": "GET", "url": "{protected_url}", "headers": {"X-Original-URL": "{path}"}},
                            {"method": "GET", "url": "{protected_url}", "headers": {"X-Rewrite-URL": "{path}"}},
                            {"method": "GET", "url": "{protected_url}", "headers": {"X-Forwarded-For": "127.0.0.1"}},
                            {"method": "GET", "url": "{protected_url}%00"},
                            {"method": "GET", "url": "{protected_url}/..;/"},
                            {"method": "GET", "url": "{protected_url}#"},
                        ]
                    },
                    on_success="analyze_bypass_results",
                    on_failure="end_failure"
                )
            ]
        )

        # CSRF测试工作流
        self.workflows['csrf_test'] = WorkflowDefinition(
            name="CSRF测试",
            description="测试跨站请求伪造漏洞",
            steps=[
                WorkflowStep(
                    name="get_form_page",
                    action="http_request",
                    params={"method": "GET", "url": "{target_url}"},
                    on_success="extract_tokens",
                    on_failure="end_failure",
                    extract_vars={"page_content": "body"}
                ),
                WorkflowStep(
                    name="extract_tokens",
                    action="extract",
                    params={
                        "patterns": {
                            "csrf_token": r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
                            "session_id": r'PHPSESSID=([a-zA-Z0-9]+)'
                        }
                    },
                    on_success="test_without_token",
                    on_failure="test_without_token"
                ),
                WorkflowStep(
                    name="test_without_token",
                    action="http_request",
                    params={
                        "method": "POST",
                        "url": "{action_url}",
                        "body": "{form_data_without_token}"
                    },
                    on_success="analyze_csrf_result",
                    on_failure="analyze_csrf_result"
                )
            ]
        )

        # 会话劫持测试工作流
        self.workflows['session_hijack'] = WorkflowDefinition(
            name="会话劫持测试",
            description="测试会话管理漏洞",
            steps=[
                WorkflowStep(
                    name="login",
                    action="http_request",
                    params={
                        "method": "POST",
                        "url": "{login_url}",
                        "body": "{credentials}"
                    },
                    on_success="extract_session",
                    on_failure="end_failure",
                    extract_vars={"session_cookie": "cookies.session"}
                ),
                WorkflowStep(
                    name="test_session_fixation",
                    action="http_request",
                    params={
                        "method": "GET",
                        "url": "{target_url}",
                        "cookies": {"session": "{preset_session}"}
                    },
                    on_success="check_fixation",
                    on_failure="end_failure"
                )
            ]
        )

    def define_workflow(
        self,
        name: str,
        steps: List[Dict[str, Any]],
        description: str = ""
    ) -> str:
        """
        定义自定义工作流

        Args:
            name: 工作流名称
            steps: 步骤定义列表
            description: 工作流描述

        Returns:
            str: 工作流ID
        """
        workflow_id = str(uuid.uuid4())

        workflow_steps = []
        for step_dict in steps:
            step = WorkflowStep(
                name=step_dict.get('name', f'step_{len(workflow_steps)}'),
                action=step_dict.get('action', 'http_request'),
                params=step_dict.get('params', {}),
                on_success=step_dict.get('on_success', ''),
                on_failure=step_dict.get('on_failure', 'end_failure'),
                extract_vars=step_dict.get('extract_vars', {})
            )
            workflow_steps.append(step)

        workflow = WorkflowDefinition(
            id=workflow_id,
            name=name,
            description=description,
            steps=workflow_steps
        )

        self.workflows[workflow_id] = workflow
        logger.info(f"[Workflow] 定义工作流: {name} ({workflow_id})")

        return workflow_id

    async def execute_workflow(
        self,
        workflow_id: str,
        initial_vars: Dict[str, Any] = None,
        timeout: float = 300.0
    ) -> Dict[str, Any]:
        """
        执行工作流

        Args:
            workflow_id: 工作流ID或内置名称
            initial_vars: 初始变量
            timeout: 总超时时间

        Returns:
            Dict: 执行结果
        """
        # 获取工作流定义
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return {"error": f"工作流不存在: {workflow_id}"}

        result = {
            "workflow_id": workflow_id,
            "workflow_name": workflow.name,
            "started_at": datetime.now().isoformat(),
            "variables": initial_vars.copy() if initial_vars else {},
            "steps_executed": [],
            "success": False,
            "findings": []
        }

        try:
            current_step_name = workflow.steps[0].name if workflow.steps else None
            step_map = {step.name: step for step in workflow.steps}

            while current_step_name:
                if current_step_name.startswith('end_'):
                    result['success'] = current_step_name == 'end_success'
                    break

                step = step_map.get(current_step_name)
                if not step:
                    result['error'] = f"步骤不存在: {current_step_name}"
                    break

                # 执行步骤
                step_result = await asyncio.wait_for(
                    self._execute_step(step, result['variables']),
                    timeout=timeout / len(workflow.steps)
                )

                result['steps_executed'].append({
                    'name': step.name,
                    'action': step.action,
                    'result': step_result
                })

                # 更新变量
                if step_result.get('extracted_vars'):
                    result['variables'].update(step_result['extracted_vars'])

                # 记录发现
                if step_result.get('findings'):
                    result['findings'].extend(step_result['findings'])

                # 确定下一步
                if step_result.get('success'):
                    current_step_name = step.on_success
                else:
                    current_step_name = step.on_failure

        except asyncio.TimeoutError:
            result['error'] = "工作流执行超时"
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[Workflow] 执行错误: {e}")

        result['completed_at'] = datetime.now().isoformat()
        self.execution_history.append(result)

        return result

    async def _execute_step(
        self,
        step: WorkflowStep,
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        执行单个工作流步骤

        Args:
            step: 步骤定义
            variables: 当前变量

        Returns:
            Dict: 步骤执行结果
        """
        result = {
            "success": False,
            "extracted_vars": {},
            "findings": []
        }

        # 替换参数中的变量
        params = self._substitute_variables(step.params, variables)

        try:
            if step.action == "http_request":
                result = await self._action_http_request(params, step.extract_vars)

            elif step.action == "parallel_requests":
                result = await self._action_parallel_requests(params)

            elif step.action == "condition":
                result = self._action_condition(params, variables)

            elif step.action == "extract":
                result = self._action_extract(params, variables)

            elif step.action == "wait":
                await asyncio.sleep(params.get('seconds', 1))
                result['success'] = True

            elif step.action == "assert":
                result = self._action_assert(params, variables)

            else:
                result['error'] = f"未知动作类型: {step.action}"

        except Exception as e:
            result['error'] = str(e)

        return result

    def _substitute_variables(
        self,
        obj: Any,
        variables: Dict[str, Any]
    ) -> Any:
        """替换对象中的变量占位符"""
        if isinstance(obj, str):
            # 替换 {var_name} 格式的变量
            for key, value in variables.items():
                obj = obj.replace(f"{{{key}}}", str(value))
            return obj

        elif isinstance(obj, dict):
            return {k: self._substitute_variables(v, variables) for k, v in obj.items()}

        elif isinstance(obj, list):
            return [self._substitute_variables(item, variables) for item in obj]

        return obj

    async def _action_http_request(
        self,
        params: Dict[str, Any],
        extract_vars: Dict[str, str]
    ) -> Dict[str, Any]:
        """执行HTTP请求动作"""
        result = {
            "success": False,
            "extracted_vars": {},
            "findings": []
        }

        if not self.http_engine:
            result['error'] = "HTTP引擎未初始化"
            return result

        try:
            response = await self.http_engine.send_request(
                url=params.get('url', ''),
                method=params.get('method', 'GET'),
                headers=params.get('headers'),
                body=params.get('body'),
                cookies=params.get('cookies')
            )

            result['success'] = True
            result['response'] = {
                'status_code': response.status_code,
                'headers': response.headers,
                'body_length': len(response.body) if response.body else 0
            }

            # 提取变量
            for var_name, path in extract_vars.items():
                value = self._extract_value(response, path)
                if value is not None:
                    result['extracted_vars'][var_name] = value

            # 检测潜在发现
            if response.status_code == 200:
                body_text = response.body.decode('utf-8', errors='replace') if response.body else ''
                if len(body_text) > 1000:  # 可能访问成功
                    result['findings'].append({
                        'type': 'access_success',
                        'description': '成功访问资源',
                        'evidence': body_text[:500]
                    })

        except Exception as e:
            result['error'] = str(e)

        return result

    async def _action_parallel_requests(
        self,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """并行执行多个HTTP请求"""
        result = {
            "success": False,
            "extracted_vars": {},
            "findings": [],
            "responses": []
        }

        if not self.http_engine:
            result['error'] = "HTTP引擎未初始化"
            return result

        requests = params.get('requests', [])

        try:
            tasks = []
            for req in requests:
                task = self.http_engine.send_request(
                    url=req.get('url', ''),
                    method=req.get('method', 'GET'),
                    headers=req.get('headers'),
                    body=req.get('body'),
                    cookies=req.get('cookies')
                )
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for i, resp in enumerate(responses):
                if isinstance(resp, Exception):
                    result['responses'].append({'error': str(resp)})
                else:
                    resp_info = {
                        'request_index': i,
                        'status_code': resp.status_code,
                        'body_length': len(resp.body) if resp.body else 0
                    }
                    result['responses'].append(resp_info)

                    # 检测绕过成功
                    if resp.status_code == 200:
                        body_text = resp.body.decode('utf-8', errors='replace') if resp.body else ''
                        if len(body_text) > 500:
                            result['findings'].append({
                                'type': 'bypass_success',
                                'description': f'请求 {i} 可能绕过认证',
                                'request': requests[i],
                                'evidence': body_text[:300]
                            })

            result['success'] = len([r for r in result['responses'] if 'error' not in r]) > 0

        except Exception as e:
            result['error'] = str(e)

        return result

    def _action_condition(
        self,
        params: Dict[str, Any],
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行条件判断"""
        result = {"success": False, "extracted_vars": {}, "findings": []}

        condition = params.get('condition', '')

        # 替换变量
        for key, value in variables.items():
            condition = condition.replace(f"{{{key}}}", repr(value))

        try:
            result['success'] = eval(condition, {"__builtins__": {}}, {})
        except:
            result['success'] = False

        return result

    def _action_extract(
        self,
        params: Dict[str, Any],
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """从内容中提取数据"""
        result = {"success": False, "extracted_vars": {}, "findings": []}

        patterns = params.get('patterns', {})
        source = variables.get('page_content', '')

        for var_name, pattern in patterns.items():
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                result['extracted_vars'][var_name] = match.group(1) if match.groups() else match.group(0)

        result['success'] = len(result['extracted_vars']) > 0

        return result

    def _action_assert(
        self,
        params: Dict[str, Any],
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行断言检查"""
        result = {"success": False, "extracted_vars": {}, "findings": []}

        assertions = params.get('assertions', [])

        for assertion in assertions:
            try:
                expr = assertion.get('expression', '')
                for key, value in variables.items():
                    expr = expr.replace(f"{{{key}}}", repr(value))

                if not eval(expr, {"__builtins__": {}}, {}):
                    result['findings'].append({
                        'type': 'assertion_failed',
                        'description': assertion.get('message', '断言失败'),
                        'expression': assertion.get('expression')
                    })
                    return result
            except:
                pass

        result['success'] = True
        return result

    def _extract_value(
        self,
        response: HTTPResponse,
        path: str
    ) -> Optional[Any]:
        """从响应中提取值"""
        try:
            if path == 'status_code':
                return response.status_code
            elif path == 'body':
                return response.body.decode('utf-8', errors='replace') if response.body else ''
            elif path.startswith('headers.'):
                header_name = path[8:]
                return response.headers.get(header_name)
            elif path.startswith('cookies.'):
                cookie_name = path[8:]
                return response.cookies.get(cookie_name)
        except:
            pass
        return None

    async def execute_auth_bypass_test(
        self,
        login_url: str,
        protected_url: str,
        credentials: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        执行认证绕过测试

        Args:
            login_url: 登录页面URL
            protected_url: 受保护资源URL
            credentials: 可选的凭据

        Returns:
            Dict: 测试结果
        """
        from urllib.parse import urlparse

        parsed = urlparse(protected_url)
        path = parsed.path

        initial_vars = {
            'login_url': login_url,
            'protected_url': protected_url,
            'path': path,
            'credentials': json.dumps(credentials) if credentials else '{}'
        }

        result = await self.execute_workflow('auth_bypass', initial_vars)

        # 汇总分析
        bypass_methods = []
        for step in result.get('steps_executed', []):
            if step.get('result', {}).get('findings'):
                for finding in step['result']['findings']:
                    if finding.get('type') == 'bypass_success':
                        bypass_methods.append(finding)

        result['summary'] = {
            'vulnerable': len(bypass_methods) > 0,
            'bypass_methods': bypass_methods,
            'recommendation': '实施严格的服务器端访问控制' if bypass_methods else '未发现认证绕过'
        }

        return result

    async def execute_csrf_test(
        self,
        target_url: str,
        action_url: str,
        form_data: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        执行CSRF测试

        Args:
            target_url: 目标页面URL
            action_url: 表单提交URL
            form_data: 表单数据

        Returns:
            Dict: 测试结果
        """
        # 构建不含CSRF token的表单数据
        form_data_without_token = {k: v for k, v in form_data.items()
                                   if 'csrf' not in k.lower() and 'token' not in k.lower()}

        initial_vars = {
            'target_url': target_url,
            'action_url': action_url,
            'form_data_without_token': json.dumps(form_data_without_token)
        }

        result = await self.execute_workflow('csrf_test', initial_vars)

        # 分析结果
        csrf_vulnerable = False
        for step in result.get('steps_executed', []):
            step_result = step.get('result', {})
            if step.get('name') == 'test_without_token':
                resp = step_result.get('response', {})
                # 如果没有token的请求成功执行，可能存在CSRF
                if resp.get('status_code') in [200, 302]:
                    csrf_vulnerable = True

        result['summary'] = {
            'vulnerable': csrf_vulnerable,
            'description': 'CSRF保护不足' if csrf_vulnerable else 'CSRF保护正常',
            'recommendation': '实施CSRF令牌验证' if csrf_vulnerable else None
        }

        return result

    async def execute_session_test(
        self,
        login_url: str,
        credentials: Dict[str, str],
        target_url: str
    ) -> Dict[str, Any]:
        """
        执行会话安全测试

        Args:
            login_url: 登录URL
            credentials: 登录凭据
            target_url: 测试目标URL

        Returns:
            Dict: 测试结果
        """
        initial_vars = {
            'login_url': login_url,
            'credentials': json.dumps(credentials),
            'target_url': target_url,
            'preset_session': 'fixation_test_' + str(uuid.uuid4())[:8]
        }

        result = await self.execute_workflow('session_hijack', initial_vars)

        # 分析会话安全问题
        issues = []

        for step in result.get('steps_executed', []):
            step_result = step.get('result', {})
            if step.get('name') == 'login':
                # 检查登录后是否重新生成会话
                old_session = initial_vars.get('preset_session')
                new_session = step_result.get('extracted_vars', {}).get('session_cookie')
                if old_session and new_session and old_session == new_session:
                    issues.append({
                        'type': 'session_fixation',
                        'description': '登录后未重新生成会话ID'
                    })

        result['summary'] = {
            'vulnerable': len(issues) > 0,
            'issues': issues,
            'recommendation': '登录后重新生成会话ID' if issues else '会话管理正常'
        }

        return result

    def get_builtin_workflows(self) -> List[Dict[str, str]]:
        """获取内置工作流列表"""
        return [
            {
                'id': wf_id,
                'name': wf.name,
                'description': wf.description,
                'steps_count': len(wf.steps)
            }
            for wf_id, wf in self.workflows.items()
        ]

    def get_execution_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取执行历史"""
        return self.execution_history[-limit:]

    def clear_history(self):
        """清除执行历史"""
        self.execution_history.clear()
