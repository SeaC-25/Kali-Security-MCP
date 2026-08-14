#!/usr/bin/env python3
"""
WebSearchBackend — LLM 自主联网搜索后端（架构设计 §8 决策七）

注册为 ToolBridge 的普通工具 web_search / web_fetch，走标准 call_tool 路径，
tool.result / execution_log 事件天然留审计日志，无需为搜索做特殊旁路。

后端（按环境变量 WEB_SEARCH_BACKEND=ddg|tavily 选择，默认 ddg）：
- DuckDuckGoBackend — duckduckgo-search / ddgs，免费无 key
- TavilyBackend     — tavily-python，需 TAVILY_API_KEY（可选后端）

降级安全：搜索/抓取遇到的任何异常（网络不可达、key 缺失、库未安装）都被吞掉，
返回空结果 + error 信息，绝不向上抛 —— LLM 决策循环不能被搜索打断。
"""

from __future__ import annotations

import html
import logging
import os
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# web_fetch 超时（秒）与正文上限（防止单条输出撑爆 LLM 上下文）
FETCH_TIMEOUT: float = 15.0
MAX_FETCH_CHARS: int = 8000

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class WebSearchBackend(ABC):
    """搜索后端抽象基类。

    公开接口 search(query, max_results) / fetch(url) 均带异常兜底：
    任何失败都返回空结果 + error 信息，永不抛异常（LLM 循环安全）。
    具体后端的搜索/抓取逻辑实现于 _do_search / _do_fetch。
    """

    name: str = "abstract"

    def search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        """搜索。返回 {"results": [...], "error": None|str}，永不抛异常。"""
        try:
            results = self._do_search(query, max_results)
            return {"results": results, "error": None}
        except Exception as e:  # noqa: BLE001 — 兜底吞异常，LLM 循环不能因搜索崩溃
            logger.warning("web_search 后端 %s 失败: %s", self.name, e)
            return {"results": [], "error": f"搜索失败({self.name}): {e}"}

    def fetch(self, url: str) -> Dict[str, Any]:
        """抓取正文。返回 {"text": str, "error": None|str}，永不抛异常。"""
        try:
            text = self._do_fetch(url)
            return {"text": text, "error": None}
        except Exception as e:  # noqa: BLE001
            logger.warning("web_fetch 后端 %s 失败: %s", self.name, e)
            return {"text": "", "error": f"抓取失败({self.name}): {e}"}

    @abstractmethod
    def _do_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """具体后端的搜索实现（可抛异常，由 search() 兜底）。"""

    @abstractmethod
    def _do_fetch(self, url: str) -> str:
        """具体后端的抓取实现（可抛异常，由 fetch() 兜底）。"""


class DuckDuckGoBackend(WebSearchBackend):
    """DuckDuckGo 后端（免费无 key）。

    库已改名：duckduckgo-search 8.x 起包名迁移为 ddgs（同名类 DDGS），
    这里优先 ddgs，回退 duckduckgo_search，两种安装都能工作。
    """

    name = "ddg"

    @staticmethod
    def _get_client_cls():
        """返回可用的 DDG 客户端类（优先新版 ddgs，回退 duckduckgo_search）。"""
        try:
            from ddgs import DDGS  # noqa: F401 — 新版包名
            return DDGS
        except ImportError:
            from duckduckgo_search import DDGS  # noqa: F401 — 旧版包名
            return DDGS

    def _do_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        DDGS = self._get_client_cls()
        with DDGS() as client:
            raw = list(client.text(query, max_results=max_results))
        results: List[Dict[str, Any]] = []
        for item in raw:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("href") or item.get("url") or "",
                "snippet": item.get("body") or item.get("snippet") or "",
            })
        return results

    def _do_fetch(self, url: str) -> str:
        return fetch_text(url)


class TavilyBackend(WebSearchBackend):
    """Tavily 后端（质量更高，需 TAVILY_API_KEY，可选）。"""

    name = "tavily"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("TAVILY_API_KEY", "")

    def _do_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        if not self.api_key:
            raise RuntimeError("缺少 TAVILY_API_KEY")
        from tavily import TavilyClient
        resp = TavilyClient(api_key=self.api_key).search(
            query=query, max_results=max_results, include_answer=False
        )
        results: List[Dict[str, Any]] = []
        for item in resp.get("results", []):
            results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("content", ""),
            })
        return results

    def _do_fetch(self, url: str) -> str:
        return fetch_text(url)


def get_search_backend() -> WebSearchBackend:
    """按环境变量 WEB_SEARCH_BACKEND 选择后端：ddg（默认）| tavily。

    未知取值回退默认 ddg，保证系统永远有一个可用的搜索后端。
    """
    choice = os.environ.get("WEB_SEARCH_BACKEND", "ddg").strip().lower()
    if choice == "tavily":
        return TavilyBackend()
    return DuckDuckGoBackend()


def fetch_text(url: str, timeout: float = FETCH_TIMEOUT,
               max_chars: int = MAX_FETCH_CHARS) -> str:
    """httpx 抓取网页正文并简单清洗（去 script/style/标签/多余空白），超时 15s。

    网络异常由调用方（WebSearchBackend.fetch 的兜底）吞掉。
    """
    import httpx
    with httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    ) as client:
        resp = client.get(url)
        resp.raise_for_status()
    return clean_html_text(resp.text, max_chars=max_chars)


def clean_html_text(raw: str, max_chars: int = MAX_FETCH_CHARS) -> str:
    """简单清洗 HTML：去掉 script/style/noscript/svg/head、标签、多余空白。"""
    if not raw:
        return ""
    text = re.sub(r"(?is)<(script|style|noscript|svg|head)\b.*?</\1>", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t\u3000\xa0]+", " ", text)  # 水平空白压缩
    text = re.sub(r"\n\s*\n+", "\n", text)          # 空行压缩
    text = "\n".join(line.strip() for line in text.splitlines())  # 行首尾空白
    text = text.strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "…"
    return text
