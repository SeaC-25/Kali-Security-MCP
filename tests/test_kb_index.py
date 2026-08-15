# -*- coding: utf-8 -*-
"""P0 向量化知识库单测（ARCH_DESIGN §11.3 P0 验收）。

覆盖：切分规则（标题分节/代码块整体保留/300~800 字符/相邻重叠 50）、
AttackChain 结构化提取、content_hash 增量跳过、RRF 融合、tokenizer、
numpy 与 sqlite-vec 两种后端端到端检索、失败静默降级。
全部离线：embedding 用注入的假 embedder，不触网、不加载真实模型。
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_build():
    spec = importlib.util.spec_from_file_location(
        "kb_build_mod", ROOT / "scripts" / "build_kb_index.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load_build()

from kali_mcp.reasoning.knowledge_retriever import (  # noqa: E402
    KbHit,
    KnowledgeRetriever,
    rrf_fuse,
    tokenize,
)

REAL_SOURCES = 17  # scripts/kb_sources.yaml 展开的真实文件数


def _token_embed(text: str) -> list:
    """确定性词袋向量（512 维，归一化）：共享 token -> 高余弦。测试用假 embedder。"""
    v = np.zeros(512, dtype=np.float32)
    for t in tokenize(text):
        v[abs(hash(t)) % 512] += 1.0
    n = float(np.linalg.norm(v))
    return (v / n).tolist() if n else v.tolist()


# --------------------------------------------------------------------------
# 切分规则
# --------------------------------------------------------------------------


def test_text_blocks_target_size_and_overlap():
    text = "恶意载荷" * 500  # 2000 字符，无标点边界 -> 字符硬切
    blocks = B._text_blocks(text, 300, 800, 50)
    assert len(blocks) >= 3
    for b in blocks:
        assert 300 <= len(b) <= 800
    for i in range(len(blocks) - 1):
        assert blocks[i][-50:] == blocks[i + 1][:50]  # 相邻块重叠 50 字符


def test_text_blocks_small_text_single_chunk():
    text = "短正文" * 50  # 150 字符
    blocks = B._text_blocks(text, 300, 800, 50)
    assert blocks == [text]


def test_markdown_sections_and_code_block_kept():
    md = (
        "# 顶层\n\n"
        "第一段正文内容用于测试。\n\n"
        "第二段正文内容。\n\n"
        "## 子节 A\n\n"
        "子节正文。\n\n"
        "```bash\n"
        "nmap -sV -p- 10.0.0.1\n"
        "sqlmap -u http://t/1.php?id=1 --batch\n"
        "```\n\n"
        "## 子节 B\n\n"
        "B 的正文。\n"
    )
    chunks = B.chunk_markdown(md, "fake.md", "test", "hash1")
    assert chunks
    assert chunks[0]["section"] == "顶层"
    code = [c for c in chunks if "代码块" in c["section"]]
    assert len(code) == 1
    assert "nmap -sV -p- 10.0.0.1" in code[0]["text"]
    assert "sqlmap -u" in code[0]["text"]  # 代码块整体保留
    sections = [c["section"] for c in chunks]
    assert any(s.startswith("顶层 / 子节 A") for s in sections)
    assert any(s.startswith("顶层 / 子节 B") for s in sections)


def test_markdown_code_block_kept_whole_even_large():
    code = "".join(f"line {i} payload\n" for i in range(120))  # ~1500 字符
    md = f"# S\n\n正文。\n\n```py\n{code}```\n"
    chunks = B.chunk_markdown(md, "fake.md", "test", "h")
    code_chunks = [c for c in chunks if "代码块" in c["section"]]
    assert len(code_chunks) == 1
    assert "line 0 payload" in code_chunks[0]["text"]
    assert "line 119 payload" in code_chunks[0]["text"]
    assert len(code_chunks[0]["text"]) >= 1400  # 未按 800 截断


def test_markdown_record_schema():
    md = "# 标题\n\n" + "内容" * 200
    chunks = B.chunk_markdown(md, "data/x.md", "credentials", "abc123")
    for c in chunks:
        assert c["source"] == "data/x.md"
        assert c["category"] == "credentials"
        assert c["content_hash"] == "abc123"
        assert c["meta"]["category"] == "credentials"
        assert c["section"] == "标题"
        assert c["text"]


def test_playbook_docstring_extraction():
    src = (ROOT / "kali_mcp" / "core" / "playbooks" / "web_surface.py").read_text(encoding="utf-8")
    chunks = B.chunk_playbook_docstrings(src, "kali_mcp/core/playbooks/web_surface.py",
                                         "playbook_ref", "h")
    assert chunks
    assert all(c["meta"]["tool"] == "web_surface" for c in chunks)
    # 模块 docstring 摘录进来
    assert any("web_surface playbook" in c["text"] for c in chunks)


def test_attack_chain_extraction():
    p = ROOT / "kali_mcp" / "reasoning" / "knowledge_graph.py"
    chains = B.extract_attack_chains(p)
    assert len(chains) >= 100  # 文档自称 100+ 条攻击路径
    keys = {"from_vuln", "to_vuln", "reasoning", "success_prob",
            "time_cost", "tools", "conditions"}
    for c in chains:
        assert keys.issubset(c.keys())
    triples = {(c["from_vuln"], c["to_vuln"], c["reasoning"]) for c in chains}
    assert len(triples) == len(chains)  # 无重复
    chunks = B.chunk_attack_chains(chains, "kali_mcp/reasoning/knowledge_graph.py", "chain", "h")
    assert len(chunks) == len(chains)
    assert chunks[0]["meta"]["from_vuln"] == chains[0]["from_vuln"]


# --------------------------------------------------------------------------
# 增量构建（content_hash 跳过未变文件）
# --------------------------------------------------------------------------


def _build_args(tmp_path, backend):
    return argparse.Namespace(
        config=str(ROOT / "scripts" / "kb_sources.yaml"),
        db=str(tmp_path / "kb.db"),
        json=str(tmp_path / "kb.json"),
        model_dir=str(tmp_path / "models"),
        force=False,
        reset=False,
        backend=backend,
    )


@pytest.mark.parametrize("backend", ["numpy", "sqlite_vec"])
def test_build_incremental_skips_unchanged(tmp_path, monkeypatch, backend):
    if backend == "sqlite_vec":
        pytest.importorskip("sqlite_vec")
    monkeypatch.setattr(B, "_embed_batch", lambda model, texts: [_token_embed(t) for t in texts])
    monkeypatch.setattr(B, "_load_model", lambda *a, **k: object())

    args = _build_args(tmp_path, backend)
    s1 = B.build(args)
    assert s1["files_changed"] == REAL_SOURCES
    assert s1["files_skipped"] == 0
    assert s1["total_chunks"] > 0
    first_total = s1["total_chunks"]

    s2 = B.build(args)
    assert s2["files_changed"] == 0
    assert s2["files_skipped"] == REAL_SOURCES  # content_hash 命中全部跳过
    assert s2["total_chunks"] == first_total

    # 强制重建会重新处理全部文件
    args2 = _build_args(tmp_path, backend)
    args2.force = True
    s3 = B.build(args2)
    assert s3["files_changed"] == REAL_SOURCES
    assert s3["total_chunks"] == first_total


def test_hash_file_stable():
    p = ROOT / "data" / "wordlists" / "CREDENTIALS_GUIDE.md"
    assert B.hash_file(p) == B.hash_file(p)
    assert len(B.hash_file(p)) == 64


# --------------------------------------------------------------------------
# RRF / tokenizer
# --------------------------------------------------------------------------


def test_rrf_fuse_order_and_dedupe():
    va = [KbHit(1, "s1", "", "t", 1.0), KbHit(2, "s2", "", "t", 1.0), KbHit(3, "s3", "", "t", 1.0)]
    bm = [KbHit(4, "s4", "", "t", 1.0), KbHit(1, "s1", "", "t", 1.0), KbHit(2, "s2", "", "t", 1.0)]
    fused = rrf_fuse(va, bm, k=1)
    assert [h.chunk_id for h in fused] == [1, 2, 4, 3]
    assert len({h.chunk_id for h in fused}) == 4  # 去重
    assert fused[0].score > fused[1].score > fused[3].score


def test_tokenize_mixed_cjk_ascii():
    toks = tokenize("SQL注入检测 payload-XSS")
    assert "sql" in toks and "payload" in toks and "xss" in toks
    assert "注" in toks and "入" in toks and "检" in toks
    assert tokenize("") == []


# --------------------------------------------------------------------------
# 端到端检索
# --------------------------------------------------------------------------

CHUNK_A = {
    "id": 1, "source": "data/wordlists/CREDENTIALS_GUIDE.md",
    "section": "Windows/AD", "category": "credentials",
    "text": "Windows 域管理员默认账号与默认密码 Administrator / Admin@123 / P@ssw0rd",
    "meta": {"category": "credentials"},
    "content_hash": "a",
}
CHUNK_B = {
    "id": 2, "source": "kali_mcp/reasoning/knowledge_graph.py",
    "section": "chain::SQL_INJECTION -> FILE_INCLUSION", "category": "chain",
    "text": "攻击链：SQL注入可以读取文件，尝试利用 LOAD_FILE 读取敏感文件，发现 LFI 漏洞",
    "meta": {"category": "chain", "from_vuln": "SQL_INJECTION", "to_vuln": "FILE_INCLUSION"},
    "content_hash": "b",
}
CHUNK_C = {
    "id": 3, "source": "tools_recipes/nmap.yaml",
    "section": "tools_recipes/nmap.yaml", "category": "recipe",
    "text": "nmap 端口与服务版本扫描，探测 open ports 与 service version，支持脚本与漏洞探测",
    "meta": {"category": "recipe", "tool": "nmap"},
    "content_hash": "c",
}


def _write_numpy_json(tmp_path):
    payload = {
        "backend": "numpy", "version": 1, "embedding_dim": 512,
        "chunks": [
            {**CHUNK_A, "embedding": _token_embed(CHUNK_A["text"])},
            {**CHUNK_B, "embedding": _token_embed(CHUNK_B["text"])},
            {**CHUNK_C, "embedding": _token_embed(CHUNK_C["text"])},
        ],
    }
    p = tmp_path / "kb.json"
    p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return p


def _retriever(tmp_path, **kw):
    kw.setdefault("db_path", tmp_path / "no.db")
    kw.setdefault("json_path", _write_numpy_json(tmp_path))
    kw.setdefault("embedder", _token_embed)
    kw.setdefault("backend", "numpy")
    return KnowledgeRetriever(**kw)


def test_retriever_numpy_semantic_top1(tmp_path):
    r = _retriever(tmp_path)
    assert r.hit_count() == 3
    for query, expect in [
        ("域管理员默认密码", "data/wordlists/CREDENTIALS_GUIDE.md"),
        ("SQL 注入读取文件", "kali_mcp/reasoning/knowledge_graph.py"),
        ("端口与服务版本扫描", "tools_recipes/nmap.yaml"),
    ]:
        hits = r.retrieve(query, top_k=3)
        assert hits, f"query {query!r} 无命中"
        assert hits[0].source == expect, f"query {query!r} top1={hits[0].source}"
        assert hits[0].score > 0


def test_retriever_filters(tmp_path):
    r = _retriever(tmp_path)
    hits = r.retrieve("域管理员默认密码", top_k=3, filters={"category": "chain"})
    assert hits and all(h.meta["category"] == "chain" for h in hits)
    hits = r.retrieve("域管理员默认密码", top_k=3, filters={"source": CHUNK_A["source"]})
    assert hits and all(h.source == CHUNK_A["source"] for h in hits)
    hits = r.retrieve("域管理员默认密码", top_k=3, filters={"tool": "sqlmap"})
    assert not hits  # 过滤后无匹配
    hits = r.retrieve("域管理员默认密码", top_k=3, filters={"tool": "nmap"})
    assert hits and hits[0].source == CHUNK_C["source"]  # nmap recipe 匹配 tool 过滤


def test_retriever_topk_limit(tmp_path):
    r = _retriever(tmp_path)
    hits = r.retrieve("域管理员默认密码", top_k=2)
    assert 0 < len(hits) <= 2


def test_retriever_empty_db_returns_empty(tmp_path):
    r = KnowledgeRetriever(db_path=tmp_path / "none.db", json_path=tmp_path / "none.json",
                           embedder=_token_embed, backend="numpy")
    assert r.retrieve("随便什么查询") == []
    assert r.hit_count() == 0
    assert r.retrieve("") == []          # 空查询
    assert r.retrieve(None) == []        # 类型容错


def test_retriever_silent_on_corrupt_store(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("这不是 JSON {{{", encoding="utf-8")
    r = KnowledgeRetriever(db_path=tmp_path / "no.db", json_path=p,
                           embedder=_token_embed, backend="numpy")
    assert r.retrieve("SQL注入") == []   # 损坏数据 -> 静默空，不抛异常


def test_retriever_sqlite_vec_end_to_end(tmp_path, monkeypatch):
    pytest.importorskip("sqlite_vec")
    monkeypatch.setattr(B, "_embed_batch", lambda model, texts: [_token_embed(t) for t in texts])
    monkeypatch.setattr(B, "_load_model", lambda *a, **k: object())
    args = _build_args(tmp_path, "sqlite_vec")
    s = B.build(args)
    assert s["backend"] == "sqlite_vec"
    assert s["total_chunks"] > 0
    r = KnowledgeRetriever(db_path=tmp_path / "kb.db",
                           json_path=tmp_path / "none.json",
                           embedder=_token_embed, backend="auto")
    assert r.hit_count() == s["total_chunks"]
    hits = r.retrieve("SQL 注入读取文件 LOAD_FILE LFI", top_k=5)
    assert hits
    assert hits[0].source == "kali_mcp/reasoning/knowledge_graph.py"  # 攻击链 chunk
    assert all(h.score > 0 for h in hits)
