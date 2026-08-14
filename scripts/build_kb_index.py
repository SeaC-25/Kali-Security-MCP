#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构建向量化知识库索引（ARCH_DESIGN §7.2 / P0 阶段）。

用法:
    py -3 scripts/build_kb_index.py
        [--config scripts/kb_sources.yaml]
        [--db data/kb_vectors.db]
        [--model-dir data/models]
        [--force]     # 忽略 content_hash，全量重建
        [--reset]     # 先清空库再构建
        [--backend auto|sqlite_vec|numpy]   # 默认 auto：sqlite-vec 可用则用，否则降级 numpy

流程:
    1. 按 kb_sources.yaml 展开数据源文件（include/exclude glob）
    2. 按文件 content_hash 增量判断：未变文件整文件跳过（幂等）
    3. 切分：
       - markdown            按标题分节；代码块整体保留；正文 300~800 字符、相邻块重叠 50
       - yaml                整文件成块
       - playbook_docstring  仅 docstring 摘录（AST 提取，不执行代码）
       - attack_chain        AttackChain 结构化条目（AST 提取，不 import 模块）
    4. sentence-transformers 本地 embedding（模型下载到 data/models，HF_HOME 指向该目录，
       离线可跑；下载失败自动重试一次）
    5. 落盘：优先 sqlite-vec（data/kb_vectors.db，vec0 虚拟表）；Windows 上扩展加载失败时
       自动降级 numpy 余弦 + JSON 文件（data/kb_vectors.json）。读取端统一走
       kali_mcp/reasoning/knowledge_retriever.py 的 KnowledgeRetriever 接口。
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import glob as globmod
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("kb.build")

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "scripts" / "kb_sources.yaml"
DEFAULT_DB = ROOT / "data" / "kb_vectors.db"
DEFAULT_JSON = ROOT / "data" / "kb_vectors.json"
DEFAULT_MODEL_DIR = ROOT / "data" / "models"
MODEL_ID = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
EMBED_DIM = 384

# --------------------------------------------------------------------------
# 通用
# --------------------------------------------------------------------------


def hash_bytes(data: bytes) -> str:
    """文件 content_hash：sha256（未变文件整文件跳过）。"""
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    return hash_bytes(path.read_bytes())


def _mk_chunk(source: str, section: str, text: str, category: str,
              content_hash: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    m = dict(meta or {})
    m.setdefault("category", category)
    return {
        "source": source,
        "section": section,
        "text": text,
        "category": category,
        "meta": m,
        "content_hash": content_hash,
    }


# --------------------------------------------------------------------------
# 切分规则（§7.2）：Markdown 按标题分节、代码块整体保留、块 300~800 字符、相邻重叠 50
# --------------------------------------------------------------------------

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)\s*(\w*)\s*$")
_SENT_BOUNDARY = set("。！？!?；;\n")


def _find_cut(text: str, start: int, end: int, overlap: int) -> Optional[int]:
    """在 (start+overlap, end] 内找最近的段落/句子边界；无则 None（按字符硬切）。"""
    for i in range(end, start + overlap, -1):
        if text[i - 1] in _SENT_BOUNDARY:
            return i
    return None


def _text_blocks(text: str, min_size: int = 300, max_size: int = 800,
                 overlap: int = 50) -> List[str]:
    """把连续正文切成 300~800 字符的块，相邻块重叠 50 字符。

    优先在段落/句子边界切，找不到边界才字符硬切。单段短文本直接整块返回。
    """
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_size:
        return [text]
    blocks: List[str] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + max_size, n)
        if end < n:
            cut = _find_cut(text, start, end, overlap)
            if cut is None:
                cut = end
        else:
            cut = n
        piece = text[start:cut]
        if piece.strip():
            blocks.append(piece.strip())
        if cut >= n:
            break
        nxt = max(cut - overlap, start + 1)
        if nxt >= cut:
            break
        start = nxt
    return blocks


def chunk_markdown(text: str, source: str, category: str, content_hash: str,
                   min_size: int = 300, max_size: int = 800, overlap: int = 50) -> List[Dict[str, Any]]:
    """Markdown 感知切分：按标题层级分节；代码块整体保留；正文按块聚合。"""
    chunks: List[Dict[str, Any]] = []
    section_parts: List[str] = []
    text_lines: List[str] = []
    in_fence = False
    fence_lang = ""
    fence_lines: List[str] = []

    def section_path() -> str:
        return " / ".join(section_parts)

    def flush_text() -> None:
        nonlocal text_lines
        body = "\n".join(text_lines).strip()
        text_lines = []
        if not body:
            return
        for block in _text_blocks(body, min_size, max_size, overlap):
            chunks.append(_mk_chunk(source, section_path(), block, category, content_hash))

    def flush_fence() -> None:
        nonlocal fence_lines
        if not fence_lines:
            return
        code = "\n".join(fence_lines)
        section = section_path()
        if section:
            section = f"{section} [代码块:{fence_lang or 'text'}]"
        chunks.append(_mk_chunk(source, section, code, category, content_hash))
        fence_lines = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not in_fence:
            m = FENCE_RE.match(line)
            if m:
                flush_text()
                in_fence = True
                fence_lang = m.group(2)
                fence_lines = []
                continue
            h = HEADING_RE.match(line)
            if h:
                flush_text()
                level = len(h.group(1))
                title = h.group(2).strip()
                section_parts = section_parts[: level - 1] + [title]
                continue
            text_lines.append(raw)
        else:
            if FENCE_RE.match(line):
                flush_fence()
                in_fence = False
                fence_lang = ""
            else:
                fence_lines.append(raw)

    flush_text()
    flush_fence()
    return chunks


def chunk_yaml(text: str, source: str, category: str, content_hash: str) -> List[Dict[str, Any]]:
    """YAML 工具配方：文件很小，整文件成块；提取 tool/id 作为过滤元数据。"""
    m = re.search(r"^(?:tool|id)\s*:\s*(\S+)", text, re.MULTILINE)
    meta = {"tool": m.group(1)} if m else {}
    return [_mk_chunk(source, source, text.strip(), category, content_hash, meta)]


def chunk_playbook_docstrings(code: str, source: str, category: str,
                              content_hash: str) -> List[Dict[str, Any]]:
    """playbook 仅 docstring 摘录：模块 + 函数 docstring（AST 提取，不执行代码）。"""
    chunks: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        logger.warning("  ! %s AST 解析失败（%s），跳过", source, exc)
        return chunks
    tool = Path(source).stem
    doc = ast.get_docstring(tree) or ""
    if doc.strip():
        chunks.append(_mk_chunk(source, tool, doc.strip(), category, content_hash,
                                {"tool": tool}))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            d = ast.get_docstring(node) or ""
            if d.strip():
                chunks.append(_mk_chunk(source, f"{tool}::{node.name}", d.strip(),
                                        category, content_hash, {"tool": tool}))
    return chunks


def extract_attack_chains(path: Path) -> List[Dict[str, Any]]:
    """从 knowledge_graph.py AST 提取 AttackChain(...) 调用（不 import 模块）。

    覆盖两种写法：直接字面量参数，以及 for 循环遍历字面量元组列表构造的
    AttackChain（如 sql_extra_chains 模式，10 条）。循环变量按元组逐项解析。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))

    def _ev(node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [_ev(e) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(_ev(e) for e in node.elts)
        if isinstance(node, ast.Attribute):  # VulnerabilityType.X -> "X"
            return node.attr
        if isinstance(node, ast.Name) and node.id in ("True", "False", "None"):
            return {"True": True, "False": False, "None": None}[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
                and isinstance(node.operand, ast.Constant):
            return -node.operand.value
        return None

    def _loop_env(node: ast.AST) -> Optional[Dict[str, List[Any]]]:
        """最近的 for 循环（遍历字面量元组列表，或赋值给该名字的列表）
        -> {循环变量: 各元组对应值}。"""
        parent_map = {}
        for n in ast.walk(tree):
            for child in ast.iter_child_nodes(n):
                parent_map[id(child)] = n
        assigns: Dict[str, ast.List] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name) \
                    and isinstance(n.value, ast.List):
                assigns[n.targets[0].id] = n.value

        def _tuples_of(iter_node: ast.AST) -> Optional[List[List[Any]]]:
            node = iter_node
            if isinstance(node, ast.Name):
                node = assigns.get(node.id)
            if not isinstance(node, ast.List):
                return None
            tuples = []
            for elt in node.elts:
                if isinstance(elt, ast.Tuple):
                    vals = [_ev(e) for e in elt.elts]
                    if any(v is None for v in vals):
                        return None
                    tuples.append(vals)
            return tuples or None

        cur = node
        while True:
            nxt = parent_map.get(id(cur))
            if nxt is None:
                return None
            if isinstance(nxt, ast.For) and isinstance(nxt.target, ast.Tuple):
                names = [t.id for t in nxt.target.elts if isinstance(t, ast.Name)]
                tuples = _tuples_of(nxt.iter)
                if tuples and all(len(t) == len(names) for t in tuples):
                    return {name: [t[i] for t in tuples]
                            for i, name in enumerate(names)}
            cur = nxt

    def _resolve(node: ast.AST, env: Optional[Dict[str, List[Any]]],
                 seen: set) -> Optional[List[Any]]:
        """返回候选值列表（循环变量为每迭代一个候选；常量/字面量为单元素列表）。"""
        if id(node) in seen:
            return None
        seen.add(id(node))
        if isinstance(node, ast.Constant):
            return [node.value]
        if isinstance(node, ast.Attribute):
            return [node.attr]
        if isinstance(node, ast.Name):
            if node.id in ("True", "False", "None"):
                return [{"True": True, "False": False, "None": None}[node.id]]
            if env and node.id in env:
                return env[node.id]
            return None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
                and isinstance(node.operand, ast.Constant):
            return [-node.operand.value]
        if isinstance(node, ast.List):
            items = [_resolve(e, env, seen) for e in node.elts]
            if any(v is None or len(v) != 1 for v in items):
                return None
            return [list(v[0] for v in items)]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "VulnerabilityType" and len(node.args) == 1:
            return _resolve(node.args[0], env, seen)
        return None

    chains: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "AttackChain":
            env = _loop_env(node)
            resolved: List[Tuple[str, List[Any]]] = []
            for k in node.keywords:
                if not k.arg:
                    continue
                vals = _resolve(k.value, env, set())
                if vals is None:
                    resolved = []
                    break
                resolved.append((k.arg, vals))
            if not resolved:
                continue
            count = max(len(v) for _, v in resolved)
            for i in range(count):
                chain = {}
                for name, vals in resolved:
                    chain[name] = vals[i] if len(vals) > 1 else vals[0]
                if chain.get("reasoning"):
                    chains.append(chain)
    return chains


def chunk_attack_chains(chains: List[Dict[str, Any]], source: str, category: str,
                        content_hash: str) -> List[Dict[str, Any]]:
    """AttackChain 结构化条目 -> 检索 chunk。"""
    out: List[Dict[str, Any]] = []
    for i, c in enumerate(chains):
        from_v = c.get("from_vuln") or c.get("from", "?")
        to_v = c.get("to_vuln") or c.get("to", "?")
        tools = c.get("tools") or []
        conds = c.get("conditions") or []
        text = (
            f"攻击链：{from_v} -> {to_v}\n"
            f"推理：{c.get('reasoning', '')}\n"
            f"成功概率：{c.get('success_prob', '')}  时间成本：{c.get('time_cost', '')}s\n"
            f"工具：{', '.join(str(t) for t in tools)}\n"
            f"前置条件：{', '.join(str(x) for x in conds)}"
        )
        meta = {"from_vuln": from_v, "to_vuln": to_v,
                "tools": tools, "conditions": conds}
        out.append(_mk_chunk(source, f"chain::{from_v} -> {to_v}",
                             text, category, content_hash, meta))
    return out


# --------------------------------------------------------------------------
# 数据源展开
# --------------------------------------------------------------------------


def expand_globs(patterns: Iterable[str], excludes: Iterable[str], root: Path) -> List[Path]:
    files: List[Path] = []
    for pat in patterns:
        for p in sorted(globmod.glob(str(root / pat), recursive=True)):
            path = Path(p)
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, ex) for ex in excludes):
                continue
            files.append(path)
    return sorted(set(files))


def load_config(path: Path) -> List[Dict[str, Any]]:
    import yaml  # 延迟导入：模块本身可被测试无 yaml 依赖地加载
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    sources = data.get("sources", []) if isinstance(data, dict) else []
    out = []
    for s in sources:
        if not isinstance(s, dict) or not s.get("include"):
            continue
        out.append({
            "name": s.get("name", ",".join(s["include"])),
            "include": list(s.get("include", [])),
            "exclude": list(s.get("exclude", [])),
            "parser": s.get("parser", "markdown"),
            "category": s.get("category", ""),
            "extract": s.get("extract"),
            "description": s.get("description", ""),
        })
    return out


# --------------------------------------------------------------------------
# 模型与 embedding
# --------------------------------------------------------------------------


def _load_model(model_dir: Path, model_id: str = MODEL_ID):
    """加载本地 sentence-transformers 模型（下载到 model_dir，HF_HOME 指向该目录）。

    下载/加载失败自动重试一次后抛出清晰错误。
    """
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    os.environ["HF_HOME"] = str(model_dir)
    os.environ["HF_HUB_CACHE"] = str(model_dir / "hub")
    os.environ["TRANSFORMERS_CACHE"] = str(model_dir / "hub")
    from sentence_transformers import SentenceTransformer

    last_exc: Optional[Exception] = None
    for attempt in (1, 2):
        try:
            # 先解析快照本地路径：在线则下载到 model_dir；离线（HF_HUB_OFFLINE）则
            # 命中缓存。把本地路径交给 SentenceTransformer，避免其内部以 repo id
            # 走 transformers 离线解析（该路径在 ST 5.x + Windows 上会 os.listdir 失败）。
            from huggingface_hub import snapshot_download
            snapshot = snapshot_download(
                model_id, cache_dir=str(model_dir),
                library_name="sentence-transformers",
                ignore_patterns=["*.onnx", "*.onnx_data", "*.ot", "*.h5", "*.msgpack"],
            )
            model = SentenceTransformer(str(snapshot), cache_folder=str(model_dir), device="cpu")
            # 默认 max_seq_length=128 会截断 800 字符块，提高到模型支持上限
            model.max_seq_length = 512
            logger.info("embedding 模型就绪: %s (dim=%d, max_seq=%d)",
                        model_id, model.get_sentence_embedding_dimension(), model.max_seq_length)
            return model
        except Exception as exc:  # noqa: BLE001 —— 网络/权重损坏都重试
            last_exc = exc
            logger.warning("  ! 模型加载失败(第%d次): %s", attempt, exc)
            if attempt == 1:
                time.sleep(5)
    raise RuntimeError(
        f"embedding 模型加载失败（已重试 2 次）: {model_id} -> {model_dir}\n"
        f"最后一次错误: {last_exc}\n"
        f"请检查网络（首次需联网下载权重）或 data/models 缓存完整性。"
    )


def _embed_batch(model, texts: List[str]) -> List[List[float]]:
    if not texts:
        return []
    vecs = model.encode(texts, batch_size=32, show_progress_bar=False,
                        normalize_embeddings=True, convert_to_numpy=True)
    return [v.tolist() for v in vecs]


# --------------------------------------------------------------------------
# 落盘：sqlite-vec 优先，numpy+JSON 降级
# --------------------------------------------------------------------------


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS chunks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            section TEXT NOT NULL DEFAULT '',
            text TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            meta TEXT NOT NULL DEFAULT '{}',
            content_hash TEXT NOT NULL,
            embedding BLOB
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(content_hash)")


def sqlite_vec_available(db_path: Path) -> bool:
    """探测 sqlite-vec 扩展是否可加载（Windows wheel 偶发加载失败）。"""
    try:
        import sqlite_vec
        conn = _connect(db_path)
        try:
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            return True
        except Exception:  # noqa: BLE001
            return False
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return False


def _ensure_vec_table(conn: sqlite3.Connection, dim: int = EMBED_DIM) -> None:
    conn.execute(f"CREATE VIRTUAL TABLE IF NOT EXISTS vec_chunks USING vec0(embedding float[{dim}])")


def _load_existing_sqlite(db_path: Path) -> Dict[str, Any]:
    """读回现有 chunk 行（按 source 分组），返回 {records, embeddings, max_id}。"""
    if not db_path.exists():
        return {"records": {}, "embeddings": {}, "max_id": 0}
    conn = _connect(db_path)
    try:
        _init_schema(conn)
        records: Dict[str, List[Dict[str, Any]]] = {}
        embeddings: Dict[str, List[List[float]]] = {}
        max_id = 0
        for row in conn.execute(
                "SELECT id, source, section, text, category, meta, content_hash, embedding FROM chunks"):
            cid, src, section, text, category, meta, chash, blob = row
            try:
                meta_obj = json.loads(meta)
            except json.JSONDecodeError:
                meta_obj = {}
            records.setdefault(src, []).append({
                "id": cid, "source": src, "section": section, "text": text,
                "category": category, "meta": meta_obj, "content_hash": chash,
            })
            if blob is not None:
                import numpy as np
                embeddings.setdefault(src, []).append(
                    np.frombuffer(blob, dtype=np.float32).tolist())
            max_id = max(max_id, cid)
        return {"records": records, "embeddings": embeddings, "max_id": max_id}
    finally:
        conn.close()


def write_sqlite(db_path: Path, records: Dict[str, List[Dict[str, Any]]],
                 embeddings: Dict[str, List[List[float]]]) -> int:
    """全量重写 sqlite（含 vec0）。返回总 chunk 数。"""
    conn = _connect(db_path)
    try:
        conn.enable_load_extension(True)
        import sqlite_vec
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        _init_schema(conn)
        _ensure_vec_table(conn, EMBED_DIM)
        conn.execute("DELETE FROM chunks")
        conn.execute("DELETE FROM vec_chunks")
        total = 0
        next_id = 1
        for src in sorted(records):
            embs = embeddings.get(src, [])
            for i, chunk in enumerate(records[src]):
                text = chunk["text"]
                emb = embs[i] if i < len(embs) else None
                blob = None
                if emb is not None:
                    import numpy as np
                    blob = np.asarray(emb, dtype=np.float32).tobytes()
                conn.execute(
                    "INSERT INTO chunks(id, source, section, text, category, meta, content_hash, embedding)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (next_id, chunk["source"], chunk["section"], text, chunk["category"],
                     json.dumps(chunk["meta"], ensure_ascii=False), chunk["content_hash"], blob))
                if blob is not None:
                    conn.execute("INSERT INTO vec_chunks(rowid, embedding) VALUES (?, ?)",
                                 (next_id, blob))
                next_id += 1
                total += 1
        conn.commit()
        return total
    finally:
        conn.close()


def write_json(json_path: Path, records: Dict[str, List[Dict[str, Any]]],
               embeddings: Dict[str, List[List[float]]]) -> int:
    """numpy 降级落盘：JSON 文件，每 chunk 内嵌 embedding 列表。返回总 chunk 数。"""
    flat = []
    next_id = 1
    for src in sorted(records):
        embs = embeddings.get(src, [])
        for i, chunk in enumerate(records[src]):
            rec = dict(chunk)
            rec["id"] = next_id
            emb = embs[i] if i < len(embs) else None
            if emb is not None:
                rec["embedding"] = emb
            flat.append(rec)
            next_id += 1
    payload = {
        "backend": "numpy",
        "version": 1,
        "embedding_dim": EMBED_DIM,
        "model": MODEL_ID,
        "chunks": flat,
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return len(flat)


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------


def build(args: argparse.Namespace) -> Dict[str, Any]:
    config_path = Path(args.config)
    if not config_path.exists():
        raise SystemExit(f"配置文件不存在: {config_path}")
    sources = load_config(config_path)
    if not sources:
        raise SystemExit(f"配置中没有有效数据源: {config_path}")

    db_path = Path(args.db)
    json_path = Path(args.json)
    model_dir = Path(args.model_dir)

    if args.reset:
        for p in (db_path, json_path):
            if p.exists():
                p.unlink()

    # 后端选择：auto -> sqlite-vec 可用则用，否则 numpy
    backend = args.backend
    if backend == "auto":
        backend = "sqlite_vec" if sqlite_vec_available(db_path) else "numpy"
    logger.info("向量后端: %s", backend)

    # 记录按 source 分组；embedding 仅对变更文件计算
    existing_data = _load_existing_sqlite(db_path) if backend == "sqlite_vec" \
        else _load_existing_json(json_path)
    records = existing_data["records"]
    embeddings = existing_data["embeddings"]
    next_id = existing_data["max_id"] + 1

    model = None
    changed_files = 0
    skipped_files = 0
    seen_sources: set = set()
    errors: List[str] = []

    for entry in sources:
        files = expand_globs(entry["include"], entry["exclude"], ROOT)
        parser = entry["parser"]
        category = entry["category"]
        for fpath in files:
            rel = fpath.relative_to(ROOT).as_posix()
            seen_sources.add(rel)
            try:
                fhash = hash_file(fpath)
            except OSError as exc:
                errors.append(f"{rel}: 读取失败 {exc}")
                continue

            existing = records.get(rel, [])
            if not args.force and any(c.get("content_hash") == fhash for c in existing):
                skipped_files += 1
                continue

            raw = fpath.read_text(encoding="utf-8")
            if parser == "markdown":
                chunks = chunk_markdown(raw, rel, category, fhash)
            elif parser == "yaml":
                chunks = chunk_yaml(raw, rel, category, fhash)
            elif parser == "playbook_docstring":
                chunks = chunk_playbook_docstrings(raw, rel, category, fhash)
            elif parser == "attack_chain":
                chains = extract_attack_chains(fpath)
                chunks = chunk_attack_chains(chains, rel, category, fhash)
            else:
                errors.append(f"{rel}: 未知 parser '{parser}'")
                continue

            for c in chunks:
                c["id"] = next_id
                next_id += 1
            records[rel] = chunks
            changed_files += 1

            if model is None:
                model = _load_model(model_dir)
            embeddings[rel] = _embed_batch(model, [c["text"] for c in chunks])
            logger.info("  [变更] %s  -> %d chunk", rel, len(chunks))

    # 清理：配置/glob 已不存在的源（含已删除文件）
    for src in [s for s in records if s not in seen_sources]:
        del records[src]
        embeddings.pop(src, None)

    # 保留的跳过源若缺少 embedding（旧库无 blob / json 无向量），补算一次
    if any(records.values()) and any(
            len(embeddings.get(src, [])) != len(chunks)
            for src, chunks in records.items()):
        if model is None:
            model = _load_model(model_dir)
        for src, chunks in records.items():
            if len(embeddings.get(src, [])) != len(chunks):
                embeddings[src] = _embed_batch(model, [c["text"] for c in chunks])

    if backend == "sqlite_vec":
        total = write_sqlite(db_path, records, embeddings)
    else:
        total = write_json(json_path, records, embeddings)

    summary = {
        "backend": backend,
        "config": str(config_path),
        "db": str(db_path),
        "json": str(json_path),
        "model_dir": str(model_dir),
        "files_changed": changed_files,
        "files_skipped": skipped_files,
        "total_chunks": total,
        "errors": errors,
    }
    return summary


def _load_existing_json(json_path: Path) -> Dict[str, Any]:
    if not json_path.exists():
        return {"records": {}, "embeddings": {}, "max_id": 0}
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        records: Dict[str, List[Dict[str, Any]]] = {}
        embeddings: Dict[str, List[List[float]]] = {}
        max_id = 0
        for c in data.get("chunks", []):
            rec = {k: c.get(k) for k in
                   ("source", "section", "text", "category", "meta", "content_hash")}
            records.setdefault(c["source"], []).append(rec)
            emb = c.get("embedding")
            if emb is not None:
                embeddings.setdefault(c["source"], []).append(emb)
            max_id = max(max_id, int(c.get("id", 0)))
        return {"records": records, "embeddings": embeddings, "max_id": max_id}
    except (json.JSONDecodeError, KeyError):
        return {"records": {}, "embeddings": {}, "max_id": 0}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="构建向量化知识库索引（P0）")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--json", default=str(DEFAULT_JSON))
    parser.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR))
    parser.add_argument("--force", action="store_true", help="忽略 content_hash 全量重建")
    parser.add_argument("--reset", action="store_true", help="先清空索引再构建")
    parser.add_argument("--backend", choices=["auto", "sqlite_vec", "numpy"], default="auto")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    os.chdir(ROOT)  # glob 相对仓库根
    summary = build(args)

    print("\n===== KB 索引构建完成 =====")
    print(f"后端          : {summary['backend']}")
    print(f"配置文件      : {summary['config']}")
    print(f"入库文件      : {summary['files_changed']} 个（变更/新增）")
    print(f"跳过未变文件  : {summary['files_skipped']} 个（content_hash 命中）")
    print(f"chunk 总数    : {summary['total_chunks']}")
    if summary["errors"]:
        print("告警:")
        for e in summary["errors"]:
            print(f"  - {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
