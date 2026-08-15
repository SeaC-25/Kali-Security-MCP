#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
向量化知识库检索器（ARCH_DESIGN §7.3 / P0 阶段）。

KnowledgeRetriever.retrieve(query, top_k, filters)：
    - 向量召回 top_k*3（sqlite-vec KNN；降级 numpy 余弦 + JSON）
    - BM25 关键词召回 top_k*3（rank-bm25，中英混合 tokenizer）
    - RRF 融合 -> meta 过滤 -> top_k
    - 检索失败/库为空 -> 静默返回空列表（降级安全，调用方跳过 KB 块）

索引由 scripts/build_kb_index.py 构建；读取端与构建端共享同一份 schema：
    - sqlite-vec: data/kb_vectors.db（chunks 表 + vec_chunks vec0 虚拟表）
    - numpy 降级: data/kb_vectors.json（chunks[].embedding 内嵌）
后端选择 KB_BACKEND=auto|sqlite_vec|numpy（默认 auto 自动探测）。
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "kb_vectors.db"
DEFAULT_JSON = ROOT / "data" / "kb_vectors.json"
DEFAULT_MODEL_DIR = ROOT / "data" / "models"
MODEL_ID = "BAAI/bge-small-zh-v1.5"
RRF_K = 60


@dataclass
class KbHit:
    """单条检索命中。score 为 RRF 融合分（rank 加权，非概率）。"""

    chunk_id: int
    source: str
    section: str
    text: str
    score: float
    meta: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# tokenizer / RRF（纯函数，可单测）
# --------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")


def tokenize(text: str) -> List[str]:
    """中英混合 tokenizer：ASCII 词 + CJK 单字（保证中文子串可命中）。"""
    text = (text or "").lower()
    tokens = _TOKEN_RE.findall(text)
    tokens.extend(_CJK_RE.findall(text))
    return tokens


def rrf_fuse(vector_hits: List[KbHit], bm25_hits: List[KbHit],
             k: int = RRF_K) -> List[KbHit]:
    """Reciprocal Rank Fusion：两个排名列表按 rank 加权融合、按 chunk_id 去重。"""
    scores: Dict[int, float] = {}
    by_id: Dict[int, KbHit] = {}
    for rank, hit in enumerate(vector_hits):
        scores[hit.chunk_id] = scores.get(hit.chunk_id, 0.0) + 1.0 / (k + rank + 1)
        by_id.setdefault(hit.chunk_id, hit)
    for rank, hit in enumerate(bm25_hits):
        scores[hit.chunk_id] = scores.get(hit.chunk_id, 0.0) + 1.0 / (k + rank + 1)
        by_id.setdefault(hit.chunk_id, hit)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    out = []
    for cid, sc in ranked:
        h = by_id[cid]
        out.append(KbHit(chunk_id=cid, source=h.source, section=h.section,
                         text=h.text, score=sc, meta=h.meta))
    return out


def _match_filters(hit: KbHit, filters: Dict[str, Any]) -> bool:
    """meta 子集匹配：filters 的每个 key 必须命中（值相等或包含于 meta 列表）。"""
    for key, value in filters.items():
        if key == "source":
            if hit.source != value:
                return False
            continue
        if key == "section":
            if hit.section != value:
                return False
            continue
        meta = hit.meta or {}
        if key not in meta:
            return False
        mv = meta[key]
        if isinstance(mv, (list, tuple, set)):
            if value not in mv:
                return False
        elif mv != value:
            return False
    return True


# --------------------------------------------------------------------------
# 检索器
# --------------------------------------------------------------------------


class KnowledgeRetriever:
    """向量 + BM25 混合检索；后端可切换（sqlite_vec / numpy），失败静默降级为空。

    线程模型：整条 retrieve 在专用单 worker 线程池内执行（模型加载 + embed 前向
    推理 + KNN/BM25），对外仍为同步方法、签名不变 —— 从 asyncio 事件循环线程
    同步调用时，CPU 密集/原生库交互不占用事件循环线程，避免 Windows 上偶发的
    进程级硬退出（exit code 5）。
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        json_path: Optional[Path] = None,
        model_dir: Optional[Path] = None,
        embedder: Any = None,
        backend: str = "auto",
    ):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.json_path = Path(json_path) if json_path else DEFAULT_JSON
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self._embedder = embedder          # 注入自定义 embedder（测试/替换模型用）
        self._model: Any = None            # 懒加载 sentence-transformers
        self._model_failed = False         # 加载失败缓存：避免每次 retrieve 重复尝试重载
        self._model_lock = threading.Lock()
        # 专用单 worker 线程池：整条检索（含 ST 模型加载 + embed 前向推理）都在
        # worker 线程执行，绝不占用 asyncio 事件循环线程 —— Windows 上在事件循环
        # 线程里加载 sentence-transformers 会偶发原生硬退出（exit code 5，无 traceback）。
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="kb-embed")
        self._backend = backend            # auto | sqlite_vec | numpy | none
        self._resolved: Optional[str] = None
        self._corpus: Optional[List[Dict[str, Any]]] = None
        self._bm25: Any = None
        self._bm25_tokenized: Optional[List[List[str]]] = None

    # ---------------- 后端探测与加载 ----------------

    def _resolve_backend(self) -> str:
        if self._resolved is not None:
            return self._resolved
        backend = self._backend
        if backend == "auto":
            if self._sqlite_vec_ready():
                backend = "sqlite_vec"
            elif self.json_path.exists():
                backend = "numpy"
            else:
                backend = "none"
        elif backend == "sqlite_vec" and not self._sqlite_vec_ready():
            backend = "numpy" if self.json_path.exists() else "none"
        self._resolved = backend
        return backend

    def _sqlite_vec_ready(self) -> bool:
        try:
            import sqlite_vec
            if not self.db_path.exists():
                return False
            conn = self._connect()
            try:
                conn.enable_load_extension(True)
                sqlite_vec.load(conn)
                conn.enable_load_extension(False)
                row = conn.execute("SELECT count(*) FROM vec_chunks").fetchone()
                return bool(row and row[0] > 0)
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 —— 探测失败即视为不可用
            return False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.enable_load_extension(True)
        import sqlite_vec
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        return conn

    def _load_corpus(self) -> List[Dict[str, Any]]:
        """按选中后端加载全部 chunk 元数据（id/source/section/text/meta/embedding）。"""
        if self._corpus is not None:
            return self._corpus
        backend = self._resolve_backend()
        if backend == "sqlite_vec":
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, source, section, text, meta, embedding FROM chunks").fetchall()
            finally:
                conn.close()
            corpus = []
            for cid, source, section, text, meta, blob in rows:
                try:
                    meta_obj = json.loads(meta)
                except (json.JSONDecodeError, TypeError):
                    meta_obj = {}
                rec: Dict[str, Any] = {"chunk_id": cid, "source": source,
                                       "section": section, "text": text, "meta": meta_obj}
                if blob is not None:
                    rec["embedding"] = np.frombuffer(blob, dtype=np.float32)
                corpus.append(rec)
        elif backend == "numpy" and self.json_path.exists():
            data = json.loads(self.json_path.read_text(encoding="utf-8"))
            corpus = []
            for c in data.get("chunks", []):
                emb = c.get("embedding")
                corpus.append({
                    "chunk_id": int(c.get("id", 0)),
                    "source": c.get("source", ""),
                    "section": c.get("section", ""),
                    "text": c.get("text", ""),
                    "meta": c.get("meta", {}) or {},
                    "embedding": np.asarray(emb, dtype=np.float32) if emb is not None else None,
                })
        else:
            corpus = []
        self._corpus = corpus
        return corpus

    # ---------------- embedding ----------------

    def _embed(self, text: str) -> Optional[np.ndarray]:
        if self._embedder is not None:
            vec = self._embedder(text)
            return np.asarray(vec, dtype=np.float32)
        self._ensure_model()
        if self._model is None:
            return None
        return self._model.encode(text, normalize_embeddings=True, convert_to_numpy=True)

    def _ensure_model(self) -> None:
        """惰性加载 sentence-transformers（幂等、线程安全；仅在 worker 线程内调用）。

        加载失败会缓存 _model_failed，避免后续每次 retrieve 都重复触发重载 ——
        重载会再次进入原生层（torch/tokenizers），在受限环境下可能重复触发
        偶发硬退出（exit code 5）。
        """
        if self._model is not None or self._model_failed:
            return
        with self._model_lock:
            if self._model is not None or self._model_failed:
                return
            model = self._load_model()
            if model is None:
                self._model_failed = True
            else:
                self._model = model

    def _load_model(self):
        try:
            os.environ["HF_HOME"] = str(self.model_dir)
            os.environ["HF_HUB_CACHE"] = str(self.model_dir / "hub")
            os.environ["TRANSFORMERS_CACHE"] = str(self.model_dir / "hub")
            from sentence_transformers import SentenceTransformer
            # 解析快照本地路径（在线下载/离线命中缓存），传给 ST 的必须是本地目录
            from huggingface_hub import snapshot_download
            snapshot = snapshot_download(
                MODEL_ID, cache_dir=str(self.model_dir),
                library_name="sentence-transformers",
                ignore_patterns=["*.onnx", "*.onnx_data", "*.ot", "*.h5", "*.msgpack"],
                local_files_only=True,
            )
            model = SentenceTransformer(str(snapshot), cache_folder=str(self.model_dir),
                                        device="cpu")
            model.max_seq_length = 512
            return model
        except Exception as exc:  # noqa: BLE001
            logger.warning("KB embedding 模型加载失败，检索降级为空: %s", exc)
            return None

    # ---------------- 向量召回 ----------------

    def _vector_topk(self, query_vec: np.ndarray, top_k: int) -> List[KbHit]:
        backend = self._resolve_backend()
        corpus = self._load_corpus()
        if backend == "sqlite_vec":
            try:
                return self._vector_topk_sqlite(query_vec, top_k)
            except Exception as exc:  # noqa: BLE001 —— KNN 异常时退化为 numpy 余弦
                logger.warning("sqlite-vec KNN 失败，降级 numpy 余弦: %s", exc)
        return self._vector_topk_numpy(query_vec, top_k, corpus)

    def _vector_topk_sqlite(self, query_vec: np.ndarray, top_k: int) -> List[KbHit]:
        conn = self._connect()
        try:
            q = np.asarray(query_vec, dtype=np.float32)
            blob = q.tobytes()
            conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_query USING vec0(embedding float[512])")
            conn.execute("DELETE FROM kb_query")
            conn.execute("INSERT INTO kb_query(rowid, embedding) VALUES (1, ?)", (blob,))
            rows = conn.execute(
                "SELECT rowid, distance FROM vec_chunks "
                "WHERE embedding MATCH (SELECT embedding FROM kb_query WHERE rowid = 1) "
                "ORDER BY distance LIMIT ?",
                (top_k,)).fetchall()
        finally:
            conn.close()
        corpus = self._load_corpus()
        by_id = {c["chunk_id"]: c for c in corpus}
        hits = []
        for rowid, dist in rows:
            rec = by_id.get(rowid)
            if rec is None:
                continue
            hits.append(KbHit(
                chunk_id=rowid, source=rec["source"], section=rec["section"],
                text=rec["text"], score=1.0 / (1.0 + float(dist)), meta=rec["meta"]))
        return hits

    def _vector_topk_numpy(self, query_vec: np.ndarray, top_k: int,
                           corpus: List[Dict[str, Any]]) -> List[KbHit]:
        q = np.asarray(query_vec, dtype=np.float32).reshape(-1)
        qn = q / (np.linalg.norm(q) + 1e-12)
        scored = []
        for rec in corpus:
            emb = rec.get("embedding")
            if emb is None:
                continue
            e = np.asarray(emb, dtype=np.float32).reshape(-1)
            sim = float(np.dot(e, qn) / (np.linalg.norm(e) + 1e-12))
            scored.append((sim, rec))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [
            KbHit(chunk_id=rec["chunk_id"], source=rec["source"], section=rec["section"],
                  text=rec["text"], score=sim, meta=rec["meta"])
            for sim, rec in scored[:top_k]
        ]

    # ---------------- BM25 召回 ----------------

    def _bm25_topk(self, query: str, top_k: int) -> List[KbHit]:
        corpus = self._load_corpus()
        if not corpus:
            return []
        if self._bm25 is None:
            from rank_bm25 import BM25Okapi
            tokenized = [tokenize(c["text"]) for c in corpus]
            self._bm25 = BM25Okapi(tokenized)
            self._bm25_tokenized = tokenized
        q_tokens = tokenize(query)
        if not q_tokens:
            return []
        scores = self._bm25.get_scores(q_tokens)
        order = np.argsort(scores)[::-1][:top_k]
        hits = []
        for idx in order:
            if scores[idx] <= 0.0:
                continue
            rec = corpus[int(idx)]
            hits.append(KbHit(
                chunk_id=rec["chunk_id"], source=rec["source"], section=rec["section"],
                text=rec["text"], score=float(scores[idx]), meta=rec["meta"]))
        return hits

    # ---------------- 对外接口 ----------------

    def retrieve(self, query: str, top_k: int = 5,
                 filters: Optional[Dict[str, Any]] = None) -> List[KbHit]:
        """混合检索主入口。失败/空库 -> 静默返回 []，不抛异常（降级安全）。

        整个检索体（含 sentence-transformers 模型加载与 embed 前向推理）提交到
        专用 worker 线程执行，避免在 asyncio 事件循环线程上跑 CPU 密集 + 原生库
        交互 —— Windows 上在事件循环线程里加载/推理 embedding 模型会偶发进程级
        硬退出（exit code 5，无 traceback）。对外签名不变，调用方无需改动。
        """
        return self._executor.submit(
            self._retrieve_impl, query, top_k, filters
        ).result()

    def _retrieve_impl(self, query: str, top_k: int = 5,
                       filters: Optional[Dict[str, Any]] = None) -> List[KbHit]:
        """worker 线程内的实际检索体（原 retrieve 逻辑，含降级保护）。"""
        try:
            if not query or not str(query).strip():
                return []
            if self._resolve_backend() == "none":
                return []
            q_vec = self._embed(str(query))
            if q_vec is None:
                return []
            vec_top = top_k * 3
            vector_hits = self._vector_topk(q_vec, vec_top)
            bm25_hits = self._bm25_topk(str(query), vec_top)
            fused = rrf_fuse(vector_hits, bm25_hits)
            if filters:
                fused = [h for h in fused if _match_filters(h, filters)]
            return fused[:top_k]
        except Exception as exc:  # noqa: BLE001 —— 检索失败静默降级
            logger.warning("KB retrieve 失败，返回空列表: %s", exc)
            return []

    def hit_count(self) -> int:
        """当前索引 chunk 总数（0 = 库为空/不可用）。"""
        try:
            return len(self._load_corpus())
        except Exception:  # noqa: BLE001
            return 0
