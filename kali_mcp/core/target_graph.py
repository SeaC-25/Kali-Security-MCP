#!/usr/bin/env python3
"""Target graph / blackboard for P0 autonomous harness."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from kali_mcp.core.task_workspace import TaskWorkspace, get_workspace, utc_now_iso

NODE_TYPES = {
    "host",
    "port",
    "service",
    "url",
    "tech",
    "account",
    "finding",
    "path",
}

EDGE_TYPES = {
    "exposes",
    "runs",
    "redirects_to",
    "same_origin",
    "evidence_of",
    "contains",
    "points_to",
}


def _now() -> str:
    return utc_now_iso()


def _normalize_node_value(node_type: str, value: str) -> str:
    """Normalize path/url values so trailing-slash variants share one key."""
    text = (value or "").strip()
    if not text:
        return ""
    lower = text.lower()
    if node_type in {"url", "path"} and "://" in lower:
        scheme, rest = lower.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            path = path.rstrip("/")
            return f"{scheme}://{host}" + (f"/{path}" if path else "")
        return f"{scheme}://{rest.rstrip('/')}"
    if node_type in {"url", "path"} and lower not in {"/", ""}:
        return lower.rstrip("/")
    return lower


def _node_key(node_type: str, value: str) -> str:
    return f"{node_type}:{_normalize_node_value(node_type, value)}"


@dataclass
class GraphNode:
    id: str
    type: str
    value: str
    confidence: float = 0.5
    last_seen: str = field(default_factory=_now)
    evidence_paths: List[str] = field(default_factory=list)
    next_checks: List[str] = field(default_factory=list)
    dead_reason: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    source: str = "scan"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphNode":
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            type=str(data.get("type") or "host"),
            value=str(data.get("value") or ""),
            confidence=float(data.get("confidence", 0.5)),
            last_seen=str(data.get("last_seen") or _now()),
            evidence_paths=list(data.get("evidence_paths") or []),
            next_checks=list(data.get("next_checks") or []),
            dead_reason=data.get("dead_reason"),
            meta=dict(data.get("meta") or {}),
            source=str(data.get("source") or "scan"),
        )


@dataclass
class GraphEdge:
    id: str
    type: str
    src: str
    dst: str
    confidence: float = 0.5
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphEdge":
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            type=str(data.get("type") or "points_to"),
            src=str(data.get("src") or ""),
            dst=str(data.get("dst") or ""),
            confidence=float(data.get("confidence", 0.5)),
            meta=dict(data.get("meta") or {}),
        )


class TargetGraph:
    """In-memory graph with JSON persistence."""

    def __init__(self, task_id: str):
        self.ws = get_workspace(task_id, create=True)
        self.task_id = self.ws.task_id
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self._key_index: Dict[str, str] = {}
        self.load()

    @property
    def path(self) -> Path:
        return self.ws.graph_path

    def load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.nodes = {
            n["id"]: GraphNode.from_dict(n) for n in data.get("nodes", []) if n.get("id")
        }
        self.edges = {
            e["id"]: GraphEdge.from_dict(e) for e in data.get("edges", []) if e.get("id")
        }
        self._rebuild_index()

    def save(self) -> str:
        payload = {
            "task_id": self.task_id,
            "updated_at": _now(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(self.path)

    def _rebuild_index(self) -> None:
        self._key_index = {}
        for node in self.nodes.values():
            self._key_index[_node_key(node.type, node.value)] = node.id

    def upsert_node(
        self,
        node_type: str,
        value: str,
        confidence: float = 0.5,
        evidence_path: Optional[str] = None,
        next_checks: Optional[Iterable[str]] = None,
        meta: Optional[Dict[str, Any]] = None,
        source: str = "scan",
        revive: bool = False,
    ) -> GraphNode:
        node_type = (node_type or "host").strip().lower()
        if node_type not in NODE_TYPES:
            node_type = "host"
        value = (value or "").strip()
        if not value:
            raise ValueError("node value required")
        # store canonical value for url/path so graph does not fork on trailing slash
        if node_type in {"url", "path"}:
            value = _normalize_node_value(node_type, value) or value

        key = _node_key(node_type, value)
        existing_id = self._key_index.get(key)
        if existing_id and existing_id in self.nodes:
            node = self.nodes[existing_id]
            node.confidence = max(node.confidence, float(confidence))
            node.last_seen = _now()
            if evidence_path and evidence_path not in node.evidence_paths:
                node.evidence_paths.append(evidence_path)
            if next_checks:
                for item in next_checks:
                    text = str(item).strip()
                    if text and text not in node.next_checks:
                        node.next_checks.append(text)
            if meta:
                node.meta.update(meta)
            if revive:
                node.dead_reason = None
            if source and node.source == "scan":
                node.source = source
            return node

        node = GraphNode(
            id=uuid.uuid4().hex[:12],
            type=node_type,
            value=value,
            confidence=float(confidence),
            evidence_paths=[evidence_path] if evidence_path else [],
            next_checks=[str(x).strip() for x in (next_checks or []) if str(x).strip()],
            meta=dict(meta or {}),
            source=source,
        )
        self.nodes[node.id] = node
        self._key_index[key] = node.id
        return node

    def add_edge(
        self,
        edge_type: str,
        src_id: str,
        dst_id: str,
        confidence: float = 0.5,
        meta: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        edge_type = (edge_type or "points_to").strip().lower()
        if edge_type not in EDGE_TYPES:
            edge_type = "points_to"
        for edge in self.edges.values():
            if edge.type == edge_type and edge.src == src_id and edge.dst == dst_id:
                edge.confidence = max(edge.confidence, float(confidence))
                if meta:
                    edge.meta.update(meta)
                return edge
        edge = GraphEdge(
            id=uuid.uuid4().hex[:12],
            type=edge_type,
            src=src_id,
            dst=dst_id,
            confidence=float(confidence),
            meta=dict(meta or {}),
        )
        self.edges[edge.id] = edge
        return edge

    def mark_dead(self, node_id: str, reason: str) -> Optional[GraphNode]:
        node = self.nodes.get(node_id)
        if not node:
            # allow value lookup
            for n in self.nodes.values():
                if n.value == node_id or n.id == node_id:
                    node = n
                    break
        if not node:
            return None
        node.dead_reason = reason or "dead"
        node.next_checks = []
        return node

    def query(
        self,
        node_type: Optional[str] = None,
        alive_only: bool = True,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        items = []
        for node in self.nodes.values():
            if node_type and node.type != node_type:
                continue
            if alive_only and node.dead_reason:
                continue
            items.append(node.to_dict())
            if len(items) >= limit:
                break
        return items

    def next_actions(self, limit: int = 20, include_insights: bool = False) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for node in self.nodes.values():
            if node.dead_reason:
                continue
            for check in node.next_checks:
                check_s = str(check or "")
                src = "insight" if check_s.startswith("insight") or node.source == "insight" else (node.source or "graph")
                actions.append(
                    {
                        "node_id": node.id,
                        "node_type": node.type,
                        "value": node.value,
                        "action": check,
                        "confidence": node.confidence,
                        "source": src,
                    }
                )
            # only suggest defaults for untouched nodes (no evidence / no tool history)
            if not node.next_checks and not node.evidence_paths and not node.meta.get("last_tool"):
                defaults = self._default_checks(node)
                for check in defaults:
                    actions.append(
                        {
                            "node_id": node.id,
                            "node_type": node.type,
                            "value": node.value,
                            "action": check,
                            "confidence": node.confidence,
                            "source": "default",
                        }
                    )
        if not include_insights:
            actions = [a for a in actions if a.get("source") != "insight"]
        return actions[: int(limit or 20)]

    def _default_checks(self, node: GraphNode) -> List[str]:
        if node.type == "url":
            return ["fingerprint", "shallow_dir", "nuclei_subset"]
        if node.type == "host":
            return ["http_probe"]
        if node.type == "port":
            return ["service_fingerprint"]
        if node.type == "finding" and node.meta.get("status") == "candidate":
            return ["verify_finding"]
        return []

    def ingest_parsed(
        self,
        tool_name: str,
        parsed: Dict[str, Any],
        target: str = "",
        evidence_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Best-effort map parser structured_data into graph nodes."""
        created_nodes: List[str] = []
        structured = parsed.get("structured_data") or {}
        summary = parsed.get("summary") or ""

        host = ""
        url = ""
        if target:
            if "://" in target:
                url = target
                host = urlparse(target).hostname or ""
            else:
                host = target.split(":")[0]

        host_node = None
        if host:
            host_node = self.upsert_node(
                "host",
                host,
                confidence=float(parsed.get("confidence") or 0.6),
                evidence_path=evidence_path,
                next_checks=["http_probe"] if not url else [],
                meta={"last_tool": tool_name, "summary": summary[:300]},
            )
            created_nodes.append(host_node.id)

        url_node = None
        if url:
            url_node = self.upsert_node(
                "url",
                url,
                confidence=float(parsed.get("confidence") or 0.7),
                evidence_path=evidence_path,
                next_checks=["fingerprint", "shallow_dir"],
                meta={"last_tool": tool_name},
            )
            created_nodes.append(url_node.id)
            if host_node:
                self.add_edge("exposes", host_node.id, url_node.id)

        # nmap-like ports
        ports = structured.get("ports") or structured.get("open_ports") or []
        if isinstance(ports, list) and host_node:
            for item in ports[:100]:
                if isinstance(item, dict):
                    port = str(item.get("port") or item.get("number") or "")
                    service = str(item.get("service") or item.get("name") or "")
                else:
                    port = str(item)
                    service = ""
                if not port:
                    continue
                port_node = self.upsert_node(
                    "port",
                    f"{host}:{port}",
                    confidence=0.8,
                    evidence_path=evidence_path,
                    next_checks=["service_fingerprint"],
                    meta={"port": port, "service": service},
                )
                created_nodes.append(port_node.id)
                self.add_edge("exposes", host_node.id, port_node.id)
                if service:
                    svc_node = self.upsert_node(
                        "service",
                        f"{host}:{port}/{service}",
                        confidence=0.7,
                        evidence_path=evidence_path,
                        meta={"service": service, "port": port},
                    )
                    created_nodes.append(svc_node.id)
                    self.add_edge("runs", port_node.id, svc_node.id)

        # nuclei / findings style
        findings = structured.get("findings") or structured.get("vulnerabilities") or []
        if isinstance(findings, list):
            for item in findings[:50]:
                if isinstance(item, dict):
                    title = str(item.get("name") or item.get("template") or item.get("title") or "finding")
                    severity = str(item.get("severity") or parsed.get("severity") or "info")
                else:
                    title = str(item)
                    severity = str(parsed.get("severity") or "info")
                fnode = self.upsert_node(
                    "finding",
                    title[:200],
                    confidence=float(parsed.get("confidence") or 0.5),
                    evidence_path=evidence_path,
                    next_checks=["verify_finding"],
                    meta={
                        "status": "candidate",
                        "severity": severity,
                        "source": "parser",
                        "tool": tool_name,
                        "target": target,
                    },
                    source="scan",
                )
                created_nodes.append(fnode.id)
                anchor = url_node or host_node
                if anchor:
                    self.add_edge("evidence_of", fnode.id, anchor.id)

        # paths from dir scanners
        paths = structured.get("paths") or structured.get("directories") or structured.get("urls") or []
        if isinstance(paths, list):
            base = url.rstrip("/") if url else ""
            for item in paths[:100]:
                if isinstance(item, dict):
                    path_val = str(item.get("path") or item.get("url") or "")
                else:
                    path_val = str(item)
                if not path_val:
                    continue
                full = path_val if path_val.startswith("http") else f"{base}{path_val}" if base else path_val
                pnode = self.upsert_node(
                    "path",
                    full,
                    confidence=0.6,
                    evidence_path=evidence_path,
                    next_checks=["fingerprint"],
                    meta={"from_tool": tool_name},
                )
                created_nodes.append(pnode.id)
                if url_node:
                    self.add_edge("contains", url_node.id, pnode.id)

        # tech fingerprints
        techs = structured.get("technologies") or structured.get("tech") or []
        if isinstance(techs, list):
            for tech in techs[:50]:
                name = str(tech.get("name") if isinstance(tech, dict) else tech)
                if not name:
                    continue
                tnode = self.upsert_node(
                    "tech",
                    name,
                    confidence=0.6,
                    evidence_path=evidence_path,
                    meta={"tool": tool_name},
                )
                created_nodes.append(tnode.id)
                anchor = url_node or host_node
                if anchor:
                    self.add_edge("runs", anchor.id, tnode.id)

        self.save()
        return {
            "task_id": self.task_id,
            "nodes_touched": len(set(created_nodes)),
            "node_ids": list(dict.fromkeys(created_nodes)),
            "graph_path": str(self.path),
        }

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        dead = 0
        for n in self.nodes.values():
            by_type[n.type] = by_type.get(n.type, 0) + 1
            if n.dead_reason:
                dead += 1
        return {
            "task_id": self.task_id,
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "dead_nodes": dead,
            "by_type": by_type,
            "graph_path": str(self.path),
        }


_GRAPH_CACHE: Dict[str, TargetGraph] = {}


def get_graph(task_id: str, reload: bool = False) -> TargetGraph:
    probe = TargetGraph(task_id)
    tid = probe.task_id
    if not reload and tid in _GRAPH_CACHE:
        return _GRAPH_CACHE[tid]
    _GRAPH_CACHE[tid] = probe
    return probe
