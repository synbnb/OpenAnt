"""Traceable source evidence and graph storage for the OpenHarmony locator.

The locator must be able to explain *why* a path was selected without turning
an LLM's prose into a fact.  This module therefore stores small, bounded source
fragments and makes graph edges refer only to evidence IDs that are already in
the store.  It is deliberately deterministic and has no network or model
dependency; OpenGrok responses are converted through the two convenience
methods at the bottom of :class:`EvidenceStore`.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping

from .opengrok_client import SearchHit, SearchResponse, SourceDocument, normalize_source_path


_SCHEMA_VERSION = "openant.source-locator.evidence-graph.v1"
_MAX_EXCERPT_CHARS = 4096
_MAX_KIND_LENGTH = 64
_MAX_TOKEN_LENGTH = 256
_MAX_TOOL_LENGTH = 128
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
_EDGE_CONFIDENCE_ORDER = {"weak": 0, "low": 0, "moderate": 1, "medium": 1, "strong": 2, "high": 2}


class EvidenceStoreError(ValueError):
    """Raised when evidence or graph input violates the storage contract."""


class EvidenceValidationError(EvidenceStoreError):
    """Raised when a single evidence item is malformed or unsafe."""


class EvidenceGraphError(EvidenceStoreError):
    """Raised when a graph edge would contain an invalid reference."""


def _bounded_text(value: str, *, name: str, limit: int, keep_markup: bool = True) -> str:
    """Normalize untrusted text while retaining source line structure.

    Newlines and tabs are useful when reading source.  Other ASCII controls
    are replaced with a space so a captured terminal escape or NUL cannot
    reach a report or prompt.  The limit is applied after normalization.
    """

    if not isinstance(value, str):
        raise EvidenceValidationError(f"{name} 必须是字符串")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    characters: list[str] = []
    for character in normalized:
        codepoint = ord(character)
        if character in {"\n", "\t"} or (codepoint >= 0x20 and codepoint != 0x7F):
            characters.append(character)
        else:
            characters.append(" ")
    # ``keep_markup`` is an explicit marker for callers.  Raw excerpts keep
    # OpenGrok markup for audit, while cleaned excerpts are supplied by the
    # SearchHit contract and are not rewritten here.
    del keep_markup
    return "".join(characters)[:limit]


def _bounded_token(value: str, *, name: str, limit: int = _MAX_TOKEN_LENGTH) -> str:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{name} 必须是字符串")
    normalized = _bounded_text(value.strip(), name=name, limit=limit)
    if not normalized:
        raise EvidenceValidationError(f"{name} 不能为空")
    if "\n" in normalized or "\t" in normalized:
        raise EvidenceValidationError(f"{name} 不能包含换行或制表符")
    return normalized


def _optional_token(value: str | None, *, name: str, limit: int = _MAX_TOKEN_LENGTH) -> str | None:
    if value is None:
        return None
    return _bounded_token(value, name=name, limit=limit)


def _content_sha256(content: str | bytes) -> str:
    if isinstance(content, str):
        raw = content.encode("utf-8", "replace")
    elif isinstance(content, bytes):
        raw = content
    else:
        raise EvidenceValidationError("content 必须是字符串或字节串")
    return hashlib.sha256(raw).hexdigest()


def _validate_hash(value: str, *, name: str = "content_sha256") -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value.lower()):
        raise EvidenceValidationError(f"{name} 必须是 64 位小写 SHA-256 十六进制字符串")
    return value.lower()


def _validate_line(value: int, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EvidenceValidationError(f"{name} 必须是正整数")
    return value


def _normalize_evidence_path(value: str) -> str:
    try:
        return normalize_source_path(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceValidationError(f"source_path 无效: {exc}") from exc


def _normalize_kind(value: str) -> str:
    kind = _bounded_token(value, name="kind", limit=_MAX_KIND_LENGTH).lower()
    if not _KIND_RE.fullmatch(kind):
        raise EvidenceValidationError(
            "kind 只能包含小写字母、数字、下划线、点、冒号或连字符"
        )
    return kind


def _stable_id(prefix: str, parts: Iterable[str]) -> str:
    canonical = "\x1f".join(parts).encode("utf-8", "replace")
    return f"{prefix}-{hashlib.sha256(canonical).hexdigest()[:16]}"


@dataclass(frozen=True)
class Evidence:
    """One bounded, source-backed fact.

    ``excerpt`` is the cleaned fragment used by downstream reasoning;
    ``raw_excerpt`` retains a bounded representation of the upstream fragment
    (including OpenGrok markup when present).  Neither field is trusted as
    executable content.  ``content_sha256`` hashes the complete source
    document when one was available, or the raw fragment as a fallback.
    """

    evidence_id: str
    kind: str
    source_path: str
    line_start: int
    line_end: int
    symbol: str | None
    excerpt: str
    raw_excerpt: str
    tool_name: str
    source_mode: str
    content_sha256: str
    query_id: str | None = None
    source_endpoint: str | None = None
    relation_from: str | None = None
    relation_to: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.startswith("E-"):
            raise EvidenceValidationError("evidence_id 必须以 E- 开头")
        object.__setattr__(self, "kind", _normalize_kind(self.kind))
        object.__setattr__(self, "source_path", _normalize_evidence_path(self.source_path))
        start = _validate_line(self.line_start, name="line_start")
        end = _validate_line(self.line_end, name="line_end")
        if end < start:
            raise EvidenceValidationError("line_end 不能小于 line_start")
        object.__setattr__(self, "line_start", start)
        object.__setattr__(self, "line_end", end)
        object.__setattr__(self, "symbol", _optional_token(self.symbol, name="symbol"))
        object.__setattr__(
            self,
            "excerpt",
            _bounded_text(self.excerpt, name="excerpt", limit=_MAX_EXCERPT_CHARS),
        )
        object.__setattr__(
            self,
            "raw_excerpt",
            _bounded_text(self.raw_excerpt, name="raw_excerpt", limit=_MAX_EXCERPT_CHARS),
        )
        object.__setattr__(
            self,
            "tool_name",
            _bounded_token(self.tool_name, name="tool_name", limit=_MAX_TOOL_LENGTH),
        )
        object.__setattr__(
            self,
            "source_mode",
            _bounded_token(self.source_mode or "unknown", name="source_mode", limit=64),
        )
        object.__setattr__(self, "content_sha256", _validate_hash(self.content_sha256))
        object.__setattr__(self, "query_id", _optional_token(self.query_id, name="query_id"))
        object.__setattr__(
            self,
            "source_endpoint",
            _optional_token(self.source_endpoint, name="source_endpoint", limit=_MAX_TOOL_LENGTH),
        )
        object.__setattr__(
            self,
            "relation_from",
            _optional_token(self.relation_from, name="relation_from"),
        )
        object.__setattr__(self, "relation_to", _optional_token(self.relation_to, name="relation_to"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "source_path": self.source_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "symbol": self.symbol,
            "excerpt": self.excerpt,
            "raw_excerpt": self.raw_excerpt,
            "tool_name": self.tool_name,
            "source_mode": self.source_mode,
            "content_sha256": self.content_sha256,
            "query_id": self.query_id,
            "source_endpoint": self.source_endpoint,
            "relation_from": self.relation_from,
            "relation_to": self.relation_to,
        }


@dataclass(frozen=True)
class EvidenceEdge:
    """A graph relation that can only be created with evidence IDs."""

    edge_id: str
    src: str
    relation: str
    dst: str
    evidence_ids: tuple[str, ...]
    confidence: str = "weak"

    def __post_init__(self) -> None:
        if not isinstance(self.edge_id, str) or not self.edge_id.startswith("G-"):
            raise EvidenceGraphError("edge_id 必须以 G- 开头")
        object.__setattr__(self, "src", _bounded_token(self.src, name="src"))
        object.__setattr__(self, "relation", _bounded_token(self.relation, name="relation"))
        object.__setattr__(self, "dst", _bounded_token(self.dst, name="dst"))
        if isinstance(self.evidence_ids, (str, bytes)):
            raise EvidenceGraphError("evidence_ids 必须是非空 ID 序列")
        ids = tuple(self.evidence_ids)
        if not ids or any(not isinstance(item, str) or not item.startswith("E-") for item in ids):
            raise EvidenceGraphError("evidence_ids 必须只包含 E- 开头的 ID")
        if len(set(ids)) != len(ids):
            raise EvidenceGraphError("同一条边不能重复引用同一个 evidence_id")
        object.__setattr__(self, "evidence_ids", ids)
        confidence = _bounded_token(self.confidence, name="confidence", limit=32).lower()
        if confidence not in _EDGE_CONFIDENCE_ORDER:
            raise EvidenceGraphError("confidence 必须是 weak/moderate/strong（或兼容别名）")
        object.__setattr__(self, "confidence", confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src": self.src,
            "relation": self.relation,
            "dst": self.dst,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
        }


class EvidenceStore:
    """In-memory, serializable evidence registry and relation index."""

    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._evidence_index: dict[tuple[str, str, int, int, str], str] = {}
        self._duplicate_counts: dict[str, int] = {}
        self._edges: dict[str, EvidenceEdge] = {}
        self._edge_index: dict[tuple[str, str, str], str] = {}
        self._graph: EvidenceGraph | None = None

    @property
    def graph(self) -> "EvidenceGraph":
        if self._graph is None:
            self._graph = EvidenceGraph(self)
        return self._graph

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return tuple(self._evidence.values())

    @property
    def edges(self) -> tuple[EvidenceEdge, ...]:
        return tuple(self._edges.values())

    def _identity(
        self,
        *,
        kind: str,
        source_path: str,
        line_start: int,
        line_end: int,
        symbol: str | None,
    ) -> tuple[str, str, int, int, str]:
        return (kind, normalize_source_path(source_path), line_start, line_end, symbol or "")

    def add_evidence(
        self,
        *,
        kind: str,
        source_path: str,
        line_start: int,
        line_end: int | None = None,
        symbol: str | None = None,
        excerpt: str = "",
        raw_excerpt: str | None = None,
        tool_name: str,
        source_mode: str = "unknown",
        query_id: str | None = None,
        content: str | bytes | None = None,
        content_sha256: str | None = None,
        source_endpoint: str | None = None,
        relation_from: str | None = None,
        relation_to: str | None = None,
    ) -> Evidence:
        """Register one item and return the canonical object.

        The identity intentionally excludes excerpt, tool and query metadata:
        repeated searches of the same source line should not inflate evidence
        or confidence.  The first observation remains canonical, while the
        duplicate count is retained for audit display.
        """

        normalized_kind = _normalize_kind(kind)
        normalized_path = _normalize_evidence_path(source_path)
        start = _validate_line(line_start, name="line_start")
        end = start if line_end is None else _validate_line(line_end, name="line_end")
        if end < start:
            raise EvidenceValidationError("line_end 不能小于 line_start")
        normalized_symbol = _optional_token(symbol, name="symbol")
        identity = (normalized_kind, normalized_path, start, end, normalized_symbol or "")
        raw_value = excerpt if raw_excerpt is None else raw_excerpt
        if not isinstance(raw_value, str):
            raise EvidenceValidationError("raw_excerpt 必须是字符串")
        if content is not None:
            calculated_hash = _content_sha256(content)
        else:
            calculated_hash = _content_sha256(raw_value)
        if content_sha256 is None:
            final_hash = calculated_hash
        else:
            final_hash = _validate_hash(content_sha256)
            if final_hash != calculated_hash:
                raise EvidenceValidationError("content_sha256 与 content/raw_excerpt 不匹配")

        existing_id = self._evidence_index.get(identity)
        if existing_id is not None:
            self._duplicate_counts[existing_id] = self._duplicate_counts.get(existing_id, 0) + 1
            return self._evidence[existing_id]

        evidence_id = _stable_id(
            "E",
            [normalized_kind, normalized_path, str(start), str(end), normalized_symbol or ""],
        )
        evidence = Evidence(
            evidence_id=evidence_id,
            kind=normalized_kind,
            source_path=normalized_path,
            line_start=start,
            line_end=end,
            symbol=normalized_symbol,
            excerpt=excerpt,
            raw_excerpt=raw_value,
            tool_name=tool_name,
            source_mode=source_mode,
            content_sha256=final_hash,
            query_id=query_id,
            source_endpoint=source_endpoint,
            relation_from=relation_from,
            relation_to=relation_to,
        )
        self._evidence[evidence_id] = evidence
        self._evidence_index[identity] = evidence_id
        self._duplicate_counts[evidence_id] = 0
        return evidence

    def duplicate_count(self, evidence_id: str) -> int:
        if evidence_id not in self._evidence:
            raise EvidenceStoreError(f"未知 evidence_id: {evidence_id}")
        return self._duplicate_counts.get(evidence_id, 0)

    def get_evidence(self, evidence_id: str) -> Evidence:
        try:
            return self._evidence[evidence_id]
        except KeyError as exc:
            raise EvidenceGraphError(f"不存在的 evidence_id: {evidence_id}") from exc

    def add_edge(
        self,
        *,
        src: str,
        relation: str,
        dst: str,
        evidence_ids: Iterable[str],
        confidence: str = "weak",
    ) -> EvidenceEdge:
        """Create or enrich an edge, rejecting every dangling reference."""

        if isinstance(evidence_ids, (str, bytes)):
            raise EvidenceGraphError("evidence_ids 必须是 ID 序列")
        ids = tuple(dict.fromkeys(evidence_ids))
        if not ids:
            raise EvidenceGraphError("图边至少需要一个 evidence_id")
        for evidence_id in ids:
            if evidence_id not in self._evidence:
                raise EvidenceGraphError(f"图边引用了不存在的 evidence_id: {evidence_id}")
        normalized_src = _bounded_token(src, name="src")
        normalized_relation = _bounded_token(relation, name="relation")
        normalized_dst = _bounded_token(dst, name="dst")
        key = (normalized_src, normalized_relation, normalized_dst)
        existing_id = self._edge_index.get(key)
        if existing_id is not None:
            existing = self._edges[existing_id]
            merged_ids = tuple(dict.fromkeys((*existing.evidence_ids, *ids)))
            merged_confidence = self._stronger_confidence(existing.confidence, confidence)
            if merged_ids == existing.evidence_ids and merged_confidence == existing.confidence:
                return existing
            updated = EvidenceEdge(
                edge_id=existing.edge_id,
                src=existing.src,
                relation=existing.relation,
                dst=existing.dst,
                evidence_ids=merged_ids,
                confidence=merged_confidence,
            )
            self._edges[existing_id] = updated
            return updated

        edge_id = _stable_id("G", [normalized_src, normalized_relation, normalized_dst])
        edge = EvidenceEdge(
            edge_id=edge_id,
            src=normalized_src,
            relation=normalized_relation,
            dst=normalized_dst,
            evidence_ids=ids,
            confidence=confidence,
        )
        self._edges[edge_id] = edge
        self._edge_index[key] = edge_id
        return edge

    @staticmethod
    def _stronger_confidence(left: str, right: str) -> str:
        normalized_right = _bounded_token(right, name="confidence", limit=32).lower()
        if normalized_right not in _EDGE_CONFIDENCE_ORDER:
            raise EvidenceGraphError("confidence 值无效")
        return left if _EDGE_CONFIDENCE_ORDER[left] >= _EDGE_CONFIDENCE_ORDER[normalized_right] else normalized_right

    def get_edge(self, edge_id: str) -> EvidenceEdge:
        try:
            return self._edges[edge_id]
        except KeyError as exc:
            raise EvidenceGraphError(f"不存在的 edge_id: {edge_id}") from exc

    def evidence_for_edge(self, edge_id: str) -> tuple[Evidence, ...]:
        edge = self.get_edge(edge_id)
        return tuple(self.get_evidence(item) for item in edge.evidence_ids)

    def evidence_for(self, node_or_candidate: Any) -> tuple[Evidence, ...]:
        """Return evidence attached to a node, edge endpoint or simple candidate.

        A candidate may be a string, a mapping containing ``node_id``/``id``/
        ``name``, or an object exposing one of those attributes.  Unknown
        shapes return an empty tuple rather than guessing a path.
        """

        node = self._candidate_name(node_or_candidate)
        if not node:
            return ()
        ids: list[str] = []
        seen: set[str] = set()
        for edge in self._edges.values():
            if edge.src != node and edge.dst != node:
                continue
            for evidence_id in edge.evidence_ids:
                if evidence_id not in seen:
                    seen.add(evidence_id)
                    ids.append(evidence_id)
        for evidence in self._evidence.values():
            if evidence.evidence_id in seen:
                continue
            if evidence.relation_from == node or evidence.relation_to == node:
                seen.add(evidence.evidence_id)
                ids.append(evidence.evidence_id)
        return tuple(self._evidence[item] for item in ids)

    @staticmethod
    def _candidate_name(candidate: Any) -> str | None:
        if isinstance(candidate, str):
            return candidate
        if isinstance(candidate, Mapping):
            for key in ("node_id", "id", "name"):
                value = candidate.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            return None
        for key in ("node_id", "id", "name"):
            value = getattr(candidate, key, None)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "evidence": [
                {
                    **evidence.to_dict(),
                    "duplicate_count": self._duplicate_counts.get(evidence.evidence_id, 0),
                }
                for evidence in self._evidence.values()
            ],
            "edges": [edge.to_dict() for edge in self._edges.values()],
        }

    def to_json(self, *, indent: int = 2) -> str:
        if isinstance(indent, bool) or not isinstance(indent, int) or indent < 0 or indent > 12:
            raise EvidenceStoreError("indent 必须是 0 到 12 之间的整数")
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=False)

    @classmethod
    def from_dict(cls, payload: Any) -> "EvidenceStore":
        if not isinstance(payload, Mapping):
            raise EvidenceStoreError("证据图必须是 JSON 对象")
        version = payload.get("schema_version")
        if version != _SCHEMA_VERSION:
            raise EvidenceStoreError(f"不支持的证据图版本: {version!r}")
        raw_evidence = payload.get("evidence")
        raw_edges = payload.get("edges")
        if not isinstance(raw_evidence, list) or not isinstance(raw_edges, list):
            raise EvidenceStoreError("证据图必须包含 evidence 和 edges 数组")
        store = cls()
        for item in raw_evidence:
            if not isinstance(item, Mapping):
                raise EvidenceStoreError("evidence 条目必须是对象")
            required = {
                "evidence_id",
                "kind",
                "source_path",
                "line_start",
                "line_end",
                "excerpt",
                "raw_excerpt",
                "tool_name",
                "source_mode",
                "content_sha256",
            }
            missing = required - item.keys()
            if missing:
                raise EvidenceStoreError("evidence 缺少字段: " + ", ".join(sorted(missing)))
            evidence = Evidence(
                evidence_id=item["evidence_id"],
                kind=item["kind"],
                source_path=item["source_path"],
                line_start=item["line_start"],
                line_end=item["line_end"],
                symbol=item.get("symbol"),
                excerpt=item["excerpt"],
                raw_excerpt=item["raw_excerpt"],
                tool_name=item["tool_name"],
                source_mode=item["source_mode"],
                content_sha256=item["content_sha256"],
                query_id=item.get("query_id"),
                source_endpoint=item.get("source_endpoint"),
                relation_from=item.get("relation_from"),
                relation_to=item.get("relation_to"),
            )
            identity = (
                evidence.kind,
                evidence.source_path,
                evidence.line_start,
                evidence.line_end,
                evidence.symbol or "",
            )
            expected_id = _stable_id(
                "E",
                [
                    evidence.kind,
                    evidence.source_path,
                    str(evidence.line_start),
                    str(evidence.line_end),
                    evidence.symbol or "",
                ],
            )
            if evidence.evidence_id != expected_id:
                raise EvidenceStoreError("evidence_id 与证据身份不匹配")
            if evidence.evidence_id in store._evidence or identity in store._evidence_index:
                raise EvidenceStoreError("证据图包含重复 evidence 身份")
            store._evidence[evidence.evidence_id] = evidence
            store._evidence_index[identity] = evidence.evidence_id
            duplicate_count = item.get("duplicate_count", 0)
            if isinstance(duplicate_count, bool) or not isinstance(duplicate_count, int) or duplicate_count < 0:
                raise EvidenceStoreError("duplicate_count 必须是非负整数")
            store._duplicate_counts[evidence.evidence_id] = duplicate_count
        for item in raw_edges:
            if not isinstance(item, Mapping):
                raise EvidenceStoreError("edge 条目必须是对象")
            try:
                edge = store.add_edge(
                    src=item["src"],
                    relation=item["relation"],
                    dst=item["dst"],
                    evidence_ids=item["evidence_ids"],
                    confidence=item.get("confidence", "weak"),
                )
            except KeyError as exc:
                raise EvidenceStoreError(f"edge 缺少字段: {exc.args[0]}") from exc
            expected_edge_id = _stable_id("G", [edge.src, edge.relation, edge.dst])
            if item.get("edge_id") != expected_edge_id or item.get("edge_id") != edge.edge_id:
                raise EvidenceStoreError("edge_id 与端点不匹配")
        return store

    def add_search_hit(
        self,
        source_path: str,
        hit: SearchHit,
        *,
        kind: str = "literal_match",
        symbol: str | None = None,
        tool_name: str = "opengrok.search",
        source_mode: str = "search",
        query_id: str | None = None,
        source_endpoint: str | None = None,
    ) -> Evidence:
        """Convert a normalized OpenGrok hit into line-backed evidence."""

        if not isinstance(hit, SearchHit):
            raise EvidenceValidationError("hit 必须是 SearchHit")
        line_number = str(hit.line_number) if isinstance(hit.line_number, (str, int)) else ""
        if not re.fullmatch(r"[1-9][0-9]*", line_number):
            raise EvidenceValidationError("OpenGrok 命中缺少有效行号，不能建立证据")
        raw_excerpt = hit.raw_line or hit.line
        return self.add_evidence(
            kind=kind,
            source_path=source_path,
            line_start=int(line_number),
            symbol=symbol,
            excerpt=hit.line,
            raw_excerpt=raw_excerpt,
            tool_name=tool_name,
            source_mode=source_mode,
            query_id=query_id,
            content=raw_excerpt,
            source_endpoint=source_endpoint,
        )

    def add_search_response(
        self,
        response: SearchResponse,
        *,
        kind: str = "literal_match",
        tool_name: str = "opengrok.search",
        source_mode: str = "search",
        query_id: str | None = None,
        source_endpoint: str | None = None,
    ) -> tuple[Evidence, ...]:
        if not isinstance(response, SearchResponse):
            raise EvidenceValidationError("response 必须是 SearchResponse")
        items: list[Evidence] = []
        for path, hits in response.results.items():
            for hit in hits:
                items.append(
                    self.add_search_hit(
                        path,
                        hit,
                        kind=kind,
                        tool_name=tool_name,
                        source_mode=source_mode,
                        query_id=query_id,
                        source_endpoint=source_endpoint,
                    )
                )
        return tuple(items)

    def add_source_excerpt(
        self,
        document: SourceDocument,
        *,
        line_start: int,
        line_end: int | None = None,
        kind: str = "symbol_reference",
        symbol: str | None = None,
        tool_name: str = "opengrok.read_source",
        query_id: str | None = None,
        source_endpoint: str | None = None,
    ) -> Evidence:
        """Extract a bounded line range while hashing the full document."""

        if not isinstance(document, SourceDocument):
            raise EvidenceValidationError("document 必须是 SourceDocument")
        start = _validate_line(line_start, name="line_start")
        end = start if line_end is None else _validate_line(line_end, name="line_end")
        if end < start:
            raise EvidenceValidationError("line_end 不能小于 line_start")
        lines = document.content.splitlines()
        if end > len(lines):
            raise EvidenceValidationError(
                f"证据行号 {start}-{end} 超出源码范围（共 {len(lines)} 行）"
            )
        excerpt = "\n".join(lines[start - 1 : end])
        return self.add_evidence(
            kind=kind,
            source_path=document.path,
            line_start=start,
            line_end=end,
            symbol=symbol,
            excerpt=excerpt,
            raw_excerpt=excerpt,
            tool_name=tool_name,
            source_mode=document.source,
            query_id=query_id,
            content=document.content,
            source_endpoint=source_endpoint,
        )

    # Explicit alias for callers that use the noun from the design document.
    add_source_evidence = add_source_excerpt


class EvidenceGraph:
    """Thin graph-facing view over an :class:`EvidenceStore`."""

    def __init__(self, store: EvidenceStore | None = None) -> None:
        self._store = store if store is not None else EvidenceStore()

    @property
    def store(self) -> EvidenceStore:
        return self._store

    @property
    def edges(self) -> tuple[EvidenceEdge, ...]:
        return self._store.edges

    def add_edge(
        self,
        *,
        src: str,
        relation: str,
        dst: str,
        evidence_ids: Iterable[str],
        confidence: str = "weak",
    ) -> EvidenceEdge:
        return self._store.add_edge(
            src=src,
            relation=relation,
            dst=dst,
            evidence_ids=evidence_ids,
            confidence=confidence,
        )

    def evidence_for(self, node_or_candidate: Any) -> tuple[Evidence, ...]:
        return self._store.evidence_for(node_or_candidate)

    def evidence_for_edge(self, edge_id: str) -> tuple[Evidence, ...]:
        return self._store.evidence_for_edge(edge_id)

    def to_dict(self) -> dict[str, Any]:
        return self._store.to_dict()

    def to_json(self, *, indent: int = 2) -> str:
        return self._store.to_json(indent=indent)
