"""暴露面识别 Agent 使用的轻量本地知识检索。

知识库刻意限制为一个 Markdown 指南。它不承担事实判断：设备命令的原始
输出仍是唯一的一手证据，检索结果只用于帮助模型选择下一条只读命令和理解
字段含义。实现使用确定性的词项重叠检索，避免为一个侦查任务引入向量库、
网络服务或不可复现的外部依赖。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
from typing import Iterable


KNOWLEDGE_SCHEMA_VERSION = "openant.exposure-surface.knowledge.v1"
DEFAULT_GUIDE_NAME = "openharmony_exposure_surface_command_guide.zh-CN.md"
MAX_GUIDE_BYTES = 512 * 1024
MAX_SNIPPET_CHARS = 2400
_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]{2,}|[\u4e00-\u9fff]{2,}")


@dataclass(frozen=True)
class KnowledgeSnippet:
    """可注入模型提示词的一个有界知识片段。"""

    doc_id: str
    title: str
    text: str
    score: int
    content_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": KNOWLEDGE_SCHEMA_VERSION,
            "doc_id": self.doc_id,
            "title": self.title,
            "text": self.text,
            "score": self.score,
            "content_sha256": self.content_sha256,
        }


def _guide_candidates() -> list[Path]:
    override = os.environ.get("OPENANT_EXPOSURE_GUIDE", "").strip()
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override).expanduser())
    package_root = Path(__file__).resolve().parents[1]
    candidates.append(package_root / "knowledge" / DEFAULT_GUIDE_NAME)
    # Keep compatibility with a checkout where the guide is maintained under
    # docs rather than package data.
    candidates.append(package_root.parent.parent / "docs" / "OPENHARMONY_EXPOSURE_SURFACE_COMMAND_GUIDE.zh-CN.md")
    return candidates


def resolve_guide_path(path: str | os.PathLike[str] | None = None) -> Path | None:
    candidates = [Path(path).expanduser()] if path else _guide_candidates()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_file() and not resolved.is_symlink():
            try:
                if resolved.stat().st_size <= MAX_GUIDE_BYTES:
                    return resolved
            except OSError:
                continue
    return None


def _tokens(value: str) -> set[str]:
    """Return stable lexical tokens, including components of identifiers/paths.

    Targets are normally written as ``unix_socket`` or
    ``/dev/unix/socket/foo`` while the guide uses natural-language headings
    such as ``Unix Domain Socket``.  Treating only the complete identifier as
    a token made the retriever return zero snippets for exactly those common
    inputs.  Keep the complete token for specificity, and add safe
    alphanumeric components so ``unix_socket`` overlaps ``Unix``/``socket``
    and a path overlaps the corresponding command guidance.
    """

    result: set[str] = set()
    for token in _TOKEN_RE.findall(value or ""):
        folded = token.casefold()
        if len(folded) >= 2:
            result.add(folded)
        for component in re.findall(r"[A-Za-z0-9]{2,}|[\u4e00-\u9fff]{2,}", token):
            result.add(component.casefold())
    return result


def _sections(markdown: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    title = "指南"
    body: list[str] = []
    for line in markdown.splitlines():
        match = re.match(r"^#{1,3}\s+(.+?)\s*$", line)
        if match:
            if body:
                text = "\n".join(body).strip()
                if text:
                    sections.append((title, text))
            title = match.group(1).strip()[:160] or "指南"
            body = []
            continue
        body.append(line)
    if body:
        text = "\n".join(body).strip()
        if text:
            sections.append((title, text))
    return sections


class KnowledgeRetriever:
    """对单个本地指南执行稳定、可解释的 lexical top-k 检索。"""

    def __init__(self, guide_path: str | os.PathLike[str] | None = None) -> None:
        self.path = resolve_guide_path(guide_path)
        self.doc_id = self.path.name if self.path else DEFAULT_GUIDE_NAME
        self.content_sha256: str | None = None
        self._sections: list[tuple[str, str]] = []
        if self.path:
            try:
                content = self.path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                content = ""
            self.content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            self._sections = _sections(content)

    @property
    def available(self) -> bool:
        return bool(self._sections and self.content_sha256)

    def retrieve(self, query: str | Iterable[str], *, top_k: int = 4) -> list[KnowledgeSnippet]:
        if not self.available or top_k <= 0:
            return []
        if isinstance(query, str):
            query_text = query
        else:
            query_text = " ".join(str(item) for item in query)
        query_tokens = _tokens(query_text)
        scored: list[tuple[int, int, str, str]] = []
        for index, (title, text) in enumerate(self._sections):
            section_tokens = _tokens(f"{title} {text}")
            overlap = len(query_tokens & section_tokens)
            # A title match is useful when the query is short; make it a
            # deterministic tie-breaker, not a hidden semantic classifier.
            title_overlap = len(query_tokens & _tokens(title))
            score = overlap * 10 + title_overlap * 3
            if score:
                scored.append((score, -index, title, text))
        scored.sort(reverse=True)
        result: list[KnowledgeSnippet] = []
        for score, _index, title, text in scored[:top_k]:
            result.append(
                KnowledgeSnippet(
                    doc_id=self.doc_id,
                    title=title,
                    text=text[:MAX_SNIPPET_CHARS],
                    score=score,
                    content_sha256=self.content_sha256 or "",
                )
            )
        return result
