"""面向回归测试的本地 OpenGrok 兼容客户端。

这个适配器只用于离线验证 source-locator 的检索和证据流程，不会被默认
运行时自动启用，也不会把本机路径暴露给 LLM。它把
``OpenAnt/source_code_base`` 下的一级 Git 仓库映射成
``/openharmony/<repo>/<relative-path>``，实现与 worker 所需的三个只读
方法：``probe``、``search`` 和 ``read_source``。

实现刻意保持“文本检索 + 有界响应”，不假装拥有 OpenGrok 的完整索引语义。
这样真实回归可以区分三种结果：源码确实未包含目标、源码包含但命中太泛、
以及源码中有可定位的精确线索；生产定位仍必须配置远程 OpenGrok。
"""

from __future__ import annotations

from dataclasses import dataclass
import mimetypes
import os
from pathlib import Path
import re
from typing import Any

from .opengrok_client import (
    EndpointCapability,
    OpenGrokPathError,
    ProbeResult,
    SearchHit,
    SearchResponse,
    SourceDocument,
    normalize_source_path,
)


class LocalCorpusError(ValueError):
    """本地回归源码根目录或查询不符合安全约束。"""


_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".repo", "node_modules", "__pycache__",
    ".cache", "target", ".gradle",
})
_TEXT_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc",
    ".gni", ".gn", ".rc", ".cfg", ".conf", ".ini", ".json", ".xml",
    ".yaml", ".yml", ".toml", ".txt", ".md", ".cmake", ".mk", ".bp",
    ".java", ".js", ".ts", ".rs", ".go", ".sh", ".py", ".te",
})
_C_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".gni", ".gn"})
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _safe_root(value: str | os.PathLike[str]) -> Path:
    raw = Path(value).expanduser()
    if raw.is_symlink():
        raise LocalCorpusError("本地源码根目录不能是符号链接")
    try:
        root = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LocalCorpusError(f"本地源码根目录不可用：{exc}") from exc
    if not root.is_dir():
        raise LocalCorpusError("本地源码根目录必须是普通目录")
    return root


def _is_under(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def _relative_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise LocalCorpusError("文件不在本地源码根目录下") from exc
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise LocalCorpusError("本地源码相对路径无效")
    return "/".join(relative.parts)


def _source_path(path: Path, root: Path) -> str:
    relative = _relative_path(path, root)
    # 一级目录是 source_code_base 中的仓库名；根目录下的文件保留为
    # openharmony/<file>，方便测试小型单仓 fixture。
    return "/openharmony/" + relative


def _strip_source_prefix(path: str) -> str:
    try:
        normalized = normalize_source_path(path)
    except OpenGrokPathError as exc:
        raise LocalCorpusError(str(exc)) from exc
    prefix = "/openharmony/"
    if normalized.startswith(prefix):
        return normalized[len(prefix):]
    return normalized.lstrip("/")


def _file_type_allowed(path: Path, file_type: str | None) -> bool:
    if file_type is None:
        return True
    if file_type.lower() in {"all", "any", "text"}:
        return True
    suffix = path.suffix.lower()
    if file_type.lower() in {"c", "cxx", "cpp", "c/c++"}:
        # OpenGrok 的 type=c 语义会覆盖 C/C++ 源码；回归适配器额外保留
        # GNI/GN，因为 OpenHarmony 的 socket 配置常通过构建变量连接。
        return suffix in _C_SUFFIXES
    return suffix == "." + file_type.lower().lstrip(".")


def _contains_identifier(text: str, query: str) -> bool:
    if not query:
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", query):
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(query)}(?![A-Za-z0-9_])", text) is not None
    return query in text


@dataclass(frozen=True)
class LocalCorpusStats:
    files_seen: int
    files_readable: int
    bytes_read: int

    def to_dict(self) -> dict[str, int]:
        return {
            "files_seen": self.files_seen,
            "files_readable": self.files_readable,
            "bytes_read": self.bytes_read,
        }


@dataclass(frozen=True)
class LocalCorpusTargetMatch:
    """一次 corpus 单遍扫描中某个目标的有界命中摘要。"""

    target: str
    full_path_hits: int
    basename_hits: int
    casefold_basename_hits: int
    samples: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "full_path_hits": self.full_path_hits,
            "basename_hits": self.basename_hits,
            "casefold_basename_hits": self.casefold_basename_hits,
            "samples": [dict(item) for item in self.samples],
        }


class LocalCorpusClient:
    """把显式本地源码目录作为只读 OpenGrok 替身。"""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        project: str = "openharmony",
        max_file_bytes: int = 2 * 1024 * 1024,
        max_total_files: int = 200_000,
    ) -> None:
        if not isinstance(project, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", project):
            raise LocalCorpusError("project 名称无效")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or not 1 <= max_file_bytes <= 16 * 1024 * 1024:
            raise LocalCorpusError("max_file_bytes 超出范围")
        if isinstance(max_total_files, bool) or not isinstance(max_total_files, int) or not 1 <= max_total_files <= 1_000_000:
            raise LocalCorpusError("max_total_files 超出范围")
        self.root = _safe_root(root)
        self.project = project
        self.max_file_bytes = max_file_bytes
        self.max_total_files = max_total_files
        self._stats = LocalCorpusStats(0, 0, 0)

    @property
    def stats(self) -> LocalCorpusStats:
        return self._stats

    def _iter_files(self):
        seen = 0
        bytes_read = 0
        readable = 0
        for current, dirs, files in os.walk(self.root, topdown=True, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in _SKIP_DIRS and not (Path(current) / name).is_symlink())
            for name in sorted(files):
                path = Path(current) / name
                if seen >= self.max_total_files:
                    break
                seen += 1
                if path.is_symlink() or path.suffix.lower() not in _TEXT_SUFFIXES:
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size > self.max_file_bytes:
                    continue
                try:
                    content = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                readable += 1
                bytes_read += len(content.encode("utf-8"))
                yield path, content
            if seen >= self.max_total_files:
                break
        self._stats = LocalCorpusStats(seen, readable, bytes_read)

    def _resolve(self, source_path: str) -> Path:
        relative = _strip_source_prefix(source_path)
        raw = self.root / Path(relative)
        current = self.root
        for component in Path(relative).parts:
            current = current / component
            if current.is_symlink():
                raise LocalCorpusError("源码路径不能经过符号链接")
        path = raw.resolve(strict=False)
        if not _is_under(path, self.root) or path == self.root or path.is_symlink():
            raise LocalCorpusError("源码路径越出本地 corpus 或是符号链接")
        if not path.exists() or not path.is_file():
            raise LocalCorpusError("本地 corpus 中不存在该源码文件")
        return path

    def probe(self, *, probe_path: str | None = None) -> ProbeResult:
        capabilities = {
            name: EndpointCapability(name=name, available=True, status_code=200, detail="local regression adapter")
            for name in ("search", "raw", "file_content", "xref")
        }
        warnings = ("这是离线本地回归适配器，不代表远程 OpenGrok 已可用。",)
        if probe_path:
            try:
                self._resolve(probe_path)
            except LocalCorpusError as exc:
                warnings += (f"probe_path 未命中本地 corpus：{exc}",)
        return ProbeResult(
            base_url="local://source_code_base",
            api_prefix="/local",
            reachable=True,
            version="local-corpus-v1",
            index_time=None,
            capabilities=capabilities,
            warnings=warnings,
        )

    def search(
        self,
        *,
        full: str | None = None,
        definition: str | None = None,
        symbol: str | None = None,
        path: str | None = None,
        file_type: str | None = None,
        max_results: int = 50,
        max_hits_per_file: int = 3,
        **_: Any,
    ) -> SearchResponse:
        provided = [("full", full), ("definition", definition), ("symbol", symbol), ("path", path)]
        selected = [(kind, value) for kind, value in provided if value is not None and str(value)]
        if len(selected) != 1:
            raise LocalCorpusError("本地回归搜索必须且只能指定一种查询")
        if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 1000:
            raise LocalCorpusError("max_results 超出范围")
        if isinstance(max_hits_per_file, bool) or not isinstance(max_hits_per_file, int) or not 1 <= max_hits_per_file <= 1000:
            raise LocalCorpusError("max_hits_per_file 超出范围")
        kind, raw_query = selected[0]
        query = str(raw_query)
        results: dict[str, tuple[SearchHit, ...]] = {}
        result_count = 0
        for file_path, content in self._iter_files():
            if not _file_type_allowed(file_path, file_type):
                continue
            source_path = _source_path(file_path, self.root)
            if kind == "path":
                matched = query.lower() in source_path.lower()
            elif kind == "definition":
                # 近似 OpenGrok definition：识别宏、变量和函数声明/定义，
                # 没有声明形式时仍允许精确 token 命中，避免把测试适配器
                # 的“没索引到”误当成真实源码不存在。
                definition_re = re.compile(
                    rf"(?m)(?:^|\s)(?:#\s*define\s+|(?:static\s+|const\s+|constexpr\s+|extern\s+)?[A-Za-z_][A-Za-z0-9_:<>*&\s]*\b){re.escape(query)}\b"
                )
                matched = definition_re.search(content) is not None or _contains_identifier(content, query)
            elif kind == "symbol":
                matched = _contains_identifier(content, query)
            else:
                matched = query in content
            if not matched:
                continue
            lines = content.splitlines()
            hits: list[SearchHit] = []
            if kind == "path":
                hit_lines = [1]
            else:
                hit_lines = [index for index, line in enumerate(lines, 1) if (query in line if kind == "full" else _contains_identifier(line, query))]
                if not hit_lines:
                    hit_lines = [1]
            for line_no in hit_lines[:max_hits_per_file]:
                hits.append(SearchHit(line=lines[line_no - 1][:4096], line_number=str(line_no), tag=kind))
            if not hits:
                continue
            results[source_path] = tuple(hits)
            result_count += 1
            if len(results) >= max_results:
                break
        return SearchResponse(
            time_ms=0,
            result_count=result_count,
            start_document=0,
            end_document=max(0, result_count - 1),
            results=results,
        )

    def scan_targets(
        self,
        targets: list[str] | tuple[str, ...],
        *,
        max_samples_per_target: int = 12,
    ) -> dict[str, LocalCorpusTargetMatch]:
        """用一次文件遍历检查多个 socket 目标。

        这是本地回归专用的精确字面/大小写别名检查，不替代远程 OpenGrok
        查询。样本包含仓库映射路径、行号和原文片段，数量严格有界。
        """

        if isinstance(targets, (str, bytes)):
            raise LocalCorpusError("targets 必须是路径序列")
        if isinstance(max_samples_per_target, bool) or not isinstance(max_samples_per_target, int) or not 1 <= max_samples_per_target <= 128:
            raise LocalCorpusError("max_samples_per_target 超出范围")
        normalized: list[tuple[str, str, str]] = []
        for target in targets:
            try:
                clean = normalize_source_path(target)
            except OpenGrokPathError as exc:
                raise LocalCorpusError(str(exc)) from exc
            basename = clean.rsplit("/", 1)[-1]
            normalized.append((clean, basename, basename.casefold()))
        counts = {
            target: {"full": 0, "base": 0, "fold": 0, "samples": []}
            for target, _, _ in normalized
        }
        for file_path, content in self._iter_files():
            source_path = _source_path(file_path, self.root)
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                folded_line = line.casefold()
                for target, basename, folded_basename in normalized:
                    kind: str | None = None
                    if target in line:
                        counts[target]["full"] += 1
                        kind = "full_path"
                    if basename in line:
                        counts[target]["base"] += 1
                        if kind is None:
                            kind = "basename"
                    if folded_basename != basename and folded_basename in folded_line:
                        counts[target]["fold"] += 1
                        if kind is None:
                            kind = "basename_casefold"
                    if kind is not None and len(counts[target]["samples"]) < max_samples_per_target:
                        counts[target]["samples"].append(
                            {"path": source_path, "line": line_no, "kind": kind, "text": line[:4096]}
                        )
        return {
            target: LocalCorpusTargetMatch(
                target=target,
                full_path_hits=values["full"],
                basename_hits=values["base"],
                casefold_basename_hits=values["fold"],
                samples=tuple(values["samples"]),
            )
            for target, values in counts.items()
        }

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 16 * 1024 * 1024:
            raise LocalCorpusError("max_bytes 超出范围")
        file_path = self._resolve(path)
        raw = file_path.read_bytes()
        truncated = len(raw) > limit
        if truncated:
            raw = raw[:limit]
        return SourceDocument(
            path=normalize_source_path(path),
            content=raw.decode("utf-8", errors="replace"),
            source="local_corpus",
            content_type=mimetypes.guess_type(file_path.name)[0] or "text/plain",
            status_code=200,
            truncated=truncated,
        )


__all__ = ["LocalCorpusClient", "LocalCorpusError", "LocalCorpusStats", "LocalCorpusTargetMatch"]
