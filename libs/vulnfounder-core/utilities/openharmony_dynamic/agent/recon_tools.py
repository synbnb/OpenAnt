"""侦查工具执行器（自动化方案 §9.2 / §11.1）：LLM 侦查请求 → 确定性执行。

执行权完全在本模块：逐 token 白名单校验 argv，越权请求直接拒绝（返回错误说明，
不执行）；输出经裁剪（行数/字节上限）后回喂 LLM。每次调用记录 audit 事件。
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

# ---- 输出裁剪上限（§11.1 L1：防单次返回撑爆上下文）----
# cat 截断不丢内容：超限时回喂 head/tail 分页指令，LLM 可分页读全文件
# （实测 freeze_rules.xml 15684B 若硬截 4KB 会丢 35/48 个 stringid）
MAX_READ_LINES = 200
MAX_GREP_LINES = 120      # 实测 HIVIEW_LOG 目录命中 94 行——80 会截断真实命中
MAX_HILOG_LINES = 50
MAX_CAT_BYTES = 4096
MAX_NOTE_CHARS = 2000
MAX_NOTES = 24

# ---- hdc_shell 只读白名单（§9.2 表）----
# argv[0] 逐 token 匹配；参数形态由 _validate_* 复核
_READONLY_ARGV0 = {
    "hilog", "ls", "cat", "test", "ps", "param", "date",
    "head", "tail", "wc", "grep", "id", "getenforce",
}

_PATH_PARAM_TOOLS = {"cat"}  # cat 目标必须绝对路径且无 ..
_PLACEHOLDER_RE = re.compile(r"__[A-Z_]+__")


@dataclass
class ReconAudit:
    """单次工具调用的审计记录（全量进 CompileResult.notes，可追溯）。"""

    tool: str
    args: dict[str, Any]
    ok: bool
    truncated: bool = False
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "args": self.args, "ok": self.ok,
            "truncated": self.truncated, "detail": self.detail,
        }


@dataclass
class ReconTools:
    """确定性工具执行器。hdc 可为 None（离线模式：设备类工具不可用）。"""

    hdc: "HDCClient | None"
    repo_root: Path
    max_device_commands: int = 40
    audit: list[ReconAudit] = field(default_factory=list)
    device_commands_used: int = 0
    notes: list[str] = field(default_factory=list)
    # 已执行的全仓 grep（pattern 列表）——insufficient 申报闸门依据
    grep_history: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 工具入口（recon_loop 由 LLM 结构化输出选择调用哪个）
    # ------------------------------------------------------------------
    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """分发一次工具调用；返回 {"ok": bool, "output": str, ...}。"""
        handler = {
            "read_file": self._read_file,
            "grep": self._grep,
            "list_dir": self._list_dir,
            "hilog_grep": self._hilog_grep,
            "hdc_shell": self._hdc_shell,
            "write_note": self._write_note,
            "read_notes": self._read_notes,
        }.get(tool)
        if handler is None:
            return self._reject(tool, args, f"未知工具: {tool}")
        try:
            result = handler(args)
        except Exception as exc:  # noqa: BLE001 — 工具层异常转为错误回喂，不中断 loop
            return self._reject(tool, args, f"{type(exc).__name__}: {exc}")
        self.audit.append(ReconAudit(tool=tool, args=args, ok=result.get("ok", False),
                                     truncated=result.get("truncated", False),
                                     detail=result.get("error", "")))
        return result

    # ------------------------------------------------------------------
    def _reject(self, tool: str, args: dict[str, Any], error: str) -> dict[str, Any]:
        self.audit.append(ReconAudit(tool=tool, args=args, ok=False, detail=error))
        return {"ok": False, "error": error}

    def _budget_device(self, tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
        if self.hdc is None:
            return self._reject(tool, args, "离线模式：设备工具不可用")
        if self.device_commands_used >= self.max_device_commands:
            return self._reject(tool, args,
                                f"侦查设备命令预算耗尽（{self.max_device_commands}）")
        self.device_commands_used += 1
        return None

    # ------------------------------------------------------------------
    def _read_file(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._repo_path(args.get("path", ""))
        offset = max(0, int(args.get("offset", 0)))
        limit = min(MAX_READ_LINES, max(1, int(args.get("limit", MAX_READ_LINES))))
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        window = lines[offset:offset + limit]
        truncated = offset + limit < total
        return {
            "ok": True,
            "output": "\n".join(f"{offset + i + 1}: {l}" for i, l in enumerate(window)),
            "total_lines": total,
            "offset": offset,
            "next_offset": offset + limit if truncated else None,
            "truncated": truncated,
        }

    def _grep(self, args: dict[str, Any]) -> dict[str, Any]:
        pattern = str(args.get("pattern", ""))
        if not pattern:
            return {"ok": False, "error": "pattern 为空"}
        path = self._repo_path(args.get("path", ""))
        limit = min(MAX_GREP_LINES, max(1, int(args.get("limit", MAX_GREP_LINES))))
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return {"ok": False, "error": f"正则非法: {exc}"}
        # 记录到 grep_history（无论命中与否）——insufficient 申报闸门要求
        # finalize 前至少做过一次全仓 grep（防止假否定循环，见 recon_loop 闸门）
        if path == self.repo_root or path.is_dir():
            self.grep_history.append(pattern)
        hits: list[str] = []
        truncated = False
        if path.is_file():
            targets = [path]
        else:
            targets = sorted(p for p in path.rglob("*") if p.is_file() and p.stat().st_size < 2_000_000)
        for target in targets:
            try:
                for i, line in enumerate(target.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if regex.search(line):
                        rel = target.relative_to(self.repo_root) if target.is_relative_to(self.repo_root) else target
                        hits.append(f"{rel}:{i}: {line.strip()}")
                        if len(hits) >= limit:
                            truncated = True
                            break
            except OSError:
                continue
            if truncated:
                break
        return {"ok": True, "output": "\n".join(hits) or "(无命中)",
                "hits": len(hits), "truncated": truncated}

    def _list_dir(self, args: dict[str, Any]) -> dict[str, Any]:
        path = self._repo_path(args.get("path", ""))
        if not path.is_dir():
            return {"ok": False, "error": f"非目录: {path}"}
        entries = sorted(p.name + ("/" if p.is_dir() else "") for p in path.iterdir())
        return {"ok": True, "output": "\n".join(entries[:200]),
                "total": len(entries), "truncated": len(entries) > 200}

    # ------------------------------------------------------------------
    def _hilog_grep(self, args: dict[str, Any]) -> dict[str, Any]:
        """真机 hilog -x 一次性 dump → 主机侧过滤（§7.1：不反复 tail）。"""
        reject = self._budget_device("hilog_grep", args)
        if reject:
            return reject
        from ..observation.snapshot import dump_hilog

        dump = dump_hilog(self.hdc, purpose="recon:hilog-dump")
        lines = dump.text.splitlines()
        # 无 tag/pattern 过滤的 dump 前 50 行全是系统噪声（实测 APPSPAWN 523 行
        # 最多、FreezeDetector 命中 0）——强制至少一个过滤条件
        tag = str(args.get("tag", ""))
        pattern = args.get("pattern", "")
        if not tag and not pattern:
            return {"ok": False,
                    "error": "hilog_grep 须提供 tag 或 pattern 至少一个（无过滤的 dump 全是系统噪声）"}
        regex = re.compile(pattern) if pattern else None
        hits: list[str] = []
        for line in lines:
            if tag and tag not in line:
                continue
            if regex and not regex.search(line):
                continue
            hits.append(line.strip())
            if len(hits) >= MAX_HILOG_LINES:
                break
        return {"ok": True, "output": "\n".join(hits) or "(无命中)",
                "hits": len(hits), "total_lines": len(lines),
                "truncated": len(hits) >= MAX_HILOG_LINES}

    def _hdc_shell(self, args: dict[str, Any]) -> dict[str, Any]:
        """只读白名单 shell（§9.2）。argv 形如 ["cat", "/path/to/file"]。"""
        reject = self._budget_device("hdc_shell", args)
        if reject:
            return reject
        argv = args.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            return {"ok": False, "error": "argv 必须是非空字符串列表"}
        if argv[0] not in _READONLY_ARGV0:
            return {"ok": False,
                    "error": f"越权命令（白名单外）: {argv[0]!r}；允许: {sorted(_READONLY_ARGV0)}"}
        # param 只允许 get 子命令（set/list 属写/枚举，list 可泄配置基线）
        if argv[0] == "param" and (len(argv) < 2 or argv[1] != "get"):
            return {"ok": False, "error": "param 仅允许 'param get <name>'（只读）"}
        if any(_PLACEHOLDER_RE.search(a) for a in argv):
            return {"ok": False, "error": "argv 含占位符（侦查阶段无运行期模板）"}
        for token in argv[1:]:
            if token.startswith("/") and ".." in Path(token).parts:
                return {"ok": False, "error": f"路径含 ..: {token}"}
        if argv[0] == "cat":
            if len(argv) != 2 or not argv[1].startswith("/"):
                return {"ok": False, "error": "cat 仅支持单绝对路径参数"}
        if argv[0] == "hilog" and any(a.startswith("-") is False and not a.startswith("/") for a in argv[1:]):
            return {"ok": False, "error": "hilog 参数仅允许选项"}
        rec = self.hdc.shell(argv, purpose="recon:shell")
        stdout = rec.stdout or ""
        if len(stdout) > MAX_CAT_BYTES:
            # 大文件不静默截断——给出分页指令（head/tail 白名单内，LLM 可分页拼接）
            return {"ok": True, "truncated": True,
                    "output": stdout[:MAX_CAT_BYTES] + (
                        f"\n\n[已截断：完整 {len(stdout)}B，用 head/tail 分页读，"
                        f"例：head -n 200 {argv[1]} / tail -n +201 {argv[1]} | head -n 200]")}
        return {"ok": True, "output": stdout.strip() or "(空输出)", "truncated": False}

    # ------------------------------------------------------------------
    def _write_note(self, args: dict[str, Any]) -> dict[str, Any]:
        text = str(args.get("text", "")).strip()
        if not text:
            return {"ok": False, "error": "note 为空"}
        if len(self.notes) >= MAX_NOTES:
            return {"ok": False, "error": f"notes 已满（{MAX_NOTES}）"}
        text = text[:MAX_NOTE_CHARS]
        self.notes.append(text)
        return {"ok": True, "output": f"note #{len(self.notes)} 已固化", "notes_count": len(self.notes)}

    def _read_notes(self, args: dict[str, Any]) -> dict[str, Any]:
        body = "\n".join(f"[{i}] {n}" for i, n in enumerate(self.notes, 1))
        return {"ok": True, "output": body or "(暂无 notes)"}

    # ------------------------------------------------------------------
    def _repo_path(self, raw: str) -> Path:
        path = Path(str(raw or ""))
        if path.is_absolute():
            resolved = path.resolve()
        else:
            resolved = (self.repo_root / path).resolve()
        root = self.repo_root.resolve()
        if not (resolved == root or root in resolved.parents):
            raise ValueError(f"路径越出仓库根 {root}: {raw}")
        return resolved

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_commands_used": self.device_commands_used,
            "max_device_commands": self.max_device_commands,
            "notes": list(self.notes),
            "audit": [a.to_dict() for a in self.audit],
        }
