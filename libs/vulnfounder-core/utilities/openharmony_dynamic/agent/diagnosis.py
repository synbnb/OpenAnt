"""诊断证据包（自动化方案 §5.3）：RunRecord + 观测证据 → 结构化 Diagnosis。

喂给 LLM 的是确定性组装的结构化证据，不是原始日志倾倒：
- guard_rejections：按描述符 known_guards 在 hilog 里匹配拒绝行
  （描述符 guard_log_hints 声明关键词，如 udp_token_check → "Token mismatch"）；
- oracle_details：各 artifact form 的 before/after/pattern_found；
- hilog_excerpt：发送时刻前后相关 tag 行（去噪后截断）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..models import ProtocolDescriptor

_HILOG_LINE_RE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+[IWEF]\s+(?P<tag>\S+?)\s*:\s(?P<msg>.*)$"
)

_HILOG_EXCERPT_LIMIT = 80

# 描述符级 guard 日志关键词缺省表（guard_log_hints 未声明时的兜底）。
# 新描述符应优先在 descriptor 上声明 guard_log_hints。
_DEFAULT_GUARD_LOG_HINTS: dict[str, list[str]] = {
    "udp_token_check": ["Token mismatch", "CheckUdpToken", "token"],
    "scm_credential_match": ["credential", "IsValidMsg", "denied"],
    "total_length_check": ["invalid", "length", "drop"],
    "freeze_rule_window": ["FreezeDetector", "rule"],
}


def _guard_hints(descriptor: ProtocolDescriptor | None) -> dict[str, list[str]]:
    hints: dict[str, list[str]] = {}
    for guard in descriptor.known_guards if descriptor else []:
        declared = list(getattr(guard, "guard_log_hints", None) or [])
        hints[guard.name] = declared or _DEFAULT_GUARD_LOG_HINTS.get(guard.name, [])
    return hints


@dataclass
class Diagnosis:
    run_id: str
    contract_id: str
    state: str = ""                      # runner 状态机停在哪一步
    reachability: str = ""
    error: str = ""
    syscalls: list[dict[str, Any]] = field(default_factory=list)
    oracle_details: dict[str, Any] = field(default_factory=dict)
    guard_rejections: list[dict[str, str]] = field(default_factory=list)
    hilog_excerpt: list[str] = field(default_factory=list)
    snapshot_diffs: list[str] = field(default_factory=list)
    revision_history: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "contract_id": self.contract_id,
            "state": self.state,
            "reachability": self.reachability,
            "error": self.error,
            "syscalls": list(self.syscalls),
            "oracle_details": dict(self.oracle_details),
            "guard_rejections": [dict(g) for g in self.guard_rejections],
            "hilog_excerpt": list(self.hilog_excerpt),
            "snapshot_diffs": list(self.snapshot_diffs),
            "revision_history": list(self.revision_history),
        }

    def to_prompt(self) -> str:
        """渲染为喂给 LLM 的紧凑文本（证据包，不是原始日志）。"""
        lines = [
            f"run_id: {self.run_id}",
            f"contract_id: {self.contract_id}",
            f"state: {self.state}",
            f"reachability: {self.reachability}",
        ]
        if self.error:
            lines.append(f"error: {self.error}")
        if self.syscalls:
            lines.append("syscalls:")
            for s in self.syscalls:
                lines.append(f"  {s}")
        if self.oracle_details:
            lines.append(f"oracle_details: {self.oracle_details}")
        if self.guard_rejections:
            lines.append("guard_rejections:")
            for g in self.guard_rejections:
                lines.append(f"  [{g.get('guard')}] {g.get('message', '')[:200]}")
        if self.hilog_excerpt:
            lines.append("hilog_excerpt:")
            for line in self.hilog_excerpt:
                lines.append(f"  {line[:240]}")
        if self.snapshot_diffs:
            lines.append("snapshot_diffs:")
            for d in self.snapshot_diffs:
                lines.append(f"  {d}")
        if self.revision_history:
            lines.append("revision_history (已尝试过的修订，不要重复):")
            for r in self.revision_history:
                lines.append(f"  - {r}")
        return "\n".join(lines)


def build_diagnosis(
    rec_dict: dict[str, Any],
    *,
    descriptor: ProtocolDescriptor | None = None,
    revision_history: list[str] | None = None,
) -> Diagnosis:
    """从 RunRecord.to_dict() 确定性组装 Diagnosis。"""
    diag = Diagnosis(
        run_id=rec_dict.get("run_id", ""),
        contract_id=rec_dict.get("contract_id", ""),
        state=rec_dict.get("state", ""),
        reachability=rec_dict.get("reachability", ""),
        error=rec_dict.get("error", ""),
        syscalls=[dict(s) for s in rec_dict.get("syscalls", [])],
        revision_history=list(revision_history or []),
    )

    # oracle 判定细节（verdict.oracle 或 observations 里的 details）
    verdict = rec_dict.get("verdict") or {}
    oracle = verdict.get("oracle") or {}
    diag.oracle_details = dict(oracle.get("details") or {})

    # hilog 命中行作为 excerpt 的主体（按行截断，去噪）
    hilog_hits = rec_dict.get("hilog_hits") or []
    for hit in hilog_hits[: _HILOG_EXCERPT_LIMIT]:
        if isinstance(hit, dict) and hit.get("message"):
            diag.hilog_excerpt.append(f"[{hit.get('tag', '')}] {hit['message']}")

    # 未命中的轮次：从 observations 里的文件系统快照提取差异摘要
    for obs in rec_dict.get("observations", []):
        fs = obs.get("filesystem") or {}
        for path, snap in fs.items():
            if isinstance(snap, dict):
                diag.snapshot_diffs.append(
                    f"{path}: exists={snap.get('exists')} size={snap.get('size')}"
                )

    # guard 拒绝行：从完整 hilog 文本中匹配（若 RunRecord 里带原始文本）
    hints = _guard_hints(descriptor)
    raw_hilog = rec_dict.get("hilog_raw_text") or ""
    if raw_hilog and hints:
        for guard_name, keywords in hints.items():
            for kw in keywords:
                if not kw:
                    continue
                for line in raw_hilog.splitlines():
                    if kw.lower() in line.lower():
                        diag.guard_rejections.append(
                            {"guard": guard_name, "keyword": kw, "message": line.strip()}
                        )
                        break  # 每个 guard 每个关键词只取一行
    return diag
