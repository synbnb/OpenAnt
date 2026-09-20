"""Stage1/2 静态分析产出 → FindingInput 的 LLM 适配器（自动化方案 §2）。

真实 Stage1 数据集（中文键：函数名称/起止位置/所处文件路径/
具体漏洞源码与漏洞描述/完整攻击链/根因分析）与 FindingInput（英文键）
字段不对齐。本模块用单轮 LLM 做语义转换（vuln_class 归类、sink 提炼、
entry_hints 候选提取），再对 LLM 输出做**确定性校验**。它不负责发现未知
socket 或端口；入口候选的源码/设备取证由协议匹配前的
``agent.entry_discovery_loop`` 负责。

- vuln_class ∈ 九类枚举（§3.3 映射表键）
- source_paths 文件在 repo_root 下真实存在
- evidence_lines 与 source_paths 对齐且行号在该文件行数范围内
- entry.kind 线索（端口/socket 路径）原样保留为 entry_hints

校验不过 → 整份拒绝（REJECTED_VALIDATION），绝不带编造路径进编译器。
LLM 不可用 → REQUIRES_PROTOCOL_REVIEW（诚实降级，不做无 LLM 的盲猜转换）。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .finding_input import FindingInput

# §3.3 合法 vuln_class 集（与 contract_compiler._VULNCLASS_ORACLE 键一致）
_VULN_CLASSES = {
    "command_injection", "arbitrary_file_write", "information_disclosure", "path_traversal",
    "permission_bypass", "fd_leak", "resource_exhaustion", "parcel_check_missing",
    "race_condition",
}

# 行号范围提取（"sp_utils.cpp:140-143" / "freeze_manager.cpp:204"）
_LINE_RANGE_RE = re.compile(r"([\w.\-]+\.(?:cpp|c|cc|h|hpp|ets|ts|java|py)):(\d+)(?:-(\d+))?")
# entry_hint 形态（与系统提示词的严格形态一一对应）：
#   hap_udp/hap_tcp <ip|unknown>:<port> | unix_dgram/unix_stream <绝对路径>
#   | event_bus <domain>/<stringid>（unknown/unknown 允许）| cli <名>
_ENTRY_HINT_RE = re.compile(
    r"^(hap_(?:udp|tcp)\s+(?:[\d.]+|unknown):\d{2,5}"
    r"|unix_(?:dgram|stream)\s+/[\w./\-]+"
    r"|event_bus\s+\S+/\S+(?:\s*触发)?"
    r"|cli\s+\S+)$",
    re.IGNORECASE,
)


@dataclass
class AdapterResult:
    """适配结果：LLM 转换 + 确定性校验。"""

    status: str                       # CONVERTED / REJECTED_VALIDATION / REQUIRES_PROTOCOL_REVIEW
    finding: FindingInput | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    llm_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "llm_used": self.llm_used,
            "finding": self.finding.to_dict() if self.finding else None,
        }


# ---------------------------------------------------------------------------
# LLM 基础设施（与 refine_loop / contract_compiler 相同复用路径，不新建通道）
# ---------------------------------------------------------------------------

def _llm_binding():
    try:
        root = Path(__file__).resolve().parents[3]
        core = str(root / "libs" / "vulnfounder-core")
        if core not in sys.path:
            sys.path.insert(0, core)
        from utilities.llm.helpers import simple_text  # noqa: PLC0415
        from utilities.llm.registry import (  # noqa: PLC0415
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
        )

        cf = load_config_file()
        lc = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, lc)
        return registry.get("dynamic_test"), simple_text
    except Exception:  # noqa: BLE001
        return None


_ADAPT_SYSTEM_PROMPT = (
    "你是静态分析 finding 的动态测试适配器。输入是 Stage1 静态分析产出"
    "（中文键 JSON），输出 FindingInput JSON（英文键）：\n"
    "{\n"
    '  "vuln_class": "九类之一：command_injection | arbitrary_file_write | '
    "information_disclosure | path_traversal | permission_bypass | fd_leak | "
    'resource_exhaustion | parcel_check_missing | race_condition",\n'
    '  "description": "<finding 的一句话结论（中文可保留）>",\n'
    '  "sink": "<最终危险操作点：函数 + 文件:行，如 popen(...) at Network.cpp:153>",\n'
    '  "entry_hints": ["<设备侧网络入口线索，从「完整攻击链」提取，必须符合以下形态之一>"]\n'
    "}\n"
    "entry_hints 形态（严格）：\n"
    '- UDP/TCP 入口: "hap_udp <ip>:<端口>" 或 "hap_tcp <ip>:<端口>"'
    "（如 hap_udp 127.0.0.1:8283）\n"
    '- Unix socket 入口: "unix_dgram <绝对路径>" 或 "unix_stream <绝对路径>"'
    "（如 unix_dgram /dev/unix/socket/hisysevent）\n"
    '- 事件总线入口: "event_bus <domain>/<stringid> 触发"——攻击链里只描述了'
    "服务内部的事件处理（如插件回调、FREEZE_INFO_PATH 字段投毒、无端口/socket）"
    "时，若该服务是事件订阅型服务（hiview 插件/HiSysEvent 订阅者），入口就是"
    "事件总线：写 \"event_bus unknown/unknown 触发\"（domain/stringid 未在"
    "攻击链中出现时填 unknown，由后续侦查 loop 从设备规则表查证）\n"
    "- 命令行入口: \"cli <可执行名>\"（如 cli SP_daemon）\n"
    "提取不到网络/socket/事件入口就给空数组——不要把内部函数回调、"
    "中间转发函数（如 FreezeDetectorPlugin::OnEventListeningCallback）当入口线索。\n"
    "硬规则：\n"
    "1. vuln_class 按攻击的**最终危害**归类（写任意文件=arbitrary_file_write；"
    "读敏感文件=information_disclosure；shell 元字符进 popen/system=command_injection；"
    "路径检查缺失读+删=path_traversal），不要按入口手段归类。\n"
    "2. sink 是攻击链末端那个真正执行危险操作的调用点（不是中间转发函数）。\n"
    "3. entry_hints 只描述**外部攻击者如何触达**该服务（网络端口/socket/事件总线/CLI），"
    "其余一律为空数组，不要编造端口或 socket 路径。\n"
    "4. 不要发明源码里不存在的函数名/行号——sink 的 文件:行 必须来自输入。\n"
    "只输出一个 JSON 对象。"
)


def _llm_convert(stage_finding: dict[str, Any]) -> dict[str, Any] | None:
    pair = _llm_binding()
    if pair is None:
        return None
    binding, simple_text = pair
    text = simple_text(binding, json.dumps(stage_finding, ensure_ascii=False),
                       system=_ADAPT_SYSTEM_PROMPT, max_tokens=4000)
    text = text.strip()
    if text.startswith("```"):
        body = text.split("```")[1]
        if body.startswith("json"):
            body = body[4:]
        text = body
    try:
        raw = json.loads(text.strip())
    except json.JSONDecodeError:
        return None
    return raw if isinstance(raw, dict) else None


# ---------------------------------------------------------------------------
# 确定性校验与行号解析
# ---------------------------------------------------------------------------

def _parse_stageloc(起止位置: str, 所处文件路径: str) -> list[int]:
    """Stage1 起止位置（"sp_utils.cpp:140-143"）→ [140, 143]；解析失败用 [1, 1]。"""
    match = _LINE_RANGE_RE.search(起止位置 or "")
    if match:
        start = int(match.group(2))
        end = int(match.group(3) or match.group(2))
        if 1 <= start <= end:
            return [start, end]
    return [1, 1]


def _verify_against_repo(finding: FindingInput, repo_root: Path) -> list[str]:
    """确定性核对：文件存在、行号在文件行数范围内、entry_hints 形态合法。"""
    errors: list[str] = []
    for src, lines in zip(finding.source_paths, finding.evidence_lines):
        path = Path(src) if Path(src).is_absolute() else repo_root / src
        if not path.exists():
            errors.append(f"源码文件不存在: {src}（repo_root={repo_root}）")
            continue
        if lines:
            total = sum(1 for _ in path.open("rb"))
            if lines[0] > total or lines[-1] > total:
                errors.append(f"行号越界: {src}:{lines} 超出文件行数 {total}")
    for hint in finding.entry_hints:
        if not _ENTRY_HINT_RE.match(hint.strip()):
            errors.append(
                f"entry_hint 形态不可识别: {hint!r}"
                f"（合法: hap_udp <ip>:<port> / unix_dgram <路径> / event_bus <domain>/<id> / cli <名>）")
    return errors


def adapt_stage_finding(
    stage_finding: dict[str, Any],
    *,
    finding_id: str,
    unit_id: str = "",
    repo_root: str,
    convert_override: dict[str, Any] | None = None,
) -> AdapterResult:
    """Stage1 finding（中文键）→ FindingInput。convert_override 用于测试注入（跳过 LLM）。

    流水：键名核对 → LLM 语义转换（vuln_class/sink/entry_hints）
    → 确定性拼装（source_paths/evidence_lines 来自 Stage1 原文，不经 LLM）
    → 仓库核对（文件存在/行号越界/hint 形态）。
    """
    # 1. Stage1 键核对（缺键 = 非 Stage1 产出，拒绝）
    required_keys = {"函数名称", "起止位置", "所处文件路径", "完整攻击链"}
    missing = required_keys - set(stage_finding)
    if missing:
        return AdapterResult(
            status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"输入缺 Stage1 必备键: {sorted(missing)}"],
        )

    # 2. LLM 语义转换（vuln_class/sink/entry_hints——这三项需要语义理解）
    raw = convert_override or _llm_convert(stage_finding)
    llm_used = convert_override is None
    if raw is None:
        return AdapterResult(
            status="REQUIRES_PROTOCOL_REVIEW",
            errors=["LLM 不可用或输出不合法（非 JSON / 结构不符）"], llm_used=llm_used,
        )

    # 3. 确定性校验 LLM 输出
    vuln_class = str(raw.get("vuln_class", "")).strip()
    if vuln_class not in _VULN_CLASSES:
        return AdapterResult(
            status="REJECTED_VALIDATION",
            errors=[f"vuln_class 非法: {vuln_class!r}（允许 {sorted(_VULN_CLASSES)}）"],
            llm_used=llm_used,
        )

    # 4. 确定性拼装：source_paths / evidence_lines 直接取自 Stage1 原文
    #    （文件路径与行号范围是机械解析，不交给 LLM——防路径幻觉）
    src_rel = str(stage_finding["所处文件路径"]).strip()
    lines = _parse_stageloc(str(stage_finding["起止位置"]), src_rel)
    finding = FindingInput(
        finding_id=finding_id,
        unit_id=unit_id or re.sub(r"[^a-z0-9_]+", "_", vuln_class).strip("_"),
        vuln_class=vuln_class,
        description=str(raw.get("description", "")) or str(stage_finding.get("根因分析", "")),
        source_paths=[src_rel],
        evidence_lines=[lines],
        sink=str(raw.get("sink", "")),
        entry_hints=[str(h) for h in raw.get("entry_hints", [])][:4],
        repo_root=repo_root,
        # 保存 Stage 1 的有限原始上下文，供后置入口发现 loop 读取调用链、证据
        # 和缺失证据；source_paths/evidence_lines 仍由下面的确定性校验负责。
        analysis_context={
            str(key): value for key, value in stage_finding.items()
            if key not in {"所处文件路径", "起止位置"}
        },
    )

    # 5. 仓库核对（确定性）
    errors = _verify_against_repo(finding, Path(repo_root))
    if errors:
        return AdapterResult(status="REJECTED_VALIDATION", finding=finding,
                             errors=errors, llm_used=llm_used)

    warnings: list[str] = []
    if not finding.entry_hints:
        warnings.append("entry_hints 为空：入口线索需描述符库/侦查 loop 自行发现")
    if not finding.sink:
        warnings.append("sink 为空：攻击链末端危险点未提取")
    return AdapterResult(status="CONVERTED", finding=finding,
                         warnings=warnings, llm_used=llm_used)
