"""契约编译器（自动化方案 §3）：FindingInput → candidate contract。

确定性填充优先：能从描述符库 / §3.3 映射表 / 风险表推导的字段禁止交给 LLM；
协议匹配之前先运行入口发现 Agent Loop，查证外部 endpoint 和入口类型；之后的
LLM 侦查 loop 才起草 fault 块、field_values 槽内取值、oracle forms 实例化、param_space。
编译产物必须通过 contract_validator 全表才得 ELIGIBLE，否则诚实降级
REQUIRES_PROTOCOL_REVIEW 并写明缺口——绝不带着未校验的契约上设备。

产物落 contracts/generated/（与手写固件隔离），不自动写入固件库。
"""

from __future__ import annotations

import json
import re
import sys
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .contract_validator import apply_compile_gate, validate_contract
from .contracts.registry import contract_from_dict
from .finding_input import FindingInput
from .models import Contract, RouteBinding
from .protocols import get_descriptor, register

# ---------------------------------------------------------------------------
# §3.3 漏洞类 → 预言机映射（确定性表；未实现的预言机诚实降级）
# 首选 oracle 以 artifact_differential forms 组合表达（当前唯一实现）。
# ---------------------------------------------------------------------------

_VULNCLASS_ORACLE: dict[str, dict[str, Any]] = {
    "command_injection": {
        "forms": [{"form": "create", "path": "__MARKER__", "content_note": "注入命令的字面输出"}],
        "impl": True,
        "ref": "DP-02",
    },
    "arbitrary_file_write": {
        "forms": [{"form": "create", "path": "__RUN_DIR__/__canary", "content_note": "写入内容"}],
        "impl": True,
    },
    "information_disclosure": {
        "forms": [{"form": "exfil", "path": "__SRC_FILE__", "output_surface_note": "泄露输出面目录"}],
        "impl": True,
        "ref": "HV-05",   # 归类漂移兜底：FreezeManager 案例两轮分别被归为
                          # path_traversal / information_disclosure（LLM 语义判断
                          # 波动），两者攻击链同族（freeze_ext 输出面）——共享
                          # exemplar 保证草案结构稳定（run 376c13e2 实证）
    },
    "path_traversal": {
        "forms": [
            {"form": "exfil", "path": "__CPU_FILE__", "output_surface_note": "输出面目录"},
            {"form": "delete", "path": "__CPU_FILE__"},
        ],
        "impl": True,
        "ref": "HV-05",
    },
    "permission_bypass": {"impl": False, "reason": "permission_differential 未实现（需双身份）"},
    "fd_leak": {"impl": False, "reason": "resource_delta 未实现"},
    "resource_exhaustion": {"impl": False, "reason": "resource_delta 未实现"},
    "parcel_check_missing": {"impl": False, "reason": "readback_differential / crash_correlated 未实现"},
    "race_condition": {"impl": False, "reason": "state_differential 重复性判定未实现"},
}

# entry.kind → 身份（当前身份阶梯；后续身份合成扩展再放宽）
_ENTRY_IDENTITY = {
    "hap_udp": ("hap_app", "hap_app", "A"),
    "hap_tcp": ("hap_app", "hap_app", "A"),
    "unix_dgram": ("root_su", "root_su", "C"),
    "unix_stream": ("root_su", "root_su", "C"),
    "native_unix": ("root_su", "root_su", "C"),
}

# entry_hints / 描述符 transports → entry.kind 推断（确定性）
_DESCRIPTOR_ENTRY_KIND: dict[str, list[str]] = {
    "hisysevent_eventraw": ["unix_dgram"],
    "sp_daemon_text": ["hap_udp", "hap_tcp"],
}

_COMPILED_DIR = Path(__file__).parent / "contracts" / "generated"

# 确定性兜底：标准否证集（V7 必填；可推导，不交给 LLM 记忆）
_DEFAULT_REFUTATION = [
    "run_pattern_bound",
    "baseline_absent",
    "source_file_planted_by_run",
]

# 描述符族 → exfil 标准输出面（output_surface 可推导项）
_DESCRIPTOR_SURFACES: dict[str, str] = {
    "hisysevent_eventraw": "/data/log/faultlog/freeze_ext",
    "sp_daemon_text": "__RUN_DIR__",
}

# 描述符族 → 预埋文件标准目录（目标服务必须可读；设备侧环境知识，确定性填充）
_DESCRIPTOR_SRC_DIRS: dict[str, str] = {
    "hisysevent_eventraw": "/data/log/eventlog",   # hiview 域可读（真机实证）
    "sp_daemon_text": "__RUN_DIR__",
}

# §9.3 常量表已退役：field_values / hilog tag 等语义内容由侦查 loop（§9）实测得出，
# 提示事实与强制回填不再存在——LLM 侦查后自主填写，校验器复核事实卡（§11.2）。
# 保留的 _DESCRIPTOR_SRC_DIRS / _DESCRIPTOR_SURFACES 降级为缺省提示（草案值优先）。

@dataclass
class CompileResult:
    contract: Contract | None
    compile_status: str
    errors: list[str] = field(default_factory=list)
    descriptor_hit: str = ""
    llm_used: bool = False
    notes: list[str] = field(default_factory=list)
    entry_discovery: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "compile_status": self.compile_status,
            "errors": list(self.errors),
            "descriptor_hit": self.descriptor_hit,
            "llm_used": self.llm_used,
            "notes": list(self.notes),
            "entry_discovery": dict(self.entry_discovery),
            "contract": self.contract.to_dict() if self.contract else None,
        }


# ---------------------------------------------------------------------------
# LLM 基础设施（与 refine_loop 相同的复用路径）
# ---------------------------------------------------------------------------

def _llm_binding():
    try:
        path = Path(__file__).resolve()
        root = next((parent for parent in path.parents if (parent / "libs" / "vulnfounder-core").is_dir()), path.parents[3])
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


# ---------------------------------------------------------------------------
# 确定性填充
# ---------------------------------------------------------------------------

def _match_descriptor(finding: FindingInput) -> str:
    """描述符库确定性查找：entry_hints + vuln_class 线索匹配已注册描述符。"""
    hints = " ".join(finding.entry_hints).lower()
    for descriptor_id, entry_kinds in _DESCRIPTOR_ENTRY_KIND.items():
        try:
            get_descriptor(descriptor_id)
        except KeyError:
            continue
        for kind in entry_kinds:
            if kind in hints or kind.replace("_", " ") in hints:
                return descriptor_id
    # sink 特征兜底：popen/网络端点 → sp_daemon_text；hisysevent → eventraw
    sink = finding.sink.lower()
    if "hisysevent" in hints or "hisysevent" in sink:
        return "hisysevent_eventraw"
    # event_bus 入口（Stage1 适配器对事件订阅型服务的产出形态）：当前描述符库
    # 中唯一事件订阅协议族为 hisysevent_eventraw；domain/stringid 具体值仍由
    # 侦查 loop 从设备规则表查证（hint 中 unknown/unknown 即此意图）
    if "event_bus" in hints:
        return "hisysevent_eventraw"
    if "udp" in hints or "tcp" in hints or "8283" in hints:
        return "sp_daemon_text"
    return ""


def _infer_entry_kind(descriptor_id: str, finding: FindingInput) -> str:
    kinds = _DESCRIPTOR_ENTRY_KIND.get(descriptor_id, [])
    hints = " ".join(finding.entry_hints).lower()
    for kind in kinds:
        if kind in hints:
            return kind
    return kinds[0] if kinds else ""


# 已知协议族的设备侧标准端点（确定性填充来源之一；V4 会在设备上复核存在性）
_DESCRIPTOR_ENDPOINTS: dict[str, str] = {
    "hisysevent_eventraw": "/dev/unix/socket/hisysevent",
    "sp_daemon_text": "127.0.0.1:8283",
}


def _infer_endpoint(descriptor_id: str, finding: FindingInput) -> str:
    """端点推断：entry_hints 中显式出现（如 socket 路径/ host:port）优先，
    否则用描述符族的标准端点。"""
    import re as _re
    # unix socket 绝对路径
    for hint in finding.entry_hints:
        m = _re.search(r"(/dev/unix/socket/[\w./-]+)", hint)
        if m:
            return m.group(1)
        m = _re.search(r"(\d+\.\d+\.\d+\.\d+:\d+)", hint)
        if m:
            return m.group(1)
    return _DESCRIPTOR_ENDPOINTS.get(descriptor_id, "")


def _select_route_candidate(initial_hints: list[str], candidates: list[Any]) -> Any | None:
    """把入口候选收窄到当前 finding 的路由切片。

    选择依据按强度排序：Stage1 明确端点 > 唯一候选 > 唯一 direct 候选；
    其它情况必须保持歧义，不能把同服务的其它端点拼进当前攻击链。
    """
    if not candidates:
        return None
    hints = " ".join(str(x).lower() for x in initial_hints)
    # Stage 1 的 endpoint 线索只能缩小传输端点，不能推翻入口发现器对该
    # finding 的 ``unrelated`` 路由判定。否则同一服务的多个端点中，错误的
    # hint 会把与 sink 无关的端点强行投影进契约。
    exact = [
        c for c in candidates
        if str(getattr(c, "endpoint", "")).lower() in hints
        and str(getattr(c, "route_relevance", "unknown")) != "unrelated"
    ]
    if len(exact) == 1:
        return exact[0]
    direct = [c for c in candidates if str(getattr(c, "route_relevance", "unknown")) == "direct"]
    if len(direct) == 1:
        return direct[0]
    if len(candidates) == 1 and str(getattr(candidates[0], "route_relevance", "unknown")) != "unrelated":
        return candidates[0]
    return None


def _route_binding_from_candidate(finding: FindingInput, candidate: Any | None) -> dict[str, Any]:
    if candidate is None:
        return RouteBinding(target_sink=finding.sink, relevance="unknown").to_dict()
    candidate_id = str(getattr(candidate, "candidate_id", ""))
    route = RouteBinding(
        route_id=RouteBinding.make_id(finding.finding_id, candidate_id, finding.sink),
        candidate_id=candidate_id,
        relevance=str(getattr(candidate, "route_relevance", "unknown")),
        handler=str(getattr(candidate, "handler", "")),
        target_sink=str(getattr(candidate, "target_sink", "")) or finding.sink,
        dispatch_conditions=list(getattr(candidate, "dispatch_conditions", []) or []),
        state_flow=list(getattr(candidate, "state_flow", []) or []),
        evidence=list(dict.fromkeys(
            list(getattr(candidate, "source_evidence", []) or [])
            + list(getattr(candidate, "route_evidence", []) or [])
        ))[:24],
        assumptions=[str(getattr(candidate, "reason", ""))] if getattr(candidate, "reason", "") else [],
        missing_evidence=[] if str(getattr(candidate, "route_relevance", "unknown")) in {"direct", "possible"}
        else ["尚未确认入口与目标 sink 的服务端分派关系"],
    )
    return route.to_dict()


def _resolve_source_ref(repo_root: Path, ref: str) -> str | None:
    """源码证据 file:line → 仓库内相对路径；basename 仅唯一命中时接受。"""
    text = str(ref).strip()
    match = re.match(r"^(.*?):\d+(?:-\d+)?$", text)
    raw = match.group(1) if match else text
    path = Path(raw)
    if path.is_absolute() and path.is_file():
        try:
            return path.relative_to(repo_root).as_posix()
        except ValueError:
            return str(path)
    candidate = repo_root / path
    if candidate.is_file():
        return path.as_posix()
    hits = list(repo_root.rglob(path.name)) if path.name else []
    if len(hits) == 1:
        return hits[0].relative_to(repo_root).as_posix()
    return None


def _route_source_paths(finding: FindingInput, candidate: Any | None, repo_root: Path) -> list[str]:
    refs = list(finding.source_paths)
    if candidate is not None:
        refs.extend(getattr(candidate, "source_evidence", []) or [])
        refs.extend(getattr(candidate, "route_evidence", []) or [])
    paths: list[str] = []
    for ref in refs:
        resolved = _resolve_source_ref(repo_root, str(ref))
        if resolved and resolved not in paths:
            paths.append(resolved)
    return paths[:8]


def _try_auto_descriptor(
    finding: FindingInput, candidate: Any | None, repo_root: Path, notes: list[str],
) -> str:
    """为当前 route 生成并注册通用描述符；失败返回空字符串交给既有库。"""
    if candidate is None or str(getattr(candidate, "route_relevance", "unknown")) not in {"direct", "possible"}:
        return ""
    source_paths = _route_source_paths(finding, candidate, repo_root)
    if not source_paths:
        notes.append("自动协议描述符跳过：当前路由没有可读取源码证据")
        return ""
    try:
        from .descriptor_synthesizer import synthesize_descriptor  # noqa: PLC0415

        route = _route_binding_from_candidate(finding, candidate)
        material = json.dumps({"route": route, "sources": source_paths}, ensure_ascii=False, sort_keys=True)
        descriptor_id = "auto_" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]
        result = synthesize_descriptor(
            source_paths, repo_root=str(repo_root), route_context=route,
            descriptor_id_override=descriptor_id, auto_approve=True,
        )
        if result.status == "APPROVED" and result.descriptor is not None:
            register(result.descriptor)
            notes.append(
                f"路由协议描述符自动生成并注册: {descriptor_id} "
                f"encoder={result.descriptor.encoder_kind} sources={len(source_paths)}"
            )
            return descriptor_id
        notes.append(f"自动协议描述符未通过: {result.status} {result.errors[:2]}")
    except Exception as exc:  # noqa: BLE001 — 自动发现失败时保留既有描述符回退
        notes.append(f"自动协议描述符异常，回退既有库: {type(exc).__name__}: {str(exc)[:180]}")
    return ""


def _load_exemplar(vuln_class: str, finding_id: str = "") -> dict[str, Any] | None:
    """加载同 vuln_class 的手写固件契约作为 few-shot 攻击链形状参考。

    匹配优先级：① finding_id 精确同名固件（如 HV-06 → HV-05.json 不匹配但
    GEN-HV-06 这类"同类相邻编号"场景由 ② 兜底）；② vuln_class → ref 表；
    ③ 自动晋升库（exemplars/auto/——全自动化收敛 P0-2：CONFIRMED 契约自动
    晋升，每类钉死第一代不可变）。
    ①② 在手写静态库（contracts/*.json）里找，③ 在自动晋升库找——都不是
    硬编码语义答案，而是展示"一条完整攻击链的契约长什么样"；LLM 的具体值
    仍须侦查查证。

    ② 的必要性实证（run 376c13e2）：adapter 把 FreezeManager 案例归类为
    information_disclosure（上轮为 path_traversal）——归类漂移是 LLM 语义
    判断的正常波动，但漂移后 exemplar 缺失导致草案丢掉双路径结构（链路
    走不通）。因此 information_disclosure 与 path_traversal 共享 ref=HV-05。
    """
    ref = _VULNCLASS_ORACLE.get(vuln_class, {}).get("ref")
    if ref:
        path = _COMPILED_DIR.parent / f"{ref}.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
    # ③ 自动晋升库：同 vuln_class 的第一代 CONFIRMED 契约（不可变，防逐代漂移）
    auto = _AUTO_EXEMPLAR_DIR / f"{vuln_class}.json"
    if auto.exists():
        try:
            return json.loads(auto.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return None


# 自动晋升库（P0-2）：CONFIRMED 契约按 vuln_class 沉淀，第一代不可变。
_AUTO_EXEMPLAR_DIR = _COMPILED_DIR / "exemplars" / "auto"


def promote_exemplar_if_absent(contract: Contract, verdict_status: str) -> str:
    """CONFIRMED 契约自动晋升为该 vuln_class exemplar（P0-2）。

    只在【该类还没有 exemplar】时写入（第一代钉死）——后续 CONFIRMED 不再
    覆盖，防止把逐代漂移固化进 few-shot 参考。写入失败静默（晋升是增强，
    不影响主流程）。返回 "promoted" / "already" / "skipped:<原因>"。
    """
    if verdict_status != "CONFIRMED":
        return "skipped:非 CONFIRMED"
    vc = contract.vuln_class
    if not vc:
        return "skipped:无 vuln_class"
    try:
        _AUTO_EXEMPLAR_DIR.mkdir(parents=True, exist_ok=True)
        out = _AUTO_EXEMPLAR_DIR / f"{vc}.json"
        if out.exists():
            return "already"
        data = contract.to_dict()
        data["_exemplar_meta"] = {
            "source": "auto-promotion(P0-2)",
            "contract_id": contract.contract_id,
            "promoted_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
            "note": "该类首个真机 CONFIRMED 契约，作为 L2 few-shot 攻击链形状参考；不可变（防逐代漂移）",
        }
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return "promoted"
    except OSError as exc:
        return f"skipped:{exc}"


def _deterministic_skeleton(
    finding: FindingInput, descriptor_id: str, candidate: Any | None = None,
) -> dict[str, Any]:
    """确定性可推导块的填充（方案 §3.2 表）。"""
    entry_kind = str(getattr(candidate, "kind", "")) if candidate is not None else ""
    entry_kind = entry_kind or _infer_entry_kind(descriptor_id, finding)
    identity = _ENTRY_IDENTITY.get(entry_kind, ("root_su", "root_su", "C"))
    endpoint = str(getattr(candidate, "endpoint", "")) if candidate is not None else ""
    try:
        descriptor_snapshot = get_descriptor(descriptor_id).to_dict()
    except KeyError:
        descriptor_snapshot = {}
    return {
        "contract_id": f"GEN-{finding.finding_id}",
        "finding_ids": [finding.finding_id],
        "unit_id": finding.unit_id,
        "vuln_class": finding.vuln_class,
        "description": finding.description,
        "entry": {
            "kind": entry_kind,
            "endpoint": endpoint or _infer_endpoint(descriptor_id, finding),
            "reachability_identity": identity[0],
        },
        "identity": {
            "execution_identity": identity[0],
            "identity_ladder_fallback": identity[1],
            "max_evidence_grade": identity[2],
        },
        "protocol": {"descriptor_id": descriptor_id, "descriptor_snapshot": descriptor_snapshot},
        "route_binding": _route_binding_from_candidate(finding, candidate),
        "risk": {"target_process": _target_process(finding), "risk_tier": "unknown"},
    }


def _target_process(finding: FindingInput) -> str:
    """从 sink 描述提取目标进程名（e.g. 'SP_daemon Network.cpp:153 popen(...)'）。"""
    sink = finding.sink
    for token in sink.replace("(", " ").replace(")", " ").split():
        if token and token[0].isupper() and token not in ("Network",):
            return token
    return sink.split()[0] if sink else "unknown"


# ---------------------------------------------------------------------------
# 编译主流程
# ---------------------------------------------------------------------------

def compile_contract(finding: FindingInput, *, hdc=None,
                     device_facts=None, on_event=None) -> CompileResult:
    """FindingInput → candidate contract（侦查 loop 起草 + 确定性填充 + 硬校验）。

    v2：LLM 起草由侦查 agent loop（§9）替代单轮盲写——LLM 可读源码、grep、
    跑只读 hdc 命令实测设备事实，再 finalize 草案；事实卡随草案提交。
    device_facts 可注入（§11.3 事实库，缺省按设备 serial 加载）。
    on_event：可选进度回调，透传给侦查 loop（recon_turn 事件）。
    """
    notes: list[str] = []

    # 2. vuln_class → oracle 映射（未实现 → ORACLE_UNAVAILABLE，诚实降级）
    oracle_map = _VULNCLASS_ORACLE.get(finding.vuln_class)
    if oracle_map is None:
        return CompileResult(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"V1: 未知 vuln_class: {finding.vuln_class}"],
        )
    if not oracle_map.get("impl"):
        return CompileResult(
            contract=None, compile_status="ORACLE_UNAVAILABLE",
            errors=[f"预言机未实现（方案 §3.3 诚实降级）: {oracle_map['reason']}"],
        )

    # 1b. 外部入口发现（必须位于描述符匹配之前）。
    # Stage1 的 entry_hints 只是候选线索；入口发现 loop 可以读取源码和设备
    # 只读事实，补充 hap_udp/unix_dgram/event_bus 等候选，然后再选择协议族。
    # 没有 LLM 时保留已有 hints，不做无依据猜测。
    entry_discovery_data: dict[str, Any] = {}
    initial_entry_hints = list(finding.entry_hints)
    selected_route_candidate: Any | None = None
    binding_pair = _llm_binding()
    if binding_pair is not None:
        from .agent.entry_discovery_loop import run_entry_discovery_loop  # noqa: PLC0415

        entry_root = Path(finding.repo_root) if finding.repo_root else Path(".")
        entry_result = run_entry_discovery_loop(
            finding=finding, repo_root=entry_root, hdc=hdc,
            binding_pair=binding_pair, on_event=on_event,
        )
        entry_discovery_data = entry_result.to_dict()
        notes.append(
            f"入口发现 loop: {entry_result.status} turns={entry_result.turns_used} "
            f"device_cmds={entry_result.device_commands_used} "
            f"candidates={len(entry_result.candidates)}"
        )
        for candidate in entry_result.candidates:
            if candidate.hint not in finding.entry_hints:
                finding.entry_hints.append(candidate.hint)
        selected_route_candidate = _select_route_candidate(
            initial_entry_hints, list(entry_result.candidates),
        )
        if selected_route_candidate is not None:
            entry_discovery_data["selected_candidate_id"] = str(
                getattr(selected_route_candidate, "candidate_id", "")
            )
            entry_discovery_data["selected_route_binding"] = _route_binding_from_candidate(
                finding, selected_route_candidate,
            )
        # 一个漏洞 finding 可能对应同一服务的多个端点（例如 SP_daemon 的
        # 8283/8284/8285）。入口发现应保留全部候选供审计，但协议契约一次只
        # 能发送一个 endpoint；没有 Stage1 明确端点时禁止按列表首项静默选择。
        if (not initial_entry_hints
                and len({c.hint for c in entry_result.candidates}) > 1
                and selected_route_candidate is None):
            notes.append("入口候选存在歧义：保留全部候选，未自动选择 endpoint")
            return CompileResult(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[
                    "入口发现得到多个可验证端点，当前契约一次只能选择一个；"
                    "请依据调用路径或用户目标选择 endpoint（候选已保留在 entry_discovery）"
                ],
                llm_used=True, notes=notes, entry_discovery=entry_discovery_data,
            )
    else:
        notes.append("入口发现 loop 未运行：LLM 基础设施不可用，保留 Stage1 已有入口线索")

    # 1c. 描述符命中（未命中 → REQUIRES_PROTOCOL_REVIEW，指向描述符合成器）
    repo_root = Path(finding.repo_root) if finding.repo_root else Path(".")
    descriptor_id = _try_auto_descriptor(
        finding, selected_route_candidate, repo_root, notes,
    ) or _match_descriptor(finding)
    if not descriptor_id:
        return CompileResult(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=["描述符库未命中：无已知协议族匹配 entry_hints/sink；需描述符合成器（方案 §6）"],
            entry_discovery=entry_discovery_data,
        )
    notes.append(f"描述符命中: {descriptor_id}")

    # 3. 确定性骨架
    skeleton = _deterministic_skeleton(finding, descriptor_id, selected_route_candidate)

    # 4. 侦查 agent loop（§9）：LLM 自主查证（读源码/grep/hdc 只读探测）→ finalize 草案
    llm_used = False
    recon_facts: dict[str, Any] = {}   # 侦查 finalize 提交的事实卡（§11.2 复核输入）
    facts_store = None                 # §11.3 设备事实库（复核通过后升级 source）
    if binding_pair is not None:
        llm_used = True
        from .agent.device_facts import DeviceFacts  # noqa: PLC0415
        from .agent.recon_loop import run_recon_loop  # noqa: PLC0415

        serial = ""
        if hdc is not None:
            serial = str(getattr(hdc, "serial", "") or "")
        facts = device_facts
        if facts is None and serial:
            try:
                facts = DeviceFacts(serial)
            except Exception:  # noqa: BLE001 — 事实库不可读不影响编译
                facts = None
        recon = run_recon_loop(
            finding=finding, skeleton=skeleton,
            descriptor_dict=get_descriptor(descriptor_id).to_dict(),
            repo_root=Path(finding.repo_root) if finding.repo_root else Path("."),
            hdc=hdc, binding_pair=binding_pair, device_facts=facts,
            oracle_forms=_VULNCLASS_ORACLE.get(finding.vuln_class, {}).get("forms", []),
            exemplar_contract=_load_exemplar(finding.vuln_class),
            on_event=on_event,
        )
        notes.append(f"侦查 loop: {recon.status} turns={recon.turns_used} "
                     f"device_cmds={recon.device_commands_used} notes={len(recon.notes)}")
        notes.extend(f"recon-note: {n}" for n in recon.notes)
        if recon.status != "finalized":
            return CompileResult(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[f"侦查 loop 未产出草案（{recon.status}）: {recon.error}"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        draft = _merge_recon_draft(recon.draft, finding, skeleton)
        recon_facts = {str(k): v for k, v in recon.facts.items()} if isinstance(recon.facts, dict) else {}
        # 事实卡沉淀（§11.3）：侦查声称的事实带 source=llm-recon 入库；
        # 校验通过后由调用方复核升级 validator-verified。
        # 【insufficient 不入库】申报"证据不足"的 run，其事实卡往往围绕一个盯错的
        # sink 展开（82fe/979a 实测：错误结论"path 不可控"入库后污染后续侦查，
        # 形成假否定自我强化循环）——只沉淀成功起草的事实。
        draft_is_insufficient = isinstance(draft, dict) and "insufficient" in draft
        if facts is not None and not draft_is_insufficient:
            facts_store = facts
            for fkey, fval in recon.facts.items():
                try:
                    facts.put(str(fkey)[:64], fval, source="llm-recon",
                              evidence=f"recon {recon.turns_used}轮")
                except (TypeError, ValueError):
                    continue
        if draft is None:
            return CompileResult(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=["LLM 起草输出不合法（非 JSON / 结构不符 / insufficient）"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        if "insufficient" in draft:
            return CompileResult(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[f"LLM 起草声明证据不足: {draft['insufficient']}"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        # fault/cleanup 缺省兜底（LLM 草案可能省略 fault 块整体或 fault.operator）
        merged_draft = {k: v for k, v in draft.items() if k in ("protocol", "oracle", "fault", "cleanup")}
        fault = dict(merged_draft.get("fault") or {})
        fault.setdefault("operator", "payload_value_substitution")
        fault.setdefault("description", finding.description)
        # FaultSpec 只认 4 键：LLM 发明的键（kind/name/type 等）剥掉
        for extra in list(fault.keys()):
            if extra not in ("operator", "description", "evidence", "expected_guards"):
                fault.pop(extra)
        merged_draft["fault"] = fault
        merged_draft.setdefault("cleanup", {"remote_paths": ["__RUN_DIR__"]})
        skeleton.update(merged_draft)
    else:
        notes.append("LLM 基础设施不可用：仅确定性骨架，预期校验失败（field_values/forms 缺失）")

    # 5. 硬校验（§4 全表）
    try:
        contract = contract_from_dict(skeleton)
    except Exception as exc:  # noqa: BLE001 — 草案结构非法
        return CompileResult(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"草案结构非法: {type(exc).__name__}: {exc}"],
            descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
            entry_discovery=entry_discovery_data,
        )
    errors = validate_contract(contract, hdc=hdc)
    if errors:
        apply_compile_gate(contract, errors)
        return CompileResult(
            contract=contract, compile_status=contract.compile_status,
            errors=errors, descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
            entry_discovery=entry_discovery_data,
        )

    # 5b. 事实卡抽样复核（§11.2）：侦查声称「实测」的可复核事实重跑只读命令核对。
    # 不一致 → REQUIRES_PROTOCOL_REVIEW（防编造侦查结果）；一致 → 升级 validator-verified。
    if recon_facts:
        from .contract_validator import verify_fact_card  # noqa: PLC0415

        verified_keys, fact_failures = verify_fact_card(recon_facts, hdc=hdc)
        if verified_keys:
            notes.append(f"事实卡复核通过 {len(verified_keys)} 条: {sorted(verified_keys)}")
            if facts_store is not None:
                for key in verified_keys:
                    item = facts_store.get_item(key)
                    if item is not None and item.get("source") == "llm-recon":
                        facts_store.put(key, item["value"], source="validator-verified",
                                        evidence="§11.2 抽样重跑一致")
        if fact_failures:
            apply_compile_gate(contract, [f"事实卡复核未过: {f}" for f in fact_failures])
            return CompileResult(
                contract=contract, compile_status=contract.compile_status,
                errors=[f"事实卡复核未过（§11.2 防编造）: {f}" for f in fact_failures],
                descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
                entry_discovery=entry_discovery_data,
            )
    contract.compile_status = "ELIGIBLE"

    # 6. 落盘 contracts/generated/（与手写固件隔离）
    _persist(contract)
    return CompileResult(contract=contract, compile_status="ELIGIBLE",
                          descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
                          entry_discovery=entry_discovery_data)


def _merge_recon_draft(draft: dict[str, Any], finding: FindingInput,
                       skeleton: dict[str, Any]) -> dict[str, Any] | None:
    """侦查草案 → 可合并形态（形状规整 + 安全兜底，不做语义覆盖）。

    与 v1 单轮盲写的差异：field_values / hilog tag 等语义内容由 LLM 侦查后
    自主填写（事实卡可追溯、校验器复核），本函数只做**形状与安全**兜底：
    - 扁平点号键归位、window 标量规整、ArtifactForm 多余键剥离
    - refutation / cleanup / content_contains 缺省（V7 必填项）
    - src_file_dir 非法形态回退描述符族缺省提示（§9.3 降级为提示，非强制）
    - 描述性文字值剔除（「推测：…」不是可执行值，留给 V8/hard-validate 打回或
      finalize 时 insufficient——见系统提示词第 5 条）
    """
    # 兼容：LLM 有时输出 "protocol.field_values" 式扁平键 → 归位到嵌套块
    _flatten_dotted_blocks(draft)
    # 兼容：hilog_expectations 的 window 可能给标量秒数 → 规整为 {"seconds": n}
    _normalize_draft_shapes(draft)
    if "insufficient" in draft:
        return {"insufficient": draft["insufficient"]}
    merged: dict[str, Any] = {}
    for key in ("protocol", "oracle", "fault"):
        if key in draft and isinstance(draft[key], dict):
            merged[key] = draft[key]
    if "protocol" in merged:
        protocol = merged["protocol"]
        protocol["descriptor_id"] = skeleton["protocol"]["descriptor_id"]
        if skeleton["protocol"].get("descriptor_snapshot"):
            protocol["descriptor_snapshot"] = skeleton["protocol"]["descriptor_snapshot"]
        # 描述性文字值剔除（「推测：…」「需按设备填写」不是可执行值）：
        # field_values 保留真实字面量或受支持占位符；param_space 保留占位符/字面量
        _strip_descriptive_values(protocol.get("field_values"))
        _strip_descriptive_values(protocol.get("param_space"))
        # HAP 传输必填槽位（mode/host/port）：transport.build 硬性要求——LLM 草案
        # 若放 param_space（非线路字段语义）或省略，归位/回填 field_values
        if skeleton["entry"]["kind"] in ("hap_udp", "hap_tcp"):
            fv = protocol.setdefault("field_values", {})
            ps_hap = protocol.get("param_space") or {}
            for slot, default in (("mode", "udp"), ("host", "127.0.0.1"), ("port", 8283)):
                if slot not in fv:
                    val = ps_hap.get(slot, default)
                    if slot == "port":
                        try:
                            val = int(val)
                        except (TypeError, ValueError):
                            val = default
                    fv[slot] = val
        # param_space 里的发送序列键归位到 protocol（runner 从 protocol.frame_sequence 读）；
        # 顺序保持：frame_sequence 按帧号排序还原
        ps2 = protocol.get("param_space")
        if isinstance(ps2, dict):
            if "frame_sequence" in ps2 and not protocol.get("frame_sequence"):
                seq_val = ps2.pop("frame_sequence")
                if isinstance(seq_val, list):
                    protocol["frame_sequence"] = [str(k) for k in seq_val]
                elif isinstance(seq_val, str) and seq_val:
                    protocol["frame_sequence"] = [s.strip() for s in seq_val.split(",") if s.strip()]
            if "inter_frame_delay_seconds" in ps2:
                try:
                    protocol.setdefault("inter_frame_delay_seconds",
                                        float(ps2.pop("inter_frame_delay_seconds")))
                except (TypeError, ValueError):
                    ps2.pop("inter_frame_delay_seconds", None)
            if "frame_sequence" in protocol and not ps2.get("frame_first") and not ps2.get("frame_second"):
                # runner 按 frame_sequence 键名取 params["frame_first"/"frame_second"]，
                # 键存在性由 _resolve_params 保证；param_space 键名保留原样即可
                pass
        ps = protocol.get("param_space")
        if isinstance(ps, dict):
            # preplant 归一：LLM 可能给 [{"path": ...}] 形态 → 提取 path
            pre = ps.get("preplant")
            if isinstance(pre, list):
                pre = [
                    item["path"] if isinstance(item, dict) and "path" in item else item
                    for item in pre
                    if (isinstance(item, str) and item) or (isinstance(item, dict) and item.get("path"))
                ]
                # 【冲突剔除】preplant 与 oracle exfil form path 冲突：runner 先按
                # oracle form 预埋（内容=run_pattern，判定 needle），再按 preplant
                # 预埋（内容=vf-dep- 良性标记），后者会**覆盖**前者 → 输出面只剩
                # vf-dep 内容 → exfil 永远 miss（run 0891cac5/f29414f8 实测假阴性）。
                # 占位符在 merge 层尚未展开（oracle path=__CPU_FILE__ vs preplant
                # 具体路径不相交），真正的剔除在 runner._resolve_params 展开后做
                # （oracle_paths vs 已展开 preplant 具体值）；此处只剔除**字面相等**的
                # 重复项（LLM 直接抄具体路径的场景）。
                oracle_paths = {
                    str(f.get("path")) for f in (merged.get("oracle", {}) or {}).get("artifact_forms", [])
                    if isinstance(f, dict) and f.get("form") == "exfil" and f.get("path")
                }
                pre = [p for p in pre if p not in oracle_paths]
                ps["preplant"] = pre
            # src_file_dir 非法形态（占位符拼接/相对路径）→ 族缺省提示回退
            if "src_file_dir" in ps:
                sfd = ps.get("src_file_dir")
                is_clean_dir = (
                    isinstance(sfd, str) and sfd.startswith("/") and "__" not in sfd
                )
                if not is_clean_dir:
                    standard = _DESCRIPTOR_SRC_DIRS.get(skeleton["protocol"]["descriptor_id"], "")
                    if standard:
                        ps["src_file_dir"] = standard
                    else:
                        ps.pop("src_file_dir", None)
    if "oracle" in merged:
        oracle = merged["oracle"]
        oracle.setdefault("kind", "artifact_differential")
        # 标准否证集（V7 必填，可推导项）
        oracle.setdefault("refutation", list(_DEFAULT_REFUTATION))
        for f in oracle.get("artifact_forms") or []:
            if not isinstance(f, dict):
                continue
            # ArtifactForm 只认 5 个键：LLM 发明的键剥掉，content → content_contains
            if "content" in f and "content_contains" not in f:
                f["content_contains"] = f.pop("content")
            for extra in list(f.keys()):
                if extra not in ("form", "path", "content_contains", "output_surface", "output_is_dir"):
                    f.pop(extra)
            if f.get("form") == "exfil":
                # output_surface 需为真实目录（surface 扫描对象）：空/占位符拼接 → 族缺省提示
                surface = str(f.get("output_surface") or "")
                if not surface or "__" in surface:
                    standard = _DESCRIPTOR_SURFACES.get(skeleton["protocol"]["descriptor_id"], "")
                    if standard:
                        f["output_surface"] = standard
                # 预埋内容 = run 唯一图案（缺了 plant 会拒绝）
                if not f.get("content_contains"):
                    f["content_contains"] = "__RUN_PATTERN__"
            # path 非 LLM 可发明项：必须是受支持占位符（runner 映射表展开）
            declared = {d["form"]: d for d in _VULNCLASS_ORACLE.get(finding.vuln_class, {}).get("forms", [])}
            d = declared.get(f.get("form"))
            if d and d.get("path") and not str(f.get("path", "")).startswith("__"):
                f["path"] = d["path"]
    # cleanup 缺省：run_dir 兜底
    merged.setdefault("cleanup", {"remote_paths": ["__RUN_DIR__"]})
    return merged or None


# ---------------------------------------------------------------------------
# 降级闭环重试（全自动化收敛 P0-1）：编译降级按缺口签名自动重跑一次 fresh
# 侦查 session。依据：L2 是有预算的探索循环，降级常因侦查运气（预算耗尽在
# 关键查证之前/单轮输出非法连击），换一个 fresh session 再试一次常自愈——
# 与 LLM 调用重试（连续 2 轮异常）同一哲学，但作用于整场侦查层。
# 同一缺口签名独立失败超限 → 收敛为 final-failure 短路（防无限烧配额）。
# ---------------------------------------------------------------------------

_FACT_CARD_FAIL_SIGNATURE = "事实卡复核未过"


def compile_gap_signature(compile_status: str, errors: list) -> str:
    """编译降级 → 缺口签名（确定性聚类键）。

    签名 = compile_status + 首个错误的规整化形态。错误文本含 run 特异内容
    （路径/轮数），剥离后同根因失败落到同一签名。
    """
    if not errors:
        return f"{compile_status}|unknown"
    import re as _re

    normalized = _re.sub(r"/[\w./\-]+", "<path>", str(errors[0]))
    normalized = _re.sub(r"\d+", "N", normalized)
    return f"{compile_status}|{normalized[:120]}"


def compile_contract_with_retry(finding, *, hdc=None, device_facts=None,
                                on_event=None, max_attempts: int = 2,
                                failure_log=None) -> CompileResult:
    """compile_contract 的闭环重试包装（P0-1）。

    - 首次 REQUIRES_PROTOCOL_REVIEW → 换 fresh session 重跑一次（新侦查 loop
      自带空 transcript/notes；device_facts 持久资产原样传入）；
    - 事实卡复核不一致**不重试**（模型在编造，重试只会再编一次）；
    - ORACLE_UNAVAILABLE / 描述符未命中是结构性缺口，重试无用；
    - 同一签名独立失败 > max_attempts 次 → 收敛 final-failure 短路（failure_log
      由调用方持有跨 run 传递）。
    """
    result = compile_contract(finding, hdc=hdc, device_facts=device_facts, on_event=on_event)
    if result.compile_status == "ELIGIBLE":
        return result

    status = result.compile_status
    if status == "ORACLE_UNAVAILABLE":
        return result
    if any("描述符库未命中" in e for e in result.errors):
        return result
    # 入口发现明确找到了多个可验证端点时，不能通过 fresh-session 重试绕过
    # 歧义闸门：第一次编译已把候选写回 finding.entry_hints，若继续重试，
    # 旧逻辑会把首个候选误当成 Stage 1 原始提示并静默选中它。
    if any("多个可验证端点" in e for e in result.errors):
        return result
    if any(_FACT_CARD_FAIL_SIGNATURE in e for e in result.errors):
        return result
    if status != "REQUIRES_PROTOCOL_REVIEW":
        return result

    sig = compile_gap_signature(status, result.errors)
    if failure_log is not None:
        count = int(failure_log.get(sig, 0)) + 1
        failure_log[sig] = count
        if count > max_attempts:
            if on_event is not None:
                try:
                    on_event({"event": "phase_note",
                              "detail": f"缺口签名 {sig[:80]} 独立失败 {count} 次 → 收敛 final-failure"})
                except Exception:  # noqa: BLE001
                    pass
            return CompileResult(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[f"final-failure（签名 {sig}，独立失败 {count} 次，已收敛）"],
                llm_used=True, notes=result.notes,
            )

    if on_event is not None:
        try:
            on_event({"event": "phase_note",
                      "detail": f"侦查降级（{result.errors[0][:80]}）→ fresh session 重试 1 次"})
        except Exception:  # noqa: BLE001
            pass
    retry_result = compile_contract(finding, hdc=hdc, device_facts=device_facts, on_event=on_event)
    if retry_result.compile_status == "ELIGIBLE":
        retry_result.notes.append("P0-1: 首场侦查降级，fresh session 重试自愈")
    return retry_result


def _persist(contract: Contract) -> None:
    _COMPILED_DIR.mkdir(parents=True, exist_ok=True)
    out = _COMPILED_DIR / f"{contract.contract_id}.json"
    out.write_text(json.dumps(contract.to_dict(), ensure_ascii=False, indent=2),
                   encoding="utf-8")


def _flatten_dotted_blocks(draft: dict[str, Any]) -> None:
    """把 "protocol.field_values" 式扁平键归位到嵌套块（LLM 输出形态兼容）。"""
    for dotted in list(draft.keys()):
        if "." not in dotted:
            continue
        block, _, sub = dotted.partition(".")
        if block not in ("protocol", "oracle", "fault", "cleanup"):
            continue
        nested = draft.setdefault(block, {})
        if isinstance(nested, dict) and sub not in nested:
            nested[sub] = draft.pop(dotted)


# 描述性文字值的特征：冒号引导的解释句、明确的推测措辞（见系统提示词第 5 条）
_DESC_VALUE_RE = re.compile(r"推测|需按|待定|待查|unknown|TBD|描述性", re.IGNORECASE)


def _strip_descriptive_values(obj: Any) -> None:
    """剔除描述性文字值：field_values/param_space 里出现「推测：…」类值时删除该键。

    这些值不是可执行载荷（发送出去不会触发任何路径），删掉比留着强：
    缺关键值时 V3/试跑会诚实暴露缺口，而不是静默发送无效报文。
    """
    if not isinstance(obj, dict):
        return
    for key in list(obj.keys()):
        vals = obj[key] if isinstance(obj[key], list) else [obj[key]]
        vals = [v for v in vals
                if isinstance(v, (int, float)) or "__" in str(v)
                or not _DESC_VALUE_RE.search(str(v))]
        if not vals:
            obj.pop(key)
        elif isinstance(obj[key], list):
            obj[key] = vals
        else:
            obj[key] = vals[0]


def _normalize_draft_shapes(draft: dict[str, Any]) -> None:
    """草案形状规整：window 标量 → {"seconds": n}；非法 output_surface 修正；
    描述性文字值（「推测：…」）剔除——不是可执行值，只能由真实查证值替代。"""
    oracle = draft.get("oracle")
    if not isinstance(oracle, dict):
        return
    expects = oracle.get("hilog_expectations")
    if isinstance(expects, list):
        cleaned = []
        for e in expects:
            if isinstance(e, dict) and isinstance(e.get("window"), (int, float)):
                e["window"] = {"seconds": e["window"]}
            # hilog_expectations 必须是 {tag, patterns} 形态：字符串形态剥掉
            if isinstance(e, dict) and e.get("tag"):
                cleaned.append(e)
        oracle["hilog_expectations"] = cleaned
    forms = oracle.get("artifact_forms")
    if isinstance(forms, list):
        for f in forms:
            if isinstance(f, dict) and f.get("form") == "exfil":
                surface = f.get("output_surface", "")
                # 含占位符或非目录形态的 output_surface 无法做 surface 扫描 → 置空走默认
                if not surface.startswith("/"):
                    f.pop("output_surface", None)
