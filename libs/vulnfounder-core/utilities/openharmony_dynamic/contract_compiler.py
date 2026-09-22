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

from .contract_validator import (
    apply_compile_gate,
    normalize_marker_path_placeholders,
    validate_contract,
)
from .contracts.registry import contract_from_dict
from .finding_input import FindingInput
from .models import Contract, RouteBinding
from .protocols import get_descriptor, register

# ---------------------------------------------------------------------------
# §3.3 漏洞类 → 预言机映射（确定性表；未实现的预言机诚实降级）
# 预言机类型由漏洞类别驱动；每种类型仍须由设备 before/during/after 观测
# 实例化，不能把“已声明”误认为“已确认”。
# ---------------------------------------------------------------------------

_VULNCLASS_ORACLE: dict[str, dict[str, Any]] = {
    "command_injection": {
        "forms": [{
            "form": "create",
            "path": "__MARKER__",
            "content_note": "注入命令的字面输出",
            "output_is_dir": False,
        }],
        "impl": True,
        "ref": "DP-02",
    },
    "arbitrary_file_write": {
        "forms": [{
            "form": "create",
            "path": "__RUN_DIR__/__canary",
            "content_note": "写入内容",
            "output_is_dir": False,
        }],
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
    "permission_bypass": {
        "kind": "permission_differential", "config": {"expected_before": "denied", "expected_after": "allowed"},
        "impl": True, "reason": "需要普通身份与授权身份的对照观测",
    },
    "fd_leak": {
        "kind": "resource_delta", "config": {"metric": "fd_count", "min_delta": 1},
        "impl": True, "reason": "需要重复请求前后的文件描述符快照",
    },
    "resource_exhaustion": {
        "kind": "resource_delta", "config": {"metric": "rss_kb", "min_delta": 1},
        "impl": True, "reason": "需要重复请求前后的资源快照",
    },
    "parcel_check_missing": {
        "kind": "crash_correlated", "config": {"allow_unattributed_crash": False},
        "impl": True, "reason": "需要目标服务存活与 faultlog 关联证据",
    },
    "race_condition": {
        "kind": "state_differential", "config": {"keys": []},
        "impl": True, "reason": "需要重复/并发请求前后的状态差分",
    },
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
    # 描述符来源必须显式可审计：自动合成、内置库回退和未解析不能混成一个
    # descriptor_hit，否则一个使用手写协议的 CONFIRMED 会被误读为自动合成成功。
    descriptor_resolution: dict[str, Any] = field(default_factory=dict)
    # 当前路由源码中提取的协议结构证据；它是候选证据，不等于已批准的
    # descriptor，也不直接决定设备发送帧。
    protocol_evidence: dict[str, Any] = field(default_factory=dict)
    # clean-room 运行标记：用于审计本轮是否禁用了历史 exemplar/设备事实库。
    clean_room: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "compile_status": self.compile_status,
            "errors": list(self.errors),
            "descriptor_hit": self.descriptor_hit,
            "llm_used": self.llm_used,
            "notes": list(self.notes),
            "entry_discovery": dict(self.entry_discovery),
            "descriptor_resolution": dict(self.descriptor_resolution),
            "protocol_evidence": dict(self.protocol_evidence),
            "clean_room": self.clean_room,
            "context_mode": "clean_room" if self.clean_room else "assisted",
            "context_sources": (
                ["current_finding", "current_source_evidence"]
                if self.clean_room else
                ["current_finding", "current_source_evidence", "device_facts", "exemplar"]
            ),
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


def _legal_probe_values(descriptor_snapshot: dict[str, Any]) -> dict[str, Any]:
    """读取并校验描述符中的无害设备自证报文。

    该函数只消费描述符声明的合法探测值，不会从 fault/param_space 读取变异
    载荷，避免自证阶段误执行攻击字符串。
    """
    from .descriptor_synthesizer import _validate_legal_probe  # noqa: PLC0415

    probe = dict(descriptor_snapshot.get("legal_probe") or {})
    errors = _validate_legal_probe(probe)
    if errors:
        raise ValueError("无害合法报文校验失败：" + "; ".join(errors))
    result: dict[str, Any] = {}
    for key in ("mode", "host", "port", "local_path", "first", "second", "third", "payload"):
        if key in probe:
            result[key] = probe[key]
    return result


def _device_endpoint_present(hdc, endpoint: str, mode: str) -> bool:
    """在发送合法探测前确认设备端点仍然存在，避免把发送成功当服务存在。"""
    match = re.match(r"^(?:[^:]+:)?(\d+)$", str(endpoint or ""))
    if not match or mode not in {"udp", "tcp"}:
        return True
    port = int(match.group(1))
    needle = f":{port:04X}".upper()
    table = "udp" if mode == "udp" else "tcp"
    for name in (table, table + "6"):
        rec = hdc.shell(["cat", f"/proc/net/{name}"], purpose=f"descriptor-selftest:{name}")
        if rec.returncode == 0 and needle in (rec.stdout or "").upper():
            return True
    return False


def _run_legal_protocol_self_test(contract: Contract, hdc, notes: list[str]) -> list[str]:
    """自动描述符注册后发送一条无害合法报文，失败则阻止 ELIGIBLE。"""
    snapshot = dict(contract.protocol.descriptor_snapshot or {})
    if not snapshot:
        return ["描述符没有快照，无法执行设备侧合法报文自证"]
    try:
        probe = _legal_probe_values(snapshot)
    except ValueError as exc:
        return [str(exc)]
    mode = str(probe.get("mode", ""))
    endpoint = str(contract.entry.endpoint or "")
    if not _device_endpoint_present(hdc, endpoint, mode):
        return [f"设备端点未监听，未发送合法探测报文: {endpoint}"]
    from .transports.hap import HapTransport  # noqa: PLC0415

    fields = dict(probe)
    selftest_target = f"SELFTEST-{contract.contract_id}"
    # target 同时用于 HAP 日志标识和测试契约名；必须显式带 SELFTEST 前缀，
    # 这样精确日志匹配才能区分本轮合法报文与历史动态测试。
    fields.setdefault("target", selftest_target)
    fields.setdefault("marker", "")
    transport = HapTransport(hdc)
    try:
        # 清空旧日志，随后必须命中本次 SELFTEST contract_id，不能用历史
        # HAP_POC_SENT 让一个没有真正运行的合法报文“自证通过”。
        clear = hdc.shell(["hilog", "-r"], purpose="descriptor-selftest:hilog-clear")
        if clear.returncode != 0:
            return [f"无法清空设备日志，不能排除旧 HAP_POC_SENT：{clear.stderr[:160]}"]
        send = transport.build_and_run(
            fields, contract_id=selftest_target, wait_seconds=2.0,
        )
        if send.reachability != "INPUT_DELIVERED":
            return [f"HAP 合法探测未送达: {send.detail}"]
        # 只查询 HAP POC 自己的 tag，避免设备长期 hilog 积压把本次关键行
        # 截断在 HDCClient 的输出上限之外。
        log = hdc.shell(["hilog", "-x", "-T", "VulnFounderHapPoc"],
                        purpose="descriptor-selftest:hilog")
        expected = f"HAP_POC_SENT {selftest_target}"
        if log.returncode != 0 or expected not in (log.stdout or ""):
            return [f"设备侧未观察到本次 {expected}，自证不能确认报文已发送"]
        notes.append(
            f"自动描述符设备侧合法报文自证通过: endpoint={endpoint} mode={mode} "
            f"frame_keys={[k for k in ('first', 'second', 'third', 'payload') if fields.get(k)]} "
            f"evidence={expected}"
        )
        return []
    except Exception as exc:  # noqa: BLE001 — 自证失败必须显式阻断，不伪造成功
        return [f"设备侧合法报文自证异常: {type(exc).__name__}: {str(exc)[:240]}"]
    finally:
        try:
            transport.cleanup()
        except Exception:
            pass


def _select_route_candidate(initial_hints: list[str], candidates: list[Any]) -> Any | None:
    """把入口候选收窄到当前 finding 的路由切片。

    选择依据按强度排序：Stage1 明确端点 > 唯一候选 > 唯一 direct 候选；
    其它情况必须保持歧义，不能把同服务的其它端点拼进当前攻击链。
    """
    if not candidates:
        return None
    normalized_hints = [str(x).strip().lower() for x in initial_hints if str(x).strip()]
    hints = " ".join(normalized_hints)
    # 优先按完整 hint（传输类型 + endpoint）匹配。只按 endpoint 匹配会把
    # 同一端口上误报的 hap_tcp 与真实 hap_udp 合并成歧义，导致 route_binding
    # 为空，协议侦查随后失去当前 finding 的入口语义。
    exact_hint = [
        c for c in candidates
        if str(getattr(c, "hint", "")).strip().lower() in normalized_hints
        and str(getattr(c, "route_relevance", "unknown")) != "unrelated"
    ]
    if len(exact_hint) == 1:
        return exact_hint[0]
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


def _entry_candidate_to_dict(candidate: Any) -> dict[str, Any]:
    """把入口候选转成审计 JSON；兼容测试/插件提供的轻量候选对象。"""
    converter = getattr(candidate, "to_dict", None)
    if callable(converter):
        try:
            value = converter()
            if isinstance(value, dict):
                return value
        except Exception:  # noqa: BLE001 — 审计序列化失败不应阻断编译
            pass
    if isinstance(candidate, dict):
        return dict(candidate)
    data: dict[str, Any] = {}
    for key in (
        "kind", "endpoint", "hint", "confidence", "source_evidence",
        "device_evidence", "candidate_id", "route_relevance", "handler",
        "target_sink", "dispatch_conditions", "state_flow", "route_evidence",
        "reason",
    ):
        value = getattr(candidate, key, None)
        if value is not None:
            data[key] = value
    return data


def _recover_cached_route_candidate(candidates: list[Any], cached: Any) -> Any | None:
    """从同一次 retry 闭环的候选缓存恢复已选择的路由。

    这里只允许 candidate_id 或完整 hint 命中当前运行刚刚重新发现/合并的
    候选，并拒绝 ``unrelated``。不会跨运行读取设备事实或历史 exemplar。
    """
    if not isinstance(cached, dict):
        return None
    wanted_id = str(cached.get("candidate_id", ""))
    wanted_hint = str(cached.get("hint", "")).strip().lower()
    for candidate in candidates:
        candidate_id = str(getattr(candidate, "candidate_id", ""))
        candidate_hint = str(getattr(candidate, "hint", "")).strip().lower()
        if ((wanted_id and candidate_id == wanted_id) or
                (wanted_hint and candidate_hint == wanted_hint)):
            if str(getattr(candidate, "route_relevance", "unknown")) == "unrelated":
                return None
            return candidate
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
        # 当前 finding 已有的候选攻击链是路由范围证据。将与目标 sink 文件
        # 相同的候选链节点加入协议补证 bundle，使模型能够核对真实的分派、
        # 状态和帧解析；但不把同一目录中其它未关联的业务处理器当作当前
        # route 的协议事实。
        def source_name(ref: Any) -> str:
            # 证据引用既可能是 file.cpp:140-143，也可能是
            # file.cpp:Namespace::Function；两者都以源码文件的第一个冒号
            # 为边界。路径本身仍由 _resolve_source_ref 做严格仓库校验。
            text = str(ref or "").strip()
            return Path(text.split(":", 1)[0]).name if text else ""

        target_names = {
            source_name(ref) for ref in finding.source_paths if str(ref).strip()
        }
        for chain in getattr(finding, "candidate_attack_chains", []) or []:
            if not isinstance(chain, (list, tuple)) or not chain:
                continue
            last = str(chain[-1])
            last_name = source_name(last)
            if last_name in target_names:
                refs.extend(str(node) for node in chain)
    paths: list[str] = []
    for ref in refs:
        resolved = _resolve_source_ref(repo_root, str(ref))
        if resolved and resolved not in paths:
            paths.append(resolved)
    return paths[:8]


def _try_auto_descriptor(
    finding: FindingInput, candidate: Any | None, repo_root: Path, notes: list[str], hdc=None,
    on_event=None, resolution: dict[str, Any] | None = None,
    evidence_out: dict[str, Any] | None = None,
) -> str:
    """为当前 route 生成并注册通用描述符；失败返回空字符串交给既有库。"""
    if candidate is None or str(getattr(candidate, "route_relevance", "unknown")) not in {"direct", "possible"}:
        if resolution is not None:
            resolution.setdefault("auto_attempted", False)
            resolution["skip_reason"] = (
                "没有选中的路由候选" if candidate is None else
                f"路由相关性不满足自动合成准入: {getattr(candidate, 'route_relevance', 'unknown')}"
            )
        notes.append("自动协议描述符跳过：没有可绑定到当前 finding 的路由候选")
        return ""
    if resolution is not None:
        resolution["auto_attempted"] = True
        resolution["candidate_id"] = str(getattr(candidate, "candidate_id", ""))
        resolution["route_relevance"] = str(getattr(candidate, "route_relevance", "unknown"))
    source_paths = _route_source_paths(finding, candidate, repo_root)
    if not source_paths:
        notes.append("自动协议描述符跳过：当前路由没有可读取源码证据")
        return ""
    try:
        from .protocol_evidence import infer_protocol_evidence  # noqa: PLC0415
        from .descriptor_synthesizer import synthesize_descriptor  # noqa: PLC0415

        route = _route_binding_from_candidate(finding, candidate)
        protocol_evidence = infer_protocol_evidence(
            source_paths, repo_root=repo_root, route_context=route,
        ).to_dict()
        if evidence_out is not None:
            evidence_out.update(protocol_evidence)
        if resolution is not None:
            resolution["protocol_evidence_status"] = protocol_evidence.get("status", "insufficient")
            resolution["protocol_evidence_counts"] = dict(protocol_evidence.get("counts") or {})
            resolution["protocol_evidence_missing"] = list(protocol_evidence.get("missing_evidence") or [])
        notes.append(
            "协议源码证据提取："
            f"status={protocol_evidence.get('status', 'insufficient')} "
            f"transport={len(protocol_evidence.get('transport', []))} "
            f"endpoint={len(protocol_evidence.get('endpoints', []))} "
            f"framing={len(protocol_evidence.get('framing', []))} "
            f"dispatch={len(protocol_evidence.get('dispatch', []))}"
        )
        # Agent 看到结构化证据与原始 route 源码引用；不会把正则命中直接
        # 升级成描述符事实，描述符合成器仍负责语义核对和设备侧自证。
        route["protocol_evidence"] = protocol_evidence
        # fresh-session 重试时把上一场确定性失败原因带给描述符补证器；这只是
        # 诊断上下文，不会把失败结论当成协议事实。
        previous_feedback = (getattr(finding, "analysis_context", {}) or {}).get(
            "dynamic_compile_feedback", []
        )
        if previous_feedback:
            route["previous_compile_feedback"] = list(previous_feedback)[-2:]
        # 描述符身份必须表示“当前路由语义”，不能绑定模型每轮临时生成的
        # route_id/candidate_id，也不能因重试顺序变化而漂移。否则同一条路由
        # 的第一次残缺描述符和第二次补全描述符会被视为两个协议，后续校验
        # 可能读到旧快照。仅保留跨重试稳定、且能影响协议/证据的字段；具体
        # 命令值仍由当前 finding 与源码证据决定，不在这里写入样本关键词。
        stable_route = {
            key: route.get(key)
            for key in (
                "relevance",
                "endpoint",
                "handler",
                "target_sink",
                "dispatch_conditions",
                "state_flow",
                "evidence",
                "assumptions",
                "missing_evidence",
            )
            if route.get(key) not in (None, "", [], {})
        }
        material = json.dumps(
            {"route": stable_route, "sources": sorted(set(source_paths))},
            ensure_ascii=False,
            sort_keys=True,
        )
        descriptor_id = "auto_" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]
        result = synthesize_descriptor(
            source_paths, repo_root=str(repo_root), route_context=route,
            descriptor_id_override=descriptor_id, auto_approve=True, hdc=hdc,
            # 描述符补证需要先读命令表/分帧/守卫，再重新 finalize；8 轮在
            # 复杂 C++ 服务上可能刚好耗尽在读证据阶段。这里仍是有界预算，
            # 不改变字段/源码/合法探测的严格校验。
            max_turns=16, on_event=on_event,
        )
        if result.status == "APPROVED" and result.descriptor is not None:
            register(result.descriptor)
            notes.append(
                f"路由协议描述符自动生成并注册: {descriptor_id} "
                f"encoder={result.descriptor.encoder_kind} sources={len(result.evidence_paths)} "
                f"attempts={result.attempts}"
            )
            if resolution is not None:
                resolution.update({
                    "auto_status": "APPROVED",
                    "descriptor_id": descriptor_id,
                    "attempts": result.attempts,
                    "evidence_paths": list(result.evidence_paths),
                })
            return descriptor_id
        if resolution is not None:
            resolution.update({
                "auto_status": str(result.status),
                "errors": list(result.errors[:4]),
                "attempts": result.attempts,
            })
        notes.append(
            f"自动协议描述符未通过: {result.status} {result.errors[:2]} "
            f"attempts={result.attempts} feedback={result.feedback_history[-2:]}"
        )
    except Exception as exc:  # noqa: BLE001 — 自动发现失败时保留既有描述符回退
        if resolution is not None:
            resolution.update({
                "auto_status": "ERROR",
                "errors": [f"{type(exc).__name__}: {str(exc)[:180]}"],
            })
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

def _select_recon_context(*, finding: FindingInput, hdc=None,
                          device_facts=None, clean_room: bool = False):
    """选择侦查上下文。

    ``clean_room`` 是一次运行级隔离开关：忽略调用方传入的历史事实卡，也不
    加载本地设备事实库和 exemplar。这样模型只能依据当前 finding、当前源码
    检索结果及本轮设备探测结果作出判断；本函数本身不写入任何持久事实。
    """
    if clean_room:
        return None, None

    facts = device_facts
    if facts is None and hdc is not None:
        serial = str(getattr(hdc, "serial", "") or "")
        if serial:
            try:
                from .agent.device_facts import DeviceFacts  # noqa: PLC0415

                facts = DeviceFacts(serial)
            except Exception:  # noqa: BLE001 — 历史事实库不可读不影响本轮
                facts = None
    return facts, _load_exemplar(finding.vuln_class)

def compile_contract(finding: FindingInput, *, hdc=None,
                     device_facts=None, on_event=None,
                     clean_room: bool = False,
                     repair_missing_oracle: bool = False,
                     require_auto_descriptor: bool = False) -> CompileResult:
    """FindingInput → candidate contract（侦查 loop 起草 + 确定性填充 + 硬校验）。

    v2：LLM 起草由侦查 agent loop（§9）替代单轮盲写——LLM 可读源码、grep、
    跑只读 hdc 命令实测设备事实，再 finalize 草案；事实卡随草案提交。
    device_facts 可注入（§11.3 事实库，缺省按设备 serial 加载）；clean_room=True
    时强制忽略注入值和本地历史事实库/exemplar，并且不持久化本轮事实卡。
    on_event：可选进度回调，透传给侦查 loop（recon_turn 事件）。
    """
    notes: list[str] = []
    descriptor_resolution: dict[str, Any] = {
        "source": "unresolved",
        "auto_attempted": False,
    }
    protocol_evidence: dict[str, Any] = {}
    if clean_room:
        notes.append("clean-room: 已禁用历史 exemplar 与设备事实库，仅使用当前 finding/源码证据")

    def _result(**kwargs) -> CompileResult:
        kwargs.setdefault("clean_room", clean_room)
        kwargs.setdefault("descriptor_resolution", dict(descriptor_resolution))
        kwargs.setdefault("protocol_evidence", dict(protocol_evidence))
        return CompileResult(**kwargs)

    # 2. vuln_class → oracle 映射（未实现 → ORACLE_UNAVAILABLE，诚实降级）
    oracle_map = _VULNCLASS_ORACLE.get(finding.vuln_class)
    if oracle_map is None:
        return _result(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"V1: 未知 vuln_class: {finding.vuln_class}"],
        )
    if not oracle_map.get("impl"):
        return _result(
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
    # 同一 compile_contract_with_retry 调用内，前一场入口 Agent 已取得的候选
    # 属于当前源码/设备证据，不应因为 fresh session 的模型波动而丢失。该缓存
    # 只存在于本次 FindingInput 内存对象，不写设备事实库，也不跨动态运行复用。
    cached_entry_candidates: list[Any] = []
    current_context = getattr(finding, "analysis_context", None)
    if isinstance(current_context, dict):
        cached_raw = current_context.get("_dynamic_current_run_entry_candidates", [])
        if isinstance(cached_raw, list):
            try:
                from .agent.entry_discovery_loop import EntryCandidate  # noqa: PLC0415

                for raw in cached_raw:
                    if not isinstance(raw, dict):
                        continue
                    cached_entry_candidates.append(EntryCandidate(
                        kind=str(raw.get("kind", "")),
                        endpoint=str(raw.get("endpoint", "")),
                        confidence=str(raw.get("confidence", "low")),
                        source_evidence=list(raw.get("source_evidence") or []),
                        device_evidence=list(raw.get("device_evidence") or []),
                        route_relevance=str(raw.get("route_relevance", "unknown")),
                        handler=str(raw.get("handler", "")),
                        target_sink=str(raw.get("target_sink", "")),
                        dispatch_conditions=list(raw.get("dispatch_conditions") or []),
                        state_flow=list(raw.get("state_flow") or []),
                        route_evidence=list(raw.get("route_evidence") or []),
                        reason=str(raw.get("reason", "")),
                    ))
            except (ImportError, TypeError, ValueError):
                cached_entry_candidates = []
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
        # 保留向后兼容的 entry_hints 可见性：调用方/旧版前端仍能直接看到
        # 入口发现结果。但 retry 包装器会在每次 fresh session 前恢复原始提示，
        # 因而不会把上一轮的多个候选误当作本轮用户指定的端点。
        fresh_candidates = list(entry_result.candidates)
        # 当前场次候选优先；当新 session 无候选、降级为 hint_fallback，或丢失了
        # 已有 handler/dispatch 条件时，合并本次运行早先已经核验的候选。合并
        # 仅使用当前运行内证据，不等同于历史 exemplar/device facts。
        if fresh_candidates:
            try:
                from .agent.entry_discovery_loop import _merge_candidates  # noqa: PLC0415

                merged_candidates = _merge_candidates([*cached_entry_candidates, *fresh_candidates])
            except (ImportError, TypeError, ValueError):
                merged_candidates = fresh_candidates
        else:
            merged_candidates = cached_entry_candidates
        if cached_entry_candidates and merged_candidates != fresh_candidates:
            entry_discovery_data["same_run_candidate_recovery"] = True
            notes.append(
                f"入口候选复用当前运行已核验证据: {len(cached_entry_candidates)} 条"
            )
        # 审计产物必须反映真正参与路由选择的候选集合，而不是只保留本轮
        # fresh session 的（可能为空或降级）列表。否则重试实际上已经恢复
        # 了入口证据，前端/报告却仍会显示“只有 fallback 候选”。
        entry_discovery_data["candidates"] = [
            _entry_candidate_to_dict(candidate) for candidate in merged_candidates
        ]
        entry_discovery_data["candidate_count"] = len(merged_candidates)
        for candidate in merged_candidates:
            hint = str(getattr(candidate, "hint", "")).strip()
            if hint and hint not in finding.entry_hints:
                finding.entry_hints.append(hint)
        selected_route_candidate = _select_route_candidate(
            initial_entry_hints, merged_candidates,
        )
        # fresh session 可能只重新发现一个候选，而当前运行缓存中保留了其余
        # 候选。若仅依赖本轮 fresh 列表，原本明确的 Stage1 端点会在重试中
        # 变成 selected=null，随后自动描述符被跳过并静默落到内置描述符。
        # 先按当前运行内稳定 candidate_id，再按完整 hint 恢复选择；不读取
        # 跨运行事实，因此不会破坏 clean-room 隔离。
        if selected_route_candidate is None and isinstance(current_context, dict):
            cached_selected = current_context.get("_dynamic_current_run_selected_candidate")
            recovered = _recover_cached_route_candidate(merged_candidates, cached_selected)
            if recovered is not None:
                selected_route_candidate = recovered
                entry_discovery_data["selected_candidate_recovered"] = True
                notes.append(
                    "当前运行重试恢复已选路由候选: "
                    f"{getattr(recovered, 'candidate_id', '') or getattr(recovered, 'hint', '')}"
                )
        if isinstance(current_context, dict) and merged_candidates:
            current_context["_dynamic_current_run_entry_candidates"] = [
                _entry_candidate_to_dict(candidate) for candidate in merged_candidates
            ]
        if selected_route_candidate is not None:
            if isinstance(current_context, dict):
                current_context["_dynamic_current_run_selected_candidate"] = (
                    _entry_candidate_to_dict(selected_route_candidate)
                )
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
                and len({c.hint for c in merged_candidates}) > 1
                and selected_route_candidate is None):
            notes.append("入口候选存在歧义：保留全部候选，未自动选择 endpoint")
            return _result(
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
    auto_descriptor_id = _try_auto_descriptor(
        finding, selected_route_candidate, repo_root, notes, hdc=hdc,
        on_event=on_event, resolution=descriptor_resolution,
        evidence_out=protocol_evidence,
    )
    if auto_descriptor_id:
        descriptor_id = auto_descriptor_id
        descriptor_resolution["source"] = "auto_generated"
    else:
        descriptor_id = _match_descriptor(finding)
        if descriptor_id:
            descriptor_resolution.update({
                "source": "library_fallback",
                "fallback_descriptor_id": descriptor_id,
            })
            if descriptor_resolution.get("auto_attempted"):
                notes.append(
                    f"自动协议描述符未被采用，显式回退内置描述符: {descriptor_id}"
                )
            else:
                notes.append(f"未执行自动协议描述符，使用内置描述符: {descriptor_id}")
    if not descriptor_id:
        return _result(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=["描述符库未命中：无已知协议族匹配 entry_hints/sink；需描述符合成器（方案 §6）"],
            entry_discovery=entry_discovery_data,
        )
    notes.append(f"描述符命中: {descriptor_id}")

    # clean-room/严格模式不能把内置库命中伪装成自动合成成功。普通 assisted
    # 模式仍可使用内置协议以保持历史兼容，但产物会明确标记 source=library_fallback。
    if require_auto_descriptor and descriptor_resolution.get("source") != "auto_generated":
        reason = descriptor_resolution.get("skip_reason") or descriptor_resolution.get("errors") or (
            "自动描述符未通过源码/设备侧校验"
        )
        return _result(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=[
                "严格自动描述符模式拒绝内置回退："
                + ("；".join(str(x) for x in reason) if isinstance(reason, list) else str(reason))
            ],
            descriptor_hit=descriptor_id, llm_used=True, notes=notes,
            entry_discovery=entry_discovery_data,
        )

    # 3. 确定性骨架
    skeleton = _deterministic_skeleton(finding, descriptor_id, selected_route_candidate)

    # 4. 侦查 agent loop（§9）：LLM 自主查证（读源码/grep/hdc 只读探测）→ finalize 草案
    llm_used = False
    recon_facts: dict[str, Any] = {}   # 侦查 finalize 提交的事实卡（§11.2 复核输入）
    facts_store = None                 # §11.3 设备事实库（复核通过后升级 source）
    if binding_pair is not None:
        llm_used = True
        from .agent.recon_loop import run_recon_loop  # noqa: PLC0415
        facts, exemplar = _select_recon_context(
            finding=finding, hdc=hdc, device_facts=device_facts,
            clean_room=clean_room,
        )
        recon = run_recon_loop(
            finding=finding, skeleton=skeleton,
            descriptor_dict=get_descriptor(descriptor_id).to_dict(),
            repo_root=Path(finding.repo_root) if finding.repo_root else Path("."),
            hdc=hdc, binding_pair=binding_pair, device_facts=facts,
            oracle_forms=_VULNCLASS_ORACLE.get(finding.vuln_class, {}).get("forms", []),
            exemplar_contract=exemplar,
            on_event=on_event,
        )
        notes.append(f"侦查 loop: {recon.status} turns={recon.turns_used} "
                     f"device_cmds={recon.device_commands_used} notes={len(recon.notes)}")
        notes.extend(f"recon-note: {n}" for n in recon.notes)
        if recon.status != "finalized":
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[f"侦查 loop 未产出草案（{recon.status}）: {recon.error}"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        draft = _merge_recon_draft(
            recon.draft, finding, skeleton,
            repair_missing_oracle=repair_missing_oracle,
        )
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
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=["LLM 起草输出不合法（非 JSON / 结构不符 / insufficient）"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        if "insufficient" in draft:
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[f"LLM 起草声明证据不足: {draft['insufficient']}"],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        route_shape_errors = _validate_recon_protocol_route(draft)
        if route_shape_errors:
            notes.append("侦查草案发送序列校验未通过：" + "；".join(route_shape_errors))
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=["协议帧序列不完整：" + e for e in route_shape_errors],
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
        # 缺少 oracle 本应是可反馈、可重试的契约缺口，而不是让
        # contract_from_dict 以 KeyError 终止整场动态测试。
        if not isinstance(skeleton.get("oracle"), dict):
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=[
                    "LLM 起草缺少 oracle 块：必须声明 artifact_forms/hilog_expectations，"
                    "并依据 vuln_class 实例化可观测预言机"
                ],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
        mutation_route_errors = _validate_mutation_route(
            skeleton, finding, skeleton, recon_notes=recon.notes,
        )
        if mutation_route_errors:
            notes.append("侦查草案发送序列校验未通过：" + "；".join(mutation_route_errors))
            return _result(
                contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
                errors=["协议帧序列不完整：" + e for e in mutation_route_errors],
                descriptor_hit=descriptor_id, llm_used=True, notes=notes,
                entry_discovery=entry_discovery_data,
            )
    else:
        notes.append("LLM 基础设施不可用：仅确定性骨架，预期校验失败（field_values/forms 缺失）")

    # 5. 硬校验（§4 全表）
    try:
        contract = contract_from_dict(skeleton)
    except Exception as exc:  # noqa: BLE001 — 草案结构非法
        return _result(
            contract=None, compile_status="REQUIRES_PROTOCOL_REVIEW",
            errors=[f"草案结构非法: {type(exc).__name__}: {exc}"],
            descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
            entry_discovery=entry_discovery_data,
        )
    errors = validate_contract(contract, hdc=hdc)
    if errors:
        apply_compile_gate(contract, errors)
        return _result(
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
            return _result(
                contract=contract, compile_status=contract.compile_status,
                errors=[f"事实卡复核未过（§11.2 防编造）: {f}" for f in fact_failures],
                descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
                entry_discovery=entry_discovery_data,
            )
    # 自动描述符不能只靠主机侧字段校验：在进入真正的漏洞变异前，先在设备侧
    # 发送一条声明中的无害合法报文。内置描述符保持历史兼容路径；只有本轮新
    # 合成的 auto_* 描述符要求通过该自证。
    if descriptor_id.startswith("auto_") and hdc is not None:
        self_test_errors = _run_legal_protocol_self_test(contract, hdc, notes)
        if self_test_errors:
            apply_compile_gate(contract, [f"协议描述符设备侧自证未通过: {e}" for e in self_test_errors])
            return _result(
                contract=contract, compile_status=contract.compile_status,
                errors=self_test_errors, descriptor_hit=descriptor_id, llm_used=llm_used,
                notes=notes, entry_discovery=entry_discovery_data,
            )
    contract.compile_status = "ELIGIBLE"

    # 6. 落盘 contracts/generated/（与手写固件隔离）
    _persist(contract)
    return _result(contract=contract, compile_status="ELIGIBLE",
                   descriptor_hit=descriptor_id, llm_used=llm_used, notes=notes,
                   entry_discovery=entry_discovery_data)


def _merge_recon_draft(draft: dict[str, Any], finding: FindingInput,
                       skeleton: dict[str, Any], *,
                       repair_missing_oracle: bool = False) -> dict[str, Any] | None:
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
    if repair_missing_oracle:
        _repair_optional_hilog_shape_for_retry(draft)
    # 兼容旧草案/旧产物把完整 marker 路径和 marker 文件名重复拼接的形状。
    # 该归一化只修正占位符语义，不替模型决定协议字段或攻击载荷。
    normalize_marker_path_placeholders(draft)
    if repair_missing_oracle:
        # 只依据当前 finding 的源码 token 纠正模型在重试中产生的等价拼写，
        # 首次严格尝试仍保留原值并报告错误，避免隐藏协议事实缺口。
        _repair_source_protocol_frame_tokens(draft, finding)
    if "insufficient" in draft:
        return {"insufficient": draft["insufficient"]}
    merged: dict[str, Any] = {}
    for key in ("protocol", "oracle", "fault"):
        if key in draft and isinstance(draft[key], dict):
            merged[key] = draft[key]

    # 预言机的“形状”由已实现的漏洞类别映射确定，不应因为 LLM 在最后一轮
    # 忘记重复输出一个结构块而让整场测试在设备发送前失败。这里仅补齐
    # artifact_differential 的可观测骨架；具体路径、内容针和线路帧仍由当前
    # finding 的源码侦查提供，且后续 validator/runner 仍会逐项校验。这样既
    # 保持 clean-room（不读取历史契约/事实库），又避免把模型的 JSON 省略误判
    # 成“设备不存在”。未知漏洞类别没有实现映射时不做猜测，继续走原有门禁。
    oracle_spec = _VULNCLASS_ORACLE.get(getattr(finding, "vuln_class", ""), {})
    if (repair_missing_oracle and oracle_spec.get("impl")
            and isinstance(oracle_spec.get("forms"), list)):
        oracle = merged.setdefault("oracle", {})
        if isinstance(oracle, dict):
            oracle.setdefault("kind", oracle_spec.get("kind", "artifact_differential"))
            if oracle_spec.get("config"):
                config = oracle.setdefault("config", {})
                if isinstance(config, dict):
                    for key, value in oracle_spec["config"].items():
                        config.setdefault(key, value)
            forms = oracle.get("artifact_forms")
            if not isinstance(forms, list) or not forms:
                forms = []
                for declared in oracle_spec["forms"]:
                    if not isinstance(declared, dict):
                        continue
                    form = {k: v for k, v in declared.items()
                            if k in ("form", "path", "output_surface", "output_is_dir")}
                    if form.get("form") in ("create", "exfil"):
                        form["content_contains"] = "__RUN_PATTERN__"
                    forms.append(form)
                oracle["artifact_forms"] = forms
            oracle.setdefault("refutation", list(_DEFAULT_REFUTATION))
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
            frame_params = protocol.setdefault("param_space", {})
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
        # 侦查器有时为了保留每帧的 endpoint/证据，会把 frame_sequence 写成
        # [{"index": 0, "payload": "...", ...}]。这仍是同一份当前源码推导的
        # 帧事实，但 Runner 的稳定接口只接受 first/second/third 槽名。这里做
        # 纯形状归一化，不解释 payload、改写命令或注入任何服务特例。
        sequence = protocol.get("frame_sequence")
        if isinstance(sequence, list) and any(isinstance(item, dict) for item in sequence):
            fv = protocol.setdefault("field_values", {})
            frame_params = protocol.setdefault("param_space", {})
            normalized_sequence: list[str] = []
            slots = ("frame_first", "frame_second", "frame_third")
            for index, item in enumerate(sequence):
                if isinstance(item, dict):
                    if index >= len(slots):
                        continue
                    value = item.get("payload")
                    if value in (None, ""):
                        value = item.get("frame")
                    if value in (None, ""):
                        value = item.get("value")
                    if value in (None, ""):
                        # 兼容模型用单字段对象表示帧，例如
                        # {"set_pkgName": "..."}。排除结构元数据后取唯一
                        # 字符串值；不根据字段名解释协议语义。
                        for item_key, item_value in item.items():
                            if item_key in {"index", "mode", "host", "port", "note", "evidence"}:
                                continue
                            if isinstance(item_value, (str, int, float)) and str(item_value).strip():
                                value = item_value
                                break
                    if value in (None, ""):
                        continue
                    key = slots[index]
                    storage_key = "frame_first_template" if key == "frame_first" else key
                    frame_params[storage_key] = value
                    normalized_sequence.append(key)
                elif str(item).strip():
                    normalized_sequence.append(str(item))
            if normalized_sequence:
                protocol["frame_sequence"] = normalized_sequence
        else:
            # 另一种常见的模型输出是直接把最终线路帧字符串放进序列：
            # ["set_x::payload", "trigger::x"]。如果该字符串不是
            # field_values/param_space 中的槽名，就按顺序归一到稳定槽位；
            # 已有槽名序列保持不动。这样不会对分隔符或命令名作任何解释。
            sequence = protocol.get("frame_sequence")
            if isinstance(sequence, list) and sequence:
                fv = protocol.setdefault("field_values", {})
                frame_params = protocol.setdefault("param_space", {})
                ps_for_slots = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
                known_slots = set(fv) | set(ps_for_slots) | {
                    "first", "second", "third", "frame_first", "frame_second", "frame_third"
                }
                if any(isinstance(item, str) and item not in known_slots for item in sequence):
                    slots = ("frame_first", "frame_second", "frame_third")
                    normalized: list[str] = []
                    for index, item in enumerate(sequence):
                        if not isinstance(item, str) or not item.strip() or index >= len(slots):
                            continue
                        key = slots[index]
                        storage_key = "frame_first_template" if key == "frame_first" else key
                        frame_params[storage_key] = item
                        normalized.append(key)
                    if normalized:
                        protocol["frame_sequence"] = normalized
        # frame_* 是运行器槽位，不是协议描述符字段。若模型把它们误放到
        # field_values，移到 param_space 以免 V3 把合成槽位误判为幻觉字段。
        fv_slots = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
        frame_params = protocol.setdefault("param_space", {})
        for slot in ("frame_first", "frame_second", "frame_third", "first", "second", "third"):
            if slot in fv_slots and slot not in frame_params:
                storage_key = "frame_first_template" if slot in {"frame_first", "first"} else slot
                frame_params[storage_key] = fv_slots.pop(slot)
            elif slot in frame_params and slot == "frame_first":
                frame_params["frame_first_template"] = frame_params.pop(slot)
        # 对通用 key/value 描述符，模型有时只把字段值写进 frame_* 槽位，
        # 认为槽位名会由编码器自动补上。这里依据当前描述符声明的字段顺序
        # 做纯编码层归一化：只在字段名、分隔符和槽位值都来自当前描述符/
        # finding 时补齐 field_name + pair_separator，绝不生成服务命令、
        # 字段名或载荷。未知字段布局仍交给校验器拒绝。
        snapshot = protocol.get("descriptor_snapshot")
        if isinstance(snapshot, dict) and snapshot.get("encoder_kind") == "key_value":
            wire = snapshot.get("wire_format")
            pair_separator = str(wire.get("pair_separator") or "") if isinstance(wire, dict) else ""
            declared_fields = snapshot.get("fields")
            field_names = [
                str(item.get("name", "")).strip()
                for item in (declared_fields if isinstance(declared_fields, list) else [])
                if isinstance(item, dict) and str(item.get("name", "")).strip()
            ]
            sequence = protocol.get("frame_sequence")
            slot_index = {
                "frame_first": 0, "first": 0,
                "frame_second": 1, "second": 1,
                "frame_third": 2, "third": 2,
            }
            if pair_separator and field_names and isinstance(sequence, list):
                normalization_notes: list[str] = []
                for raw_slot in sequence:
                    slot = str(raw_slot)
                    idx = slot_index.get(slot)
                    if idx is None or idx >= len(field_names):
                        continue
                    storage_key = "frame_first_template" if idx == 0 else (
                        "frame_second" if idx == 1 else "frame_third"
                    )
                    value = frame_params.get(storage_key)
                    if not isinstance(value, (str, bytes)):
                        continue
                    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                    if not text.strip() or pair_separator in text:
                        continue
                    if text.strip().lower() in {
                        "first", "second", "third", "frame_first",
                        "frame_second", "frame_third", "frame_first_template",
                        "frame_second_template", "frame_third_template",
                    }:
                        continue
                    frame_params[storage_key] = f"{field_names[idx]}{pair_separator}{text}"
                    normalization_notes.append(
                        f"{storage_key} 使用描述符字段 {field_names[idx]!r} 补齐线路分隔符"
                    )
                if normalization_notes:
                    protocol.setdefault("normalization_notes", []).extend(normalization_notes)
        ps = protocol.get("param_space")
        if isinstance(ps, dict):
            # preplant 归一：LLM 可能给 [{"path": ...}] 形态 → 提取 path
            pre = ps.get("preplant")
            # preplant 是“发送前必须存在的设备路径模板”，不是说明文字。
            # LLM 有时会把“无需预埋/目录受 SELinux 限制”等解释句写成一个
            # 字符串；如果直接交给 runner，runner 会把字符串逐字符遍历，产生
            # mkdir("m") 这类不可解释的设备失败。统一归一成列表，并只保留
            # 绝对设备路径或 runner 支持的占位符路径；不绑定任何样本名称。
            if isinstance(pre, (str, dict)):
                pre = [pre]
            elif isinstance(pre, bool):
                # LLM 有时会把“无需预埋”表达成布尔 false。布尔值不是路径集合，
                # 若原样进入 runner，``for tpl in preplant`` 会触发
                # ``TypeError: 'bool' object is not iterable``，导致设备测试在发送
                # HAP 之前直接变成基础设施错误。false 的语义是空集合；true 没有
                # 可执行路径含义，也按空集合处理并留下可审计的归一化结果。
                pre = []
            if isinstance(pre, list):
                normalized_pre: list[str] = []
                for item in pre:
                    value = item.get("path") if isinstance(item, dict) else item
                    if not isinstance(value, str):
                        continue
                    value = value.strip()
                    if _is_runtime_path_template(value):
                        normalized_pre.append(value)
                pre = list(dict.fromkeys(normalized_pre))
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
        oracle_spec = _VULNCLASS_ORACLE.get(finding.vuln_class, {})
        oracle.setdefault("kind", oracle_spec.get("kind", "artifact_differential"))
        if oracle_spec.get("config"):
            config = oracle.setdefault("config", {})
            if isinstance(config, dict):
                for key, value in oracle_spec["config"].items():
                    config.setdefault(key, value)
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
            # create/exfil 都需要一个本轮唯一的内容针，才能在设备端区分
            # “路径存在/命令到达”与“确实写入了本次测试产生的内容”。模型可以只
            # 识别路径而省略 content_contains；这里统一补成运行器会展开的
            # __RUN_PATTERN__，不依赖具体服务、命令或历史 exemplar。
            if f.get("form") in ("create", "exfil"):
                if not f.get("content_contains"):
                    f["content_contains"] = "__RUN_PATTERN__"
            # output_is_dir 只对 exfil 的输出面有意义；create/delete/attr 的
            # path 是被观察的具体产物，统一为文件语义，避免模型默认值 True
            # 误导后续观察器。
            if f.get("form") in ("create", "delete", "attr"):
                f["output_is_dir"] = False
            if f.get("form") == "exfil":
                # output_surface 需为真实目录（surface 扫描对象）：空/占位符拼接 → 族缺省提示
                surface = str(f.get("output_surface") or "")
                if not surface or "__" in surface:
                    standard = _DESCRIPTOR_SURFACES.get(skeleton["protocol"]["descriptor_id"], "")
                    if standard:
                        f["output_surface"] = standard
            # path 非 LLM 可发明项：必须是受支持占位符（runner 映射表展开）
            declared = {d["form"]: d for d in _VULNCLASS_ORACLE.get(finding.vuln_class, {}).get("forms", [])}
            d = declared.get(f.get("form"))
            if d and d.get("path") and not str(f.get("path", "")).startswith("__"):
                f["path"] = d["path"]
    # cleanup 缺省：run_dir 兜底
    merged.setdefault("cleanup", {"remote_paths": ["__RUN_DIR__"]})
    return merged or None


def _validate_recon_protocol_route(draft: dict[str, Any]) -> list[str]:
    """检查侦查草案的多帧槽位是否真的可发送。

    这是协议/契约层的通用形状校验，不绑定某个服务命令：如果 LLM 声明了
    ``frame_sequence``，序列中的每个槽必须有非空的最终字面量或受支持占位符。
    否则运行器会“成功发送”一个空帧，造成看似 INPUT_DELIVERED、实际没有触发
    目标处理器的假阴性。错误会回流到 fresh-session，而不是静默 ELIGIBLE。
    """
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    sequence = protocol.get("frame_sequence")
    if not isinstance(sequence, list) or not sequence:
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    descriptor_snapshot = protocol.get("descriptor_snapshot") if isinstance(protocol.get("descriptor_snapshot"), dict) else {}
    wire_format = descriptor_snapshot.get("wire_format") if isinstance(descriptor_snapshot.get("wire_format"), dict) else {}
    pair_separator = str(wire_format.get("pair_separator") or "")
    # 某些文本协议在 key/value 分隔符之外还有独立的认证/路由后缀。
    # 例如 command:::token：服务端先按 token_separator 去掉后缀，再按
    # pair_separator 解析命令。只有描述符明确声明了该语法，校验器才允许
    # 紧邻的重复字符；不能通过历史服务名或样本名猜测。
    token_separator = str(
        wire_format.get("token_separator")
        or wire_format.get("auth_suffix_separator")
        or wire_format.get("suffix_separator")
        or ""
    )
    descriptor_fields = descriptor_snapshot.get("fields")
    field_names = [
        str(item.get("name") or "").strip()
        for item in descriptor_fields
        if isinstance(item, dict)
    ] if isinstance(descriptor_fields, list) else []
    slot_index = {
        "frame_first": 0, "first": 0,
        "frame_second": 1, "second": 1,
        "frame_third": 2, "third": 2,
    }

    def _usable_frame(value: Any) -> bool:
        # 帧最终要交给 transport 编码为线路字节；None、空串、数字索引和
        # 布尔占位都不是可发送的帧。此前模型把 frame_first=0 当成“第 1 帧
        # 的索引”，校验却把它当成有效值，导致 INPUT_DELIVERED 但实际没有
        # 业务帧到达服务端。这里不解释协议语义，只拒绝非字面量槽位。
        return isinstance(value, (str, bytes)) and bool(str(value).strip())

    errors: list[str] = []
    for index, slot in enumerate(sequence, start=1):
        key = str(slot)
        value = field_values.get(key)
        if not _usable_frame(value):
            value = param_space.get(key)
        # 运行器对这两个标准槽位使用 frame_*_template / frame_second；允许
        # 模型把首帧放到模板键，但不能允许声明了序列却留下空槽。
        if key == "frame_first" and not _usable_frame(value):
            value = field_values.get("frame_first_template")
            if not _usable_frame(value):
                value = param_space.get("frame_first_template")
        if not _usable_frame(value):
            errors.append(f"protocol.frame_sequence[{index}]={key} 没有可发送的帧值")
        elif str(value).strip().lower() in {
            "first", "second", "third", "frame_first", "frame_second",
            "frame_third", "frame_first_template", "frame_second_template",
            "frame_third_template",
        }:
            # 这些是 schema 槽位标签，不是线路帧。模型常把序列字段名
            # 原样填回，transport 随后会“成功”发送无业务意义的文本。
            errors.append(
                f"protocol.frame_sequence[{index}]={key} 的值 {value!r} 只是槽位标签，"
                "不是可发送的完整协议帧"
            )
        elif pair_separator and str(descriptor_snapshot.get("encoder_kind", "")) == "key_value":
            # 对声明为 key/value 的文本描述符，槽位值必须已经是线路帧，
            # 不能把 first/second 之类的数组标签或裸字段名交给 transport。
            if pair_separator not in str(value):
                errors.append(
                    f"protocol.frame_sequence[{index}]={key} 不是完整 key/value 帧，"
                    f"缺少分隔符 {pair_separator!r}"
                )
            else:
                # 如果描述符给出了字段顺序，帧必须以对应字段名和一个分隔符
                # 开始。模型偶尔会把 key::value 误写成 key:::value；普通的
                # “包含分隔符”检查会放过这种帧，设备端却会把字段值前的额外
                # 冒号一并解析，导致合法 handler 未命中。这里不解释业务命令，
                # 只依据描述符字段和 wire_format 拒绝紧邻的重复分隔符。
                field_index = slot_index.get(key)
                if field_index is not None and field_index < len(field_names):
                    field_name = field_names[field_index]
                    prefix = f"{field_name}{pair_separator}"
                    text_value = str(value)
                    token_prefix = f"{field_name}{token_separator}" if token_separator else ""
                    if field_name and token_prefix and text_value.startswith(token_prefix):
                        # 这是描述符声明的 token 后缀，不是重复的 key/value
                        # 分隔符；保留给服务端的 RemoveToken/等价阶段处理。
                        continue
                    if field_name and text_value.startswith(prefix):
                        remainder = text_value[len(prefix):]
                        if remainder.startswith(pair_separator[:1]):
                            errors.append(
                                f"protocol.frame_sequence[{index}]={key} 在字段分隔符后出现"
                                f"重复分隔符 {pair_separator!r}；请按 descriptor 的 wire_format "
                                "生成一个字段分隔符"
                            )
    return errors


_MUTATION_ROUTE_CLASSES = frozenset({
    "command_injection", "arbitrary_file_write", "path_traversal",
    "permission_bypass", "parcel_check_missing",
})


def _source_guard_requirements(finding: FindingInput) -> list[dict[str, str]]:
    """从当前 finding 指定源码提取“命令前缀→守卫字面量”要求。

    这是通用的轻量证据校验，不认识任何 OpenHarmony 服务名。它只处理常见的
    ``#define TOKEN "literal"``/常量定义，以及接收函数中
    ``recv.find(TOKEN)`` 附近的消息枚举；用途是把模型常见的大小写/拼写
    误差回流为可修正反馈，而不是替模型推断完整污点链。
    """
    raw_paths = list(getattr(finding, "source_paths", []) or [])
    for chain in getattr(finding, "candidate_attack_chains", []) or []:
        for node in chain:
            value = str(node or "").strip()
            if ":" in value:
                value = value.rsplit(":", 1)[0]
            if value:
                raw_paths.append(value)
    roots: list[Path] = []
    for raw in raw_paths:
        text = re.sub(r":\d+(?:-\d+)?$", "", str(raw).strip())
        if not text:
            continue
        path = Path(text)
        if not path.is_absolute():
            path = Path(getattr(finding, "repo_root", "") or ".") / path
        path = path.resolve()
        if path.is_file() and path not in roots:
            roots.append(path)
    # 同一服务目录的头文件常承载宏/消息表；只扩展直接 include 目录，不做全仓
    # 扫描，避免把无关组件中的同名守卫混入当前 finding。
    candidates: list[Path] = list(roots)
    for root in list(roots):
        for parent in (root.parent, root.parent / "include"):
            try:
                for path in parent.iterdir():
                    if path.is_file() and path.suffix in {".c", ".cc", ".cpp", ".h", ".hh", ".hpp"}:
                        if path not in candidates:
                            candidates.append(path)
            except OSError:
                continue
    texts: dict[Path, list[str]] = {}
    for path in candidates:
        try:
            texts[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
    definitions: dict[str, str] = {}
    define_re = re.compile(
        r"(?:#define\s+|(?:constexpr|const)\s+[^;=\n]*\b)([A-Z][A-Z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:=\s*)?\"([^\"]+)\""
    )
    for lines in texts.values():
        for line in lines:
            match = define_re.search(line)
            if match:
                definitions.setdefault(match.group(1), match.group(2))

    enum_to_wire: dict[str, str] = {}
    map_re = re.compile(r"MessageType::([A-Z0-9_]+)[^\n]*?std::string\(\"([^\"]+)\"\)")
    for lines in texts.values():
        for line in lines:
            match = map_re.search(line)
            if match:
                enum_to_wire.setdefault(match.group(1), match.group(2))

    requirements: list[dict[str, str]] = []
    find_re = re.compile(r"\.find\(\s*([A-Z][A-Z0-9_]*)\s*\)")
    enum_re = re.compile(r"MessageType::([A-Z0-9_]+)")
    for path, lines in texts.items():
        for index, line in enumerate(lines):
            match = find_re.search(line)
            if not match or match.group(1) not in definitions:
                continue
            context = "\n".join(lines[max(0, index - 14):index + 1])
            enums = enum_re.findall(context)
            command = ""
            for enum_name in reversed(enums):
                if enum_name in enum_to_wire:
                    command = enum_to_wire[enum_name]
                    break
            if not command:
                continue
            item = {
                "command": command,
                "literal": definitions[match.group(1)],
                "evidence": f"{path}:{index + 1}",
            }
            if item not in requirements:
                requirements.append(item)
    return requirements


def _validate_source_guard_values(draft: dict[str, Any], finding: FindingInput) -> list[str]:
    """确保模型提交的相关帧包含当前源码声明的守卫字面量。"""
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    sequence = protocol.get("frame_sequence") if isinstance(protocol.get("frame_sequence"), list) else []
    combined = {**param_space, **field_values}
    slot_names = {str(slot) for slot in sequence} if sequence else set(combined)
    frames: list[str] = []
    for key in slot_names:
        value = combined.get(key)
        if key == "frame_first":
            value = combined.get("frame_first_template", value)
        if isinstance(value, (str, bytes)) and str(value).strip():
            frames.append(str(value))
    if not frames:
        return []
    errors: list[str] = []
    for requirement in _source_guard_requirements(finding):
        command = requirement["command"]
        relevant = [frame for frame in frames if command in frame]
        if not relevant:
            continue
        literal = requirement["literal"]
        if not any(literal in frame for frame in relevant):
            errors.append(
                f"当前源码守卫 {requirement['evidence']} 要求命令帧 {command!r} 包含字面量 "
                f"{literal!r}；提交帧未满足该条件，请按源码原文修正"
            )
    return errors


def _validate_oracle_payload_observability(draft: dict[str, Any]) -> list[str]:
    """确保需要内容差分的预言机确实有可观测写入载荷。

    ``touch <marker>`` 能证明路径被执行，却不能满足 create/exfil 形态默认的
    ``content_contains=__RUN_PATTERN__``。这是契约层的通用反馈：只检查 runner
    占位符与常见写入语义，不生成任何命令或服务字段。
    """
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    oracle = draft.get("oracle") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict) or not isinstance(oracle, dict):
        return []
    forms = oracle.get("artifact_forms") if isinstance(oracle.get("artifact_forms"), list) else []
    requires_content = any(
        isinstance(form, dict)
        and form.get("form") in {"create", "exfil"}
        and str(form.get("content_contains") or "") == "__RUN_PATTERN__"
        for form in forms
    )
    if not requires_content:
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}

    # 只检查“实际会被 transport 发送”的线路帧。旧逻辑递归扫描整个
    # field_values/param_space，只要某个说明性字段（例如 recvBuf）包含
    # __RUN_PATTERN__ 就放行，即使 frame_first_template 实际是 touch marker，
    # 这会造成设备创建空文件后被误认为具备内容差分。这里保留通用槽位
    # 解析，不认识任何服务命令，也不从非发送字段推断可观测载荷。
    sequence = protocol.get("frame_sequence") if isinstance(protocol.get("frame_sequence"), list) else []
    frame_keys = {
        "first", "second", "third", "frame_first", "frame_second", "frame_third",
        "frame_first_template", "frame_second_template", "frame_third_template",
        "payload", "payload_template", "message", "message_template",
    }
    selected_keys = [str(key) for key in sequence if str(key)] or [
        key for key in (*param_space.keys(), *field_values.keys()) if key in frame_keys
    ]
    actual_frames: list[str] = []
    for key in selected_keys:
        values: list[Any] = []
        for container in (param_space, field_values):
            if key in container:
                values.append(container.get(key))
        # Runner 的 frame_first 是稳定槽位，允许其模板别名作为同一帧来源。
        if key == "frame_first":
            for container in (param_space, field_values):
                if "frame_first_template" in container:
                    values.append(container.get("frame_first_template"))
        if key == "first":
            for container in (param_space, field_values):
                for alias in ("frame_first", "frame_first_template"):
                    if alias in container:
                        values.append(container.get(alias))
        for value in values:
            if isinstance(value, str) and value.strip():
                actual_frames.append(value)
                break
    text = "\n".join(actual_frames)
    # 运行器会把 __RUN_PATTERN__ 替换成当前轮次的字面量。若模型把它
    # 写成 $__RUN_PATTERN__ 或 \\__RUN_PATTERN__，替换后会被设备侧
    # shell 当作变量展开/转义文本，而不是写入本轮内容，最终只能得到
    # INPUT_DELIVERED/SINK_CONTROLLED 的假阴性。这里不绑定任何服务命令，
    # 仅校验占位符的可观测性。
    for item in actual_frames:
        if not isinstance(item, str):
            continue
        for marker in ("__RUN_PATTERN__", "__MARKER_PATH__", "__MARKER__"):
            start = 0
            while True:
                index = item.find(marker, start)
                if index < 0:
                    break
                if index > 0 and item[index - 1] in {"$", "\\"}:
                    return [
                        f"运行时占位符 {marker} 被 shell 变量前缀或转义符包裹；"
                        "请在实际发送帧中直接使用占位符，避免替换后被设备 shell 吞掉"
                    ]
                start = index + len(marker)
    # frame_sequence 中的槽位值必须是完整线路帧。模型有时会把字段名
    # frame_first/frame_second，或模板标签 first/second 原样放回协议；这类
    # 文本虽然非空，却不会触发任何业务分派。校验只依赖契约 schema，不依赖
    # 某个服务的命令名称。
    if isinstance(sequence, list):
        slot_labels = {
            "first", "second", "third", "frame_first", "frame_second",
            "frame_third", "frame_first_template", "frame_second_template",
            "frame_third_template",
        }
        for slot in sequence:
            key = str(slot)
            candidates = []
            for container in (param_space, field_values):
                value = container.get(key)
                if isinstance(value, str):
                    candidates.append(value.strip().lower())
            if key == "frame_first":
                for container in (param_space, field_values):
                    value = container.get("frame_first_template")
                    if isinstance(value, str):
                        candidates.append(value.strip().lower())
            if any(value in slot_labels for value in candidates):
                return [
                    f"protocol.frame_sequence[{key}] 的值只是槽位标签，"
                    "请提交依据当前源码得到的完整线路帧"
                ]
    if (("__MARKER_PATH__" in text or "__MARKER__" in text)
            and "__RUN_PATTERN__" not in text):
        return [
            "oracle 要求 create/exfil 观察本轮内容，但变异帧只创建 marker 未写入 "
            "__RUN_PATTERN__；请依据当前源码选择可观察的内容写入形式（如 echo/printf/tee），"
            "并在实际发送的帧中同时保留 marker 路径与 __RUN_PATTERN__"
        ]
    return []


def _validate_route_dispatch_spelling(draft: dict[str, Any], skeleton: dict[str, Any]) -> list[str]:
    """检查模型帧中的命令 token 是否保持当前 route 的源码拼写。

    文本协议的分派通常是大小写敏感的。模型可能从枚举名生成
    ``CATCH_NETWORK_TRAFFIC``，而源码线路值是 ``catch_network_traffic``；这种
    差异不会被一般的 shell/字段校验发现，却会让输入停在“已发送”而没有进入
    目标处理器。这里不认识任何具体服务，只从当前 route binding 的 handler、
    dispatch_conditions、state_flow 和 evidence 中提取带下划线的 token，发现
    仅大小写不同的线路值就反馈给下一轮模型修正。
    """
    route = skeleton.get("route_binding") if isinstance(skeleton, dict) else None
    if not isinstance(route, dict):
        return []
    route_text = "\n".join(
        str(route.get(key, ""))
        for key in ("handler", "target_sink", "dispatch_conditions", "state_flow", "evidence")
    )
    tokens: set[str] = set()
    # 只收集形似协议命令的 token，避免把普通英文说明词当成命令。
    tokens.update(re.findall(r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b", route_text))
    tokens.update(
        item for item in re.findall(r"['\"]([A-Za-z][A-Za-z0-9_.-]{2,})['\"]", route_text)
        if "_" in item or "-" in item
    )
    if not tokens:
        return []
    # 同一个分派项经常同时出现在枚举名和线路字面量中，例如
    # ``CATCH_NETWORK_TRAFFIC`` 与 ``catch_network_traffic``。枚举名只是
    # 源码内部标识，真正需要发送的是源码中出现的线路字面量。按大小写
    # 折叠归并时优先保留包含小写字符的形式，避免把合法的线路帧误报为
    # “仅大小写不同”。这仍然是通用的源码证据归并，不依赖任何服务名称。
    canonical_tokens: dict[str, str] = {}
    for token in sorted(tokens, key=lambda item: (item.casefold(), item)):
        folded = token.casefold()
        current = canonical_tokens.get(folded)
        if current is None:
            canonical_tokens[folded] = token
        elif current.isupper() and not token.isupper():
            canonical_tokens[folded] = token
    tokens = set(canonical_tokens.values())
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    sequence = protocol.get("frame_sequence") if isinstance(protocol.get("frame_sequence"), list) else []
    combined = {**param_space, **field_values}
    frames: list[str] = []
    for key in sequence or combined:
        value = combined.get(key)
        if key == "frame_first":
            value = combined.get("frame_first_template", value)
        if isinstance(value, str) and value.strip():
            frames.append(value)
    for token in sorted(tokens, key=len, reverse=True):
        folded = token.casefold()
        for frame in frames:
            if frame.strip().casefold() == folded:
                return [
                    f"线路帧 {frame!r} 只有分派 token {token!r}，不是完整线路帧；"
                    "请依据当前源码补齐该协议要求的字段分隔符和参数值"
                ]
            if folded in frame.casefold() and token not in frame:
                return [
                    f"线路帧中的 route token {frame!r} 仅与源码 token {token!r} 大小写不同；"
                    "请按当前源码中的字面量原样发送，不能用枚举名替代线路命令"
                ]
    return []


def _route_source_files(finding: FindingInput) -> list[Path]:
    """收集当前 finding/候选路由的有限源码证据文件。

    协议 token 校验不能只依赖 LLM 写入的 ``route_binding`` 文本；命令表和
    ``recv.find("...")`` 往往位于 handler 的头文件或同目录 include 文件中。
    这里沿当前 finding 和候选攻击链最多展开一层本地 include 目录，不做全仓
    搜索，也不使用服务名、样本名或历史协议表。
    """
    repo_root = Path(getattr(finding, "repo_root", "") or ".").resolve()
    refs: list[str] = list(getattr(finding, "source_paths", []) or [])
    for chain in getattr(finding, "candidate_attack_chains", []) or []:
        if isinstance(chain, (list, tuple)):
            refs.extend(str(item) for item in chain if item)

    # 支持 file.cpp:line、file.cpp:start-end、file.cpp:Namespace::Function。
    # 只截取已知源码扩展名前的路径，避免把函数限定名当作文件路径。
    path_re = re.compile(r"^(.*?\.(?:c|cc|cpp|cxx|h|hh|hpp))(?:[:].*)?$", re.IGNORECASE)
    roots: list[Path] = []
    for ref in refs:
        text = str(ref or "").strip()
        match = path_re.match(text)
        raw = match.group(1) if match else text
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = repo_root / path
        path = path.resolve()
        if path.is_file() and path not in roots:
            roots.append(path)
            continue
        # 允许候选链只提供 basename，但仅在仓库内唯一命中时接受。
        if not path.is_absolute() or path == repo_root / Path(raw):
            try:
                hits = list(repo_root.rglob(Path(raw).name))
            except OSError:
                hits = []
            if len(hits) == 1 and hits[0].is_file() and hits[0] not in roots:
                roots.append(hits[0].resolve())

    files: list[Path] = list(roots)
    # 命令表通常位于当前源文件的 include 子目录；只展开一层，控制成本和
    # 误关联范围。文件身份仍然由真实路径和后续内容校验决定。
    for root in list(roots):
        # 先读 include 目录中的头文件（命令表/常量表通常在这里），再读
        # 当前目录的头文件；同目录的其它业务 .cpp 已由 finding/候选链提供，
        # 不在这里批量扩展，避免把相关头文件挤出 64 文件上限。
        for directory in (root.parent / "include", root.parent):
            try:
                children = sorted(directory.iterdir())
            except OSError:
                continue
            for child in children:
                if child.is_file() and child.suffix.lower() in {".h", ".hh", ".hpp"}:
                    if child not in files:
                        files.append(child)
                if len(files) >= 64:
                    return files[:64]
    return files[:64]


def _source_protocol_tokens(finding: FindingInput) -> list[dict[str, str]]:
    """从当前路由源码提取可发送的协议命令字面量。

    支持常见的 OpenHarmony/C++ 形态：

    * ``MessageType::X, std::string("wire_token")`` 命令表；
    * ``recvBuf.find("wire_token::")`` 或字符串比较；
    * ``#define TOKEN "wire_token"`` / constexpr 字符串。

    返回值保留精确大小写、源码位置和来源类别。提取不到时返回空，表示
    当前证据不足，不擅自把未知文本协议当作已验证协议。
    """
    mapping_re = re.compile(
        r"MessageType::[A-Za-z0-9_]+[^\n]*?std::string\(\"([^\"]+)\"\)"
    )
    string_re = re.compile(
        r"(?:\.find\s*\(|==\s*|!=\s*|compare\s*\(|starts_with\s*\(|\bcase\s+)\s*\"([^\"]+)\""
    )
    define_re = re.compile(
        r"(?:#define\s+[A-Za-z_][A-Za-z0-9_]*|(?:constexpr|const)\s+[^;=\n]*?)\s*(?:\[[^\]]*\])?\s*(?:=\s*)?\"([^\"]+)\""
    )
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(raw: str, path: Path, line_no: int, source_kind: str) -> None:
        value = str(raw or "").strip()
        if value.endswith("::"):
            value = value[:-2]
        # 协议 token 必须从字母开头；保留大小写和中间的下划线/连字符。
        match = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*)$", value)
        if not match:
            return
        token = match.group(1)
        key = (token, str(path))
        if key in seen:
            return
        seen.add(key)
        result.append({
            "token": token,
            "evidence": f"{path}:{line_no}",
            "source_kind": source_kind,
        })

    for path in _route_source_files(finding):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for index, line in enumerate(lines, start=1):
            for match in mapping_re.finditer(line):
                add(match.group(1), path, index, "message_map")
            for match in string_re.finditer(line):
                add(match.group(1), path, index, "dispatch_literal")
            for match in define_re.finditer(line):
                add(match.group(1), path, index, "constant_literal")
    return result


def _frame_command_token(value: Any) -> str:
    """提取一帧最前面的命令 token，不解释后续业务字段或 shell 内容。"""
    if not isinstance(value, (str, bytes)):
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_.-]*)", text)
    return match.group(1) if match else ""


def _repair_source_protocol_frame_tokens(
    draft: dict[str, Any], finding: FindingInput,
) -> list[str]:
    """在 fresh-session 重试中按当前源码纠正等价的帧 token 拼写。

    模型有时会把源码中的 ``set_pkgName`` 写成 ``set_pkg_name``，或只改变
    大小写。这类变形不是新的协议事实，直接把它交给设备会导致 handler
    无法命中；但把任意未知 token 自动替换成某个服务命令同样不安全。因此
    这里只允许：

    * 目标 token 必须由 ``_source_protocol_tokens`` 从本次 finding 的源码证据
      提取；
    * 模型 token 与源码 token 去掉非字母数字并统一大小写后完全相同；
    * 只改写帧开头的 token，保留 ``::`` 后面的载荷原文。

    首次严格编译不调用本修复；只有 ``repair_missing_oracle=True`` 的 fresh
    session 才会使用，并把每次改写写入协议审计字段。这样不会把校验器变成
    服务专用白名单，也不会凭空构造攻击载荷。
    """
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    source_tokens = _source_protocol_tokens(finding)
    if not source_tokens:
        return []
    compact_tokens: dict[str, dict[str, str]] = {}
    for item in source_tokens:
        token = str(item.get("token") or "").strip()
        if not token:
            continue
        compact = re.sub(r"[^a-z0-9]", "", token.casefold())
        # 同一规范化键对应多个源码字面量时不自动选一个，避免把不同命令
        # 的近似拼写错误地合并；保留首个标记为歧义并跳过。
        if compact in compact_tokens and compact_tokens[compact]["token"] != token:
            compact_tokens[compact] = {"token": "", "evidence": ""}
        else:
            compact_tokens[compact] = {"token": token, "evidence": str(item.get("evidence") or "")}

    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    combined = {**param_space, **field_values}
    sequence = protocol.get("frame_sequence") if isinstance(protocol.get("frame_sequence"), list) else []
    keys: list[str] = []
    if sequence:
        keys.extend(str(item) for item in sequence)
    else:
        keys.extend(str(key) for key in combined)
    # frame_first 在 merge 阶段使用 frame_first_template 存储；其它槽位保持
    # 原名。只遍历线路帧槽位，不能修改普通协议字段中的 token。
    frame_keys = {
        "first", "second", "third", "frame_first", "frame_second", "frame_third",
        "frame_first_template", "frame_second_template", "frame_third_template",
    }
    repairs: list[str] = []
    seen_storage: set[str] = set()
    for key in keys:
        if key not in frame_keys:
            continue
        storage_key = "frame_first_template" if key in {"first", "frame_first"} else key
        if storage_key in seen_storage:
            continue
        seen_storage.add(storage_key)
        value = combined.get(storage_key)
        if not isinstance(value, (str, bytes)):
            continue
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        token = _frame_command_token(text)
        if not token:
            continue
        compact = re.sub(r"[^a-z0-9]", "", token.casefold())
        candidate = compact_tokens.get(compact)
        if not candidate or not candidate.get("token") or candidate["token"] == token:
            continue
        replacement = candidate["token"]
        repaired = re.sub(r"^\s*" + re.escape(token), lambda match: match.group(0)[:len(match.group(0)) - len(token)] + replacement, text, count=1)
        if repaired == text:
            continue
        # param_space 是运行器实际读取的优先位置；若原值只存在 field_values，
        # 将修复结果写入相同语义的 param_space 槽位，避免留下双份冲突值。
        param_space[storage_key] = repaired
        field_values.pop(storage_key, None)
        repairs.append(
            f"retry-source-token-repair: {token!r} → {replacement!r} "
            f"（源码证据 {candidate.get('evidence') or 'unknown'}）"
        )
    if repairs:
        protocol.setdefault("normalization_notes", []).extend(repairs)
    return repairs


def _validate_source_protocol_tokens(draft: dict[str, Any], finding: FindingInput) -> list[str]:
    """逐帧核对 LLM 生成的命令 token 与当前源码字面量。

    该校验专门防止协议命令被模型自动改写大小写、下划线或拼写。它不维护
    任意服务的命令白名单：允许的 token 完全来自本次 finding 的源码证据。
    当证据 bundle 没有提取到协议 token 时返回空，让既有的 route 文本校验和
    LLM 补证流程继续处理；不能凭空把某个服务命令写入通用规则。
    """
    tokens = _source_protocol_tokens(finding)
    if not tokens:
        return []
    known = {item["token"]: item for item in tokens}
    known_folded = {item["token"].casefold(): item for item in tokens}
    known_compact = {re.sub(r"[^a-z0-9]", "", item["token"].casefold()): item for item in tokens}

    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    sequence = protocol.get("frame_sequence") if isinstance(protocol.get("frame_sequence"), list) else []
    combined = {**param_space, **field_values}
    keys = [str(item) for item in sequence] if sequence else [
        key for key in combined
        if key in {"first", "second", "third", "frame_first", "frame_second", "frame_third", "frame_first_template", "frame_second_template", "frame_third_template"}
    ]
    errors: list[str] = []
    for key in keys:
        value = combined.get(key)
        if key == "frame_first" and not value:
            value = combined.get("frame_first_template")
        if key == "first" and not value:
            value = combined.get("frame_first_template") or combined.get("frame_first")
        token = _frame_command_token(value)
        if not token:
            continue
        if token in known:
            continue
        folded = known_folded.get(token.casefold())
        compact = known_compact.get(re.sub(r"[^a-z0-9]", "", token.casefold()))
        if folded is not None:
            errors.append(
                f"协议帧 {key} 使用命令 token {token!r}，源码要求精确字面量 {folded['token']!r}（证据 {folded['evidence']}）；禁止改变大小写"
            )
        elif compact is not None:
            errors.append(
                f"协议帧 {key} 使用命令 token {token!r}，与源码 token {compact['token']!r} 仅存在分隔符/拼写差异（证据 {compact['evidence']}）；请按源码原文发送"
            )
        else:
            errors.append(
                f"协议帧 {key} 使用未知命令 token {token!r}；当前源码证据中的候选 token 为 {sorted(known)!r}，请补证或修正帧"
            )
    return errors


def _validate_lifecycle_sequence(draft: dict[str, Any], notes: list[str] | None) -> list[str]:
    """拒绝在危险操作之前发送源码已标注为停止/重置的控制帧。

    这不是服务命令白名单。侦查器会把状态写入、线程启动/停止和清理动作写入
    notes；这里只把“某个实际帧 token 在同一份当前源码笔记中被明确描述为
    stop/reset/clear/disable/close”作为反馈，避免模型把结束采集的控制帧放在
    sink 前面。若没有这种当前证据，不修改也不猜测序列。
    """
    if not notes:
        return []
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return []
    sequence = protocol.get("frame_sequence")
    if not isinstance(sequence, list) or len(sequence) < 3:
        return []
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    combined = {**param_space, **field_values}
    stop_terms = (
        "stop", "reset", "clear", "disable", "close", "terminate", "shutdown",
        "停止", "重置", "清除", "禁用", "关闭", "结束",
    )
    for index, raw_slot in enumerate(sequence):
        if index < 2:
            continue
        slot = str(raw_slot)
        value = combined.get(slot)
        if slot == "frame_first":
            value = combined.get("frame_first_template", value)
        if not isinstance(value, (str, bytes)):
            continue
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        # 只取线路帧的第一个 token；字段值中出现的单词不能触发该规则。
        token = re.split(r"::|[\\s,;|]", text.strip(), maxsplit=1)[0].strip().casefold()
        if not token or len(token) < 3:
            continue
        for note in notes:
            lower = str(note).casefold()
            pos = lower.find(token)
            if pos < 0:
                continue
            window = lower[max(0, pos - 180):pos + 240]
            if any(term in window for term in stop_terms):
                return [
                    f"线路帧 {text!r} 在 sink 前被当前源码证据描述为停止/重置控制；"
                    "请移除该尾部控制帧，仅保留从入口到危险操作所需的最短顺序"
                ]
    return []


def _validate_mutation_route(draft: dict[str, Any], finding: FindingInput,
                             skeleton: dict[str, Any], *,
                             recon_notes: list[str] | None = None) -> list[str]:
    """拒绝“只有合法探测、没有实际变异帧”的网络契约。

    这是一条协议形状约束，而不是样本协议规则：合法探测只能说明端点响应，
    不能证明当前输入会抵达危险参数。若 vuln_class 需要验证输入影响，且入口
    是 HAP/Unix 传输，侦查草案必须声明至少一个可发送的变异槽位。具体帧名、
    分隔符和 payload 仍由 LLM 根据本次源码证据填写；这里不生成任何服务命令。
    """
    if getattr(finding, "vuln_class", "") not in _MUTATION_ROUTE_CLASSES:
        return []
    entry = (skeleton.get("entry") or {}).get("kind", "")
    if entry not in {"hap_udp", "hap_tcp", "native_unix", "unix_dgram", "unix_stream"}:
        return []
    protocol = draft.get("protocol") if isinstance(draft, dict) else None
    if not isinstance(protocol, dict):
        return ["缺少 protocol，无法声明变异帧"]
    sequence = protocol.get("frame_sequence")
    if isinstance(sequence, list) and sequence:
        # _validate_recon_protocol_route 已负责确认每个槽有值；这里仅确认不是
        # 一个只引用合法探测字段的伪序列。命令执行类还要继续检查实际槽位
        # 是否携带 shell 语法，不能因为“有 frame_first 名称”就提前放行。
        keys = {str(k) for k in sequence}
        has_frame_slot = bool(keys & {
            "first", "second", "third", "frame_first", "frame_second", "frame_third"
        })
    else:
        has_frame_slot = False
    field_values = protocol.get("field_values") if isinstance(protocol.get("field_values"), dict) else {}
    param_space = protocol.get("param_space") if isinstance(protocol.get("param_space"), dict) else {}
    combined = {**param_space, **field_values}
    mutation_keys = {
        "first", "second", "third", "frame_first", "frame_second", "frame_third",
        "frame_first_template", "frame_second_template", "frame_third_template",
        "payload", "payload_template", "message", "message_template",
    }
    has_explicit_slot = any(
        key in mutation_keys and isinstance(value, (str, int, float)) and str(value).strip()
        for key, value in combined.items()
    )
    if not has_explicit_slot and not has_frame_slot:
        return [
            "当前传输入口只有 legal_probe/命令枚举，未声明可发送的变异帧；"
            "请读取候选链上的分帧与字段解析源码后填写 frame_sequence 和帧模板，"
            "或在确实无法确认输入路径时提交 insufficient"
        ]
    # 对命令执行类 finding 再做一条与服务无关的载荷形状检查：仅把运行期
    # marker 当成普通字段值，或只重复 legal_probe，并不能验证 shell 参数受
    # 控制。这里不生成命令、不指定协议字段，只要求模型提交源码证据支持的
    # shell 语法变异（元字符或 runner marker 占位符与元字符组合）。
    if getattr(finding, "vuln_class", "") == "command_injection":
        frame_keys = {
            "first", "second", "third", "frame_first", "frame_second", "frame_third",
            "frame_first_template", "frame_second_template", "frame_third_template",
        }
        frame_values = [str(value) for key, value in combined.items()
                        if key in frame_keys and isinstance(value, (str, bytes))]
        shell_meta = re.compile(r"[;|&`$><]|\\n")
        if not any(shell_meta.search(value) for value in frame_values):
            return [
                "命令执行类变异帧未包含 shell 语法变异；当前值看起来只是普通字段/marker，"
                "请依据当前源码中参数到 shell sink 的关系提交带元字符的测试载荷，"
                "不要复制 legal_probe"
            ]
    # 协议命令 token 必须逐字保持当前源码中的分派字面量。该校验位于
    # shell 载荷形状检查之后，既不生成 payload，也不认识任何特定服务；它
    # 只消费本次 finding 的 handler/MESSAGE_MAP/解析器源码证据。
    source_token_errors = _validate_source_protocol_tokens(draft, finding)
    if source_token_errors:
        return source_token_errors
    guard_errors = _validate_source_guard_values(draft, finding)
    if guard_errors:
        return guard_errors
    dispatch_errors = _validate_route_dispatch_spelling(draft, skeleton)
    if dispatch_errors:
        return dispatch_errors
    lifecycle_errors = _validate_lifecycle_sequence(draft, recon_notes)
    if lifecycle_errors:
        return lifecycle_errors
    oracle_errors = _validate_oracle_payload_observability(draft)
    if oracle_errors:
        return oracle_errors
    return []


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


def _attach_compile_feedback(finding: Any, result: CompileResult) -> None:
    """把本场确定性拒绝原因回流到下一场侦查上下文。

    只追加编译器实际观察到的错误/notes，不把模型猜测升级成事实；容量有界，
    避免多次 fresh session 让 prompt 无限增长。
    """
    original_entry_hints = list(getattr(finding, "entry_hints", []) or [])
    context = getattr(finding, "analysis_context", None)
    if not isinstance(context, dict):
        return
    previous = context.get("dynamic_compile_feedback")
    history = list(previous) if isinstance(previous, list) else []
    item = {
        "compile_status": result.compile_status,
        "errors": [str(x)[:500] for x in result.errors[:4]],
        "notes": [str(x)[:500] for x in result.notes[-4:]],
    }
    history.append(item)
    context["dynamic_compile_feedback"] = history[-3:]


def compile_contract_with_retry(finding, *, hdc=None, device_facts=None,
                                on_event=None, max_attempts: int = 3,
                                clean_room: bool = False,
                                failure_log=None,
                                require_auto_descriptor: bool | None = None) -> CompileResult:
    """compile_contract 的闭环重试包装（P0-1）。

    - 首次 REQUIRES_PROTOCOL_REVIEW → 在有界次数内换 fresh session 重跑（新侦查
      loop 自带空 transcript/notes）；clean_room=True 时每次都不读取历史上下文；
    - 事实卡复核不一致**不重试**（模型在编造，重试只会再编一次）；
    - ORACLE_UNAVAILABLE / 描述符未命中是结构性缺口，重试无用；
    - 同一签名独立失败 > max_attempts 次 → 收敛 final-failure 短路（failure_log
      由调用方持有跨 run 传递）。

    默认 3 次仍是有界重试：动态契约的失败往往是模型在 finalize 阶段遗漏
    结构字段或线路槽位，fresh session 可以吸收这种非确定性，但不会绕过
    validator，也不会把失败状态改写成设备确认。需要更大预算的调用方可以
    显式传入 ``max_attempts``，而不是隐式改变测试语义。
    """
    # clean-room 默认启用严格自动描述符闸门：它不能以历史/内置协议的成功
    # 冒充本轮自动合成成功。调用方仍可显式关闭，以保持 assisted 模式的兼容性。
    if require_auto_descriptor is None:
        require_auto_descriptor = bool(clean_room)

    # 只允许同一次 retry 闭环复用入口候选。FindingInput 可能来自长期驻留的
    # worker，若不清理这两个内部键，下一次独立动态测试会错误继承上一场证据。
    context = getattr(finding, "analysis_context", None)
    if isinstance(context, dict):
        context.pop("_dynamic_current_run_entry_candidates", None)
        context.pop("_dynamic_current_run_selected_candidate", None)
        context.pop("dynamic_compile_feedback", None)

    # 在首场编译前冻结 Stage1 原始入口提示；不能从首场 Agent 追加的多候选
    # entry_hints 反向生成“明确端点”，否则 fresh session 会误选首个候选。
    original_entry_hints = list(getattr(finding, "entry_hints", []) or [])
    result = compile_contract(finding, hdc=hdc, device_facts=device_facts,
                              on_event=on_event, clean_room=clean_room,
                              require_auto_descriptor=require_auto_descriptor)
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

    initial_result = result
    attempts_done = 1
    while attempts_done < max(1, int(max_attempts)):
        _attach_compile_feedback(finding, result)

        sig = compile_gap_signature(result.compile_status, result.errors)
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
                    llm_used=True, notes=result.notes, clean_room=clean_room,
                )

        # 每次 fresh session 从同一份用户/Stage1 提示开始；入口候选则通过
        # analysis_context 的当前运行缓存恢复，避免候选累积改变路由选择。
        try:
            finding.entry_hints = list(original_entry_hints)
        except Exception:  # noqa: BLE001 — 兼容轻量测试对象
            pass
        retry_no = attempts_done + 1
        if on_event is not None:
            try:
                on_event({"event": "phase_note",
                          "detail": f"侦查降级（{result.errors[0][:80]}）→ fresh session 重试 {retry_no}/{max_attempts}"})
            except Exception:  # noqa: BLE001
                pass
        retry_result = compile_contract(
            finding, hdc=hdc, device_facts=device_facts,
            on_event=on_event, clean_room=clean_room,
            require_auto_descriptor=require_auto_descriptor,
            # 首场保持严格门禁，只有收到确定性“缺少 oracle”反馈后，
            # fresh-session 才允许使用 vuln_class 的已实现预言机骨架修复
            # LLM 的结构省略；这不是服务专用兜底，也不会替模型生成攻击帧。
            repair_missing_oracle=True,
        )
        attempts_done += 1
        if retry_result.compile_status == "ELIGIBLE":
            # fresh session 成功也要保留每一场失败反馈；否则前端只能看到“重试成功”，
            # 无法知道描述符/侦查为何被拒绝，也无法审计是否真的发生了自愈。
            retry_result.notes = [
                f"P0-1: fresh session 重试自愈（第 {attempts_done}/{max_attempts} 次）",
                *initial_result.notes,
                f"P0-1: 首场失败原因: {'；'.join(initial_result.errors[:3]) or '未提供'}",
                *retry_result.notes,
            ]
            return retry_result

        # 结构性缺口或事实卡不一致不应继续烧模型；与首场相同的终止规则仍然适用。
        retry_status = retry_result.compile_status
        if retry_status != "REQUIRES_PROTOCOL_REVIEW":
            return retry_result
        if any(_FACT_CARD_FAIL_SIGNATURE in e for e in retry_result.errors):
            return retry_result
        if any("描述符库未命中" in e or "多个可验证端点" in e for e in retry_result.errors):
            return retry_result
        result = retry_result

    # 所有有界 fresh session 均未通过：合并诊断并保留最后一场产物状态。
    merged_notes: list[str] = []
    for note in [*initial_result.notes, *result.notes,
                 f"P0-1: fresh session 在 {attempts_done} 次尝试后仍未修复缺口: {result.errors[:2]}"]:
        if note not in merged_notes:
            merged_notes.append(note)
    result.notes = merged_notes
    result.errors = list(dict.fromkeys([*initial_result.errors, *result.errors]))
    return result


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


def _is_runtime_path_template(value: str) -> bool:
    """判断一个值是否可能是 runner 可展开的设备路径模板。

    这里只做通用形状校验：具体路径前缀、占位符闭合和安全边界仍由
    ``contract_validator`` 负责。说明句、相对路径和空值不能进入 runner。
    """
    text = str(value or "").strip()
    if not text or _DESC_VALUE_RE.search(text):
        return False
    if text.startswith("/"):
        return True
    # runner 的路径模板以双下划线占位符开头（例如 __RUN_DIR__/dep.txt）。
    # 允许先保留给 V8 做占位符白名单校验，避免在这里复制另一份语义表。
    return text.startswith("__") and "\n" not in text and "\r" not in text


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
            # 这里仅做无害的 window 形状归一，不再静默删除字符串或缺少
            # tag/pattern 的对象。它们必须原样进入 V7 硬校验，否则非法草案
            # 会被“清洗”为空列表并误认为没有日志期望。
            if isinstance(e, dict):
                # 模型提出的日志是辅助观测，不因缺少某条设备版本相关日志
                # 否决已有 artifact 证据；只有显式 required=true 的契约才
                # 将该日志纳入强制预言机。手工契约可保留 required=true。
                e.setdefault("required", False)
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


def _repair_optional_hilog_shape_for_retry(draft: dict[str, Any]) -> None:
    """在 fresh-session 重试时隔离非法的可选日志期望。

    ``hilog_expectations`` 只是辅助观测；真正的效果预言机仍由
    ``artifact_forms`` 负责。模型偶尔会把字段说明（例如字符串列表）放进
    该字段。首轮仍保持严格门禁并报告格式错误；重试时将不能执行的条目
    留在 ``oracle.evidence`` 审计说明中，并从运行时列表移除，避免同一形状
    消耗全部重试预算，同时绝不把字符串当作日志查询条件执行。
    """
    oracle = draft.get("oracle")
    if not isinstance(oracle, dict) or "hilog_expectations" not in oracle:
        return
    raw = oracle.get("hilog_expectations")
    if isinstance(raw, list):
        invalid_count = sum(not isinstance(item, dict) for item in raw)
        if not invalid_count:
            return
        oracle["hilog_expectations"] = [item for item in raw if isinstance(item, dict)]
    else:
        invalid_count = 1
        oracle["hilog_expectations"] = []
    note = (
        f"retry-shape-repair: 忽略 {invalid_count} 条不可执行的 "
        "oracle.hilog_expectations（保留 artifact 预言机）"
    )
    evidence = str(oracle.get("evidence") or "").strip()
    oracle["evidence"] = f"{evidence}; {note}" if evidence else note
