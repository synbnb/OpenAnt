"""P0 自动化收敛三项的单元测试（离线，无 LLM/无设备）。

- P0-1 降级闭环重试：compile_gap_signature 规整化 + compile_contract_with_retry
  的重试/短路/不重试分类（mock compile_contract）。
- P0-2 exemplar 自动晋升：promote_exemplar_if_absent 首代写入/二代不覆盖/
  非 CONFIRMED 跳过 + _load_exemplar 自动晋升库命中。
- P0-3 端点确定性预扫：_scan_repo_endpoints 触发条件/端口提取/上限。

运行：cd libs/vulnfounder-core && python -m pytest core/test_p0_automation.py -q
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))
_UTIL = _CORE / "utilities"
if str(_UTIL) not in sys.path:
    sys.path.insert(0, str(_UTIL))

from core.scan_artifact_bridge import _scan_repo_endpoints  # noqa: E402
from core.exp_package import (  # noqa: E402
    _extract_guards_from_poc,
    _probe_pt_victims_dynamic,
)
from openharmony_dynamic import contract_compiler as cc  # noqa: E402
from openharmony_dynamic.contract_validator import validate_contract  # noqa: E402
from openharmony_dynamic.contracts.registry import load_contract  # noqa: E402


# ---------------------------------------------------------------------------
# P0-3 端点预扫
# ---------------------------------------------------------------------------

def test_scan_repo_endpoints_triggers_on_udp_without_port(tmp_path: Path) -> None:
    (tmp_path / "svc.cpp").write_text(
        'static constexpr uint16_t PORT = 8283;\n'
        'void loop() { int fd = socket(AF_INET, SOCK_DGRAM, 0); bind(fd, PORT); }\n',
        encoding="utf-8")
    hits = _scan_repo_endpoints(tmp_path, "攻击链描述 UDP datagram")
    assert hits == ["127.0.0.1:8283"]


def test_scan_repo_endpoints_no_udp_no_scan(tmp_path: Path) -> None:
    (tmp_path / "svc.cpp").write_text('int PORT = 8283;\n', encoding="utf-8")
    # 攻击链无 UDP 关键词 → 不扫描
    assert _scan_repo_endpoints(tmp_path, "本地文件读写链路") == []
    # 攻击链已带端点 → 不扫描
    assert _scan_repo_endpoints(tmp_path, "UDP datagram 到 127.0.0.1:9999") == []


def test_scan_repo_endpoints_ignores_non_socket_files(tmp_path: Path) -> None:
    # 有端口常量但文件无 socket 语义 → 不提取
    (tmp_path / "math.cpp").write_text('int PORT = 8283;\n', encoding="utf-8")
    assert _scan_repo_endpoints(tmp_path, "UDP datagram") == []


def test_scan_repo_endpoints_dedup_and_cap(tmp_path: Path) -> None:
    for i, port in enumerate((9001, 9002, 9003, 9004)):
        (tmp_path / f"s{i}.cpp").write_text(
            f'void f() {{ socket(AF_INET, 0, 0); int p = htons({port}); }}\n',
            encoding="utf-8")
    hits = _scan_repo_endpoints(tmp_path, "UDP datagram")
    assert len(hits) == 3 and hits[0] == "127.0.0.1:9001" or len(hits) <= 3
    assert all(h.startswith("127.0.0.1:") for h in hits)


def test_oracle_payload_checks_selected_wire_frame_only() -> None:
    """说明性 recvBuf 不能掩盖实际 frame 的 touch/空内容载荷。"""
    draft = {
        "oracle": {"artifact_forms": [{"form": "create", "content_contains": "__RUN_PATTERN__"}]},
        "protocol": {
            "frame_sequence": ["frame_first", "frame_second"],
            "field_values": {
                # 非发送字段带有 marker，不应被当作真实线路载荷。
                "recvBuf": "set_pkgName::smartperf;echo __RUN_PATTERN__>__MARKER_PATH__",
            },
            "param_space": {
                "frame_first_template": "set_pkgName::smartperf;touch __MARKER_PATH__",
                "frame_second": "catch_network_traffic",
            },
        },
    }
    errors = cc._validate_oracle_payload_observability(draft)
    assert errors and "只创建 marker" in errors[0]

    draft["protocol"]["param_space"]["frame_first_template"] = (
        "set_pkgName::smartperf;echo __RUN_PATTERN__>__MARKER_PATH__"
    )
    assert cc._validate_oracle_payload_observability(draft) == []


def test_validate_contract_rejects_non_mapping_hilog_expectations() -> None:
    """hilog 期望必须是结构化对象，不能让字符串进入设备运行阶段。"""
    contract = load_contract("DP-02")
    contract.oracle.hilog_expectations = ["must_not_contain", "optional"]

    errors = validate_contract(contract)

    assert any("hilog_expectations" in error for error in errors)


def test_normalize_draft_shapes_does_not_silently_drop_invalid_hilog_entries() -> None:
    """非法日志期望要交给硬校验报告，不能被归一化悄悄吞掉。"""
    draft = {"oracle": {"hilog_expectations": ["must_not_contain"]}}

    cc._normalize_draft_shapes(draft)

    assert draft["oracle"]["hilog_expectations"] == ["must_not_contain"]


def test_retry_repairs_non_executable_hilog_entries_without_touching_artifact_oracle() -> None:
    """fresh-session 只隔离非法日志辅助项，不替模型生成协议或效果条件。"""
    draft = {
        "oracle": {
            "artifact_forms": [{"form": "create", "path": "__MARKER__"}],
            "hilog_expectations": ["must_not_contain", {"tag": "SP", "required": False}],
        }
    }

    cc._repair_optional_hilog_shape_for_retry(draft)

    assert draft["oracle"]["hilog_expectations"] == [{"tag": "SP", "required": False}]
    assert draft["oracle"]["artifact_forms"] == [{"form": "create", "path": "__MARKER__"}]
    assert "retry-shape-repair" in draft["oracle"]["evidence"]


def test_retry_repairs_equivalent_source_protocol_token(tmp_path: Path) -> None:
    """重试只按当前源码证据修正 token 分隔符，不改写后续攻击载荷。"""
    source = tmp_path / "route.cpp"
    source.write_text(
        '#define SET_PACKAGE "set_pkgName"\n'
        'bool IsRoute(const std::string &s) { return s.find("set_pkgName::") != std::string::npos; }\n',
        encoding="utf-8",
    )
    finding = type("Finding", (), {
        "source_paths": [str(source)],
        "candidate_attack_chains": [],
        "repo_root": str(tmp_path),
    })()
    draft = {
        "protocol": {
            "frame_sequence": ["frame_first"],
            "field_values": {},
            "param_space": {
                "frame_first_template": "set_pkg_name::smartperf;printf '%s' __RUN_PATTERN__ > __MARKER_PATH__",
            },
        },
    }

    repairs = cc._repair_source_protocol_frame_tokens(draft, finding)

    assert repairs and "set_pkg_name" in repairs[0] and "set_pkgName" in repairs[0]
    assert draft["protocol"]["param_space"]["frame_first_template"].startswith(
        "set_pkgName::smartperf;"
    )
    assert "printf '%s' __RUN_PATTERN__" in draft["protocol"]["param_space"]["frame_first_template"]
    assert any("retry-source-token-repair" in note for note in draft["protocol"]["normalization_notes"])


# ---------------------------------------------------------------------------
# P0-2 exemplar 自动晋升
# ---------------------------------------------------------------------------

class _FakeContract:
    """最小契约桩：promote_exemplar_if_absent 只用 vuln_class/contract_id/to_dict。"""

    def __init__(self, vuln_class: str, contract_id: str = "GEN-TEST") -> None:
        self.vuln_class = vuln_class
        self.contract_id = contract_id

    def to_dict(self) -> dict:
        return {"contract_id": self.contract_id, "vuln_class": self.vuln_class}


def test_promote_first_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    c = _FakeContract("path_traversal")
    assert cc.promote_exemplar_if_absent(c, "CONFIRMED") == "promoted"
    saved = json.loads((tmp_path / "auto" / "path_traversal.json").read_text(encoding="utf-8"))
    assert saved["_exemplar_meta"]["source"] == "auto-promotion(P0-2)"


def test_promote_second_generation_no_overwrite(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    assert cc.promote_exemplar_if_absent(_FakeContract("fd_leak", "GEN-A"), "CONFIRMED") == "promoted"
    # 第二个 CONFIRMED 不覆盖（第一代钉死）
    assert cc.promote_exemplar_if_absent(_FakeContract("fd_leak", "GEN-B"), "CONFIRMED") == "already"
    saved = json.loads((tmp_path / "auto" / "fd_leak.json").read_text(encoding="utf-8"))
    assert saved["contract_id"] == "GEN-A"


def test_promote_skips_non_confirmed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    assert cc.promote_exemplar_if_absent(_FakeContract("race_condition"), "NOT_REPRODUCED").startswith("skipped")
    assert not (tmp_path / "auto" / "race_condition.json").exists()


def test_load_exemplar_hits_auto_library(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    (tmp_path / "auto").mkdir()
    ref_contract = {"contract_id": "GEN-AUTO", "vuln_class": "resource_exhaustion"}
    (tmp_path / "auto" / "resource_exhaustion.json").write_text(
        json.dumps(ref_contract), encoding="utf-8")
    # 该类无手写 ref → 回落自动晋升库
    assert cc._load_exemplar("resource_exhaustion") == ref_contract


def test_clean_room_context_never_loads_history(monkeypatch) -> None:
    """clean-room 只允许当前 finding/源码证据，不读取历史 facts/exemplar。"""
    from utilities.openharmony_dynamic.agent import device_facts as facts_module

    def _unexpected_facts(*args, **kwargs):
        raise AssertionError("clean-room 不得实例化设备事实库")

    def _unexpected_exemplar(*args, **kwargs):
        raise AssertionError("clean-room 不得加载历史 exemplar")

    monkeypatch.setattr(facts_module, "DeviceFacts", _unexpected_facts)
    monkeypatch.setattr(cc, "_load_exemplar", _unexpected_exemplar)
    facts, exemplar = cc._select_recon_context(
        finding=type("Finding", (), {"vuln_class": "command_injection"})(),
        hdc=type("HDC", (), {"serial": "SERIAL-HISTORY"})(),
        device_facts=None,
        clean_room=True,
    )
    assert facts is None
    assert exemplar is None


def test_merge_recon_draft_fills_generic_create_observation() -> None:
    """create 形态也必须有运行期唯一内容，否则 V7 无法验证写入是否发生。

    这是通用的可观测性兜底，不绑定某个服务或命令；模型只需给出 create
    的目标路径，运行器即可使用本轮 run_pattern 作为写入内容/判定针。
    """
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"protocol": {"descriptor_id": "auto_test"},
                "entry": {"kind": "hap_udp"}}
    draft = {"oracle": {"artifact_forms": [
        {"form": "create", "path": "__MARKER__"}
    ]}}
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    form = merged["oracle"]["artifact_forms"][0]
    assert form["content_contains"] == "__RUN_PATTERN__"


def test_merge_recon_normalizes_composite_marker_path() -> None:
    """契约编译阶段统一 marker 完整路径语义，避免运行后才出现假阴性。"""
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"protocol": {"descriptor_id": "auto_test"},
                "entry": {"kind": "hap_udp"}}
    draft = {
        "protocol": {"param_space": {
            "frame_first_template":
                "route::value;echo __RUN_PATTERN__ > "
                "__MARKER_PATH__/__MARKER__",
        }},
        "oracle": {"artifact_forms": [{
            "form": "create",
            "path": "__MARKER_PATH__/__MARKER__",
            "content_contains": "__RUN_PATTERN__",
            "output_is_dir": True,
        }]},
    }

    merged = cc._merge_recon_draft(draft, finding, skeleton)
    assert merged is not None
    assert merged["protocol"]["param_space"]["frame_first_template"].endswith(
        "__MARKER_PATH__"
    )
    form = merged["oracle"]["artifact_forms"][0]
    assert form["path"] == "__MARKER_PATH__"
    assert form["output_is_dir"] is False


def test_mutation_route_rejects_legal_probe_only_for_network_finding() -> None:
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"entry": {"kind": "hap_udp"}}
    draft = {
        "protocol": {
            "field_values": {"mode": "udp", "host": "127.0.0.1", "port": 8283,
                              "command": ["safe_probe"]},
            "param_space": {},
            "frame_sequence": [],
        }
    }
    errors = cc._validate_mutation_route(draft, finding, skeleton)
    assert errors and "变异帧" in errors[0]


def test_mutation_route_accepts_evidence_backed_frame_template() -> None:
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"entry": {"kind": "hap_udp"}}
    draft = {"protocol": {"param_space": {
        "frame_first_template": "route::value;echo __MARKER_PATH__"
    }}}
    assert cc._validate_mutation_route(draft, finding, skeleton) == []


def test_merge_recon_normalizes_structured_frame_sequence() -> None:
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"protocol": {"descriptor_id": "auto_test"},
                "entry": {"kind": "hap_udp"}}
    draft = {"protocol": {"frame_sequence": [
        {"index": 0, "payload": "route::payload __MARKER__", "note": "源码证据"},
        {"index": 1, "payload": "trigger::x"},
    ], "field_values": {"mode": "udp", "host": "127.0.0.1", "port": 8283}}}
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    proto = merged["protocol"]
    assert proto["frame_sequence"] == ["frame_first", "frame_second"]
    assert proto["param_space"]["frame_first_template"].startswith("route::")
    assert proto["param_space"]["frame_second"] == "trigger::x"


def test_merge_recon_normalizes_single_field_frame_objects() -> None:
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"protocol": {"descriptor_id": "auto_test"},
                "entry": {"kind": "hap_udp"}}
    draft = {"protocol": {"frame_sequence": [
        {"set_pkgName": "set_pkgName::payload __MARKER__", "index": 0},
        {"catch_network_traffic": "catch_network_traffic::x", "index": 1},
    ]}}
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    proto = merged["protocol"]
    assert proto["frame_sequence"] == ["frame_first", "frame_second"]
    assert proto["param_space"]["frame_first_template"].startswith("set_pkgName::")
    assert proto["param_space"]["frame_second"] == "catch_network_traffic::x"


def test_merge_recon_normalizes_literal_frame_sequence() -> None:
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"protocol": {"descriptor_id": "auto_test"},
                "entry": {"kind": "hap_udp"}}
    draft = {"protocol": {"frame_sequence": [
        "set_pkgName::payload __MARKER__", "catch_network_traffic::x"
    ]}}
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    proto = merged["protocol"]
    assert proto["frame_sequence"] == ["frame_first", "frame_second"]
    assert proto["param_space"]["frame_first_template"].startswith("set_pkgName::")


def test_merge_recon_prefixes_key_value_slot_from_descriptor_fields() -> None:
    """模型只给 frame 槽位值时，按当前描述符字段完成通用线路编码。"""
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {
        "protocol": {
            "descriptor_id": "sp_daemon_text",
            "descriptor_snapshot": {
                "encoder_kind": "key_value",
                "wire_format": {"pair_separator": "::"},
                "fields": [
                    {"name": "set_pkgName"},
                    {"name": "catch_network_traffic"},
                ],
            },
        },
        "entry": {"kind": "hap_udp"},
    }
    draft = {"protocol": {
        "frame_sequence": ["frame_first", "frame_second"],
        "param_space": {
            "frame_first": "smartperf;echo __MARKER__",
            "frame_second": "x",
        },
    }}
    merged = cc._merge_recon_draft(draft, finding, skeleton)
    proto = merged["protocol"]
    assert proto["param_space"]["frame_first_template"].startswith("set_pkgName::")
    assert proto["param_space"]["frame_second"].startswith("catch_network_traffic::")
    assert cc._validate_recon_protocol_route(merged) == []


def test_validate_recon_protocol_route_rejects_numeric_frame_index() -> None:
    """数组下标不是线路帧，不能让空帧通过形状闸门。"""
    draft = {"protocol": {
        "frame_sequence": ["frame_first"],
        "param_space": {"frame_first": 0},
    }}
    errors = cc._validate_recon_protocol_route(draft)
    assert errors and "没有可发送的帧值" in errors[0]


def test_validate_mutation_route_rejects_plain_frame_placeholder() -> None:
    """frame_first=first 不能掩盖真正变异载荷仍在其它字段中的问题。"""
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"entry": {"kind": "hap_udp"}}
    draft = {"protocol": {
        "frame_sequence": ["frame_first", "frame_second"],
        "param_space": {"frame_first_template": "first", "frame_second": "second"},
        "field_values": {"set_pkgName": "set_pkgName::x;echo marker"},
    }}
    errors = cc._validate_mutation_route(draft, finding, skeleton)
    assert errors and "shell 语法变异" in errors[0]


def test_mutation_route_rejects_shell_escaped_runtime_marker() -> None:
    """运行期 marker 不能被 shell 变量前缀或反斜杠包裹后交给设备。"""
    finding = type("Finding", (), {"vuln_class": "command_injection"})()
    skeleton = {"entry": {"kind": "hap_udp"}}
    draft = {"protocol": {
        "frame_sequence": ["frame_first"],
        "param_space": {
            "frame_first_template": "route::value;echo "
            + chr(36) + "__RUN_PATTERN__ > __MARKER_PATH__"
        },
        "field_values": {},
    }, "oracle": {"artifact_forms": [
        {"form": "create", "path": "__MARKER_PATH__",
         "content_contains": "__RUN_PATTERN__"}
    ]}}
    errors = cc._validate_mutation_route(draft, finding, skeleton)
    assert errors and "占位符" in errors[0]


def test_retry_preserves_clean_room_on_every_attempt(monkeypatch) -> None:
    """fresh-session 重试不能把 clean-room 降级成历史上下文模式。"""
    calls = []

    def fake_compile(finding, **kwargs):
        calls.append(dict(kwargs))
        if len(calls) == 1:
            return _CompiledStub("REQUIRES_PROTOCOL_REVIEW", ["侦查 loop budget_exhausted"])
        return _CompiledStub("ELIGIBLE", contract=object())

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object(), clean_room=True)
    assert out.compile_status == "ELIGIBLE"
    assert len(calls) == 2
    assert all(call.get("clean_room") is True for call in calls)


# ---------------------------------------------------------------------------
# P0-1 降级闭环重试
# ---------------------------------------------------------------------------

def test_gap_signature_normalizes_paths_and_numbers() -> None:
    a = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize /tmp/x1.json"])
    b = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize /tmp/y9.json"])
    c = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["事实卡复核未过: socket"])
    assert a == b          # 同根因 → 同签名（路径/数字规整化）
    assert a != c          # 不同根因 → 不同签名


class _CompiledStub:
    """CompileResult 形态的轻量桩。"""

    def __init__(self, status: str, errors: list[str] | None = None,
                 contract: object = None) -> None:
        self.compile_status = status
        self.errors = errors or []
        self.contract = contract
        self.notes = []
        self.descriptor_hit = ""
        self.llm_used = True


def test_retry_reruns_once_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _CompiledStub("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize"])
        return _CompiledStub("ELIGIBLE", contract=object())

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert out.compile_status == "ELIGIBLE"
    assert "fresh session 重试自愈" in out.notes[0]
    assert calls["n"] == 2


def test_retry_no_rerun_on_structural_gaps(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("ORACLE_UNAVAILABLE", ["预言机未实现（方案 §3.3 诚实降级）: x"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert out.compile_status == "ORACLE_UNAVAILABLE"
    assert calls["n"] == 1     # 结构性缺口不重试


def test_retry_no_rerun_on_fact_card_fabrication(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("REQUIRES_PROTOCOL_REVIEW", ["事实卡复核未过（§11.2 防编造）: k"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert calls["n"] == 1     # 编造型失败不重试


def test_retry_final_failure_short_circuit(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("REQUIRES_PROTOCOL_REVIEW",
                             ["侦查 loop 未产出草案（budget_exhausted）: 轮次耗尽"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    failure_log: dict[str, int] = {}
    # 预置历史：该签名已独立失败 3 次（超 max_attempts=2）
    sig = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                   ["侦查 loop 未产出草案（budget_exhausted）: 轮次耗尽"])
    failure_log[sig] = 3
    out = cc.compile_contract_with_retry(object(), failure_log=failure_log)
    assert out.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert "final-failure" in out.errors[0]
    assert calls["n"] == 1     # 收敛：不再发起 fresh session 重试（只烧首场编译）


# ---------------------------------------------------------------------------
# P2 动态 victim 探测 + 守卫泛化
# ---------------------------------------------------------------------------

class _FakeHDC:
    """HDCClient 桩：按路径返回预置 ls/stat 输出。"""

    def __init__(self, dirs: dict[str, tuple[int, list[str]]]) -> None:
        # dirs: 目录 → (rc, 文件名列表)；stat 全部返回 4096
        self._dirs = dirs

    def run(self, argv, *, purpose=""):
        class _R:
            def __init__(self, rc, out):
                self.returncode, self.stdout = rc, out
        if argv[:2] == ["shell", "ls"]:
            d = argv[2]
            rc, names = self._dirs.get(d, (1, []))
            return _R(rc, "\n".join(names))
        if argv[:2] == ["shell", "stat"]:
            return _R(0, "4096\n")
        return _R(1, "")


def test_dynamic_probe_collects_real_files() -> None:
    hdc = _FakeHDC({"/system/etc/hiview": (0, ["freeze_rules.xml", ".hidden", "hisysevent.cfg"])})
    hits = _probe_pt_victims_dynamic(hdc)
    assert hits == [
        "/system/etc/hiview/freeze_rules.xml",
        "/system/etc/hiview/hisysevent.cfg",
    ]


def test_dynamic_probe_empty_falls_back_later() -> None:
    # 全目录探测失败 → 空列表（调用方回落静态清单）
    hdc = _FakeHDC({})
    assert _probe_pt_victims_dynamic(hdc) == []
    assert _probe_pt_victims_dynamic(None) == []


def test_extract_guards_from_poc() -> None:
    poc = {"protocol": {"field_values": {
        "set_pkgName": "smartperf;echo x", "mode": "udp", "port": 8283}}}
    assert _extract_guards_from_poc(poc) == ("smartperf",)
    # 无守卫候选 → 静态表兜底
    assert _extract_guards_from_poc({"protocol": {"field_values": {"mode": "udp"}}}) == ("smartperf",)
