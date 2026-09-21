from __future__ import annotations

import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from utilities.openharmony_dynamic.runner import (
    RunRecord,
    Runner,
    _filter_preplant_paths,
)
from utilities.openharmony_dynamic.models import (
    ArtifactForm,
    CleanupSpec,
    Contract,
    EntrySpec,
    FaultSpec,
    IdentitySpec,
    OracleSpec,
    ProtocolSpec,
    RiskSpec,
)
from utilities.openharmony_dynamic.contracts.registry import load_contract


def test_preplant_boolean_is_empty_and_does_not_reach_runner():
    assert _filter_preplant_paths(False, {"/data/run/marker.txt"}) == []
    assert _filter_preplant_paths(True, {"/data/run/marker.txt"}) == []


def test_preplant_oracle_parent_is_filtered_but_unrelated_file_remains():
    oracle = {"/data/run/marker.txt"}
    assert _filter_preplant_paths(
        ["/data/run", "/data/run/marker.txt", "/data/input.txt"], oracle
    ) == ["/data/input.txt"]


def test_preplant_does_not_use_string_as_character_paths():
    assert _filter_preplant_paths("/data/run", {"/other/out.txt"}) == ["/data/run"]


def test_resolve_params_expands_all_runtime_tokens_in_transport_frames():
    """运行期图案不能以占位符原样发送到设备。"""
    contract = Contract(
        contract_id="contract-demo",
        finding_ids=["finding-demo"],
        unit_id="unit-demo",
        vuln_class="command_injection",
        entry=EntrySpec(kind="hap_udp", endpoint="127.0.0.1:8283"),
        identity=IdentitySpec(),
        protocol=ProtocolSpec(
            descriptor_id="descriptor-demo",
            field_values={
                "frame_first_template":
                    "set_pkgName::smartperf;echo __RUN_PATTERN__ > __MARKER_PATH__",
                "frame_second": "catch_network_traffic::__RUN_PATTERN__",
            },
        ),
        fault=FaultSpec(operator="payload_value_substitution"),
        oracle=OracleSpec(),
        risk=RiskSpec(target_process="SP_daemon"),
        cleanup=CleanupSpec(),
    )
    runner = Runner.__new__(Runner)
    params = runner._resolve_params(
        contract,
        "run-demo",
        "/data/local/tmp/vf/run-demo",
        "PATTERN-demo",
    )

    assert "__RUN_PATTERN__" not in params["frame_first"]
    assert "__MARKER_PATH__" not in params["frame_first"]
    assert params["frame_first"].startswith("set_pkgName::smartperf;echo PATTERN-demo > ")
    assert params["frame_second"] == "catch_network_traffic::PATTERN-demo"


def test_resolve_params_canonicalizes_composite_marker_path_and_file_semantics():
    """旧/LLM 契约不能把完整 marker 路径再次拼上 marker 文件名。"""
    contract = Contract(
        contract_id="contract-marker-path",
        finding_ids=["finding-marker-path"],
        unit_id="unit-marker-path",
        vuln_class="command_injection",
        entry=EntrySpec(kind="hap_udp", endpoint="127.0.0.1:8283"),
        identity=IdentitySpec(),
        protocol=ProtocolSpec(
            descriptor_id="descriptor-demo",
            field_values={
                "frame_first_template":
                    "set_pkgName::smartperf;echo __RUN_PATTERN__ > "
                    "__MARKER_PATH__/__MARKER__",
            },
        ),
        fault=FaultSpec(operator="payload_value_substitution"),
        oracle=OracleSpec(artifact_forms=[ArtifactForm(
            form="create",
            path="__MARKER_PATH__/__MARKER__",
            content_contains="__RUN_PATTERN__",
            output_is_dir=True,
        )]),
        risk=RiskSpec(target_process="SP_daemon"),
        cleanup=CleanupSpec(),
    )
    runner = Runner.__new__(Runner)
    params = runner._resolve_params(
        contract,
        "run-marker-path",
        "/data/local/tmp/vf/run-marker-path",
        "PATTERN-marker-path",
    )

    expected = (
        "/data/local/tmp/vf/run-marker-path/"
        "marker_contract-marker-path_run-marker-path.txt"
    )
    assert params["frame_first"].endswith(expected)
    assert contract.oracle.artifact_forms[0].path == expected
    assert contract.oracle.artifact_forms[0].output_is_dir is False


def test_hilog_poll_ignores_malformed_entries_instead_of_crashing(monkeypatch):
    """即使绕过编译门禁，运行器也不能因字符串期望调用 get() 崩溃。"""
    class _Hilog:
        text = ""

    monkeypatch.setattr(
        "utilities.openharmony_dynamic.runner.dump_hilog",
        lambda *args, **kwargs: _Hilog(),
    )
    runner = Runner.__new__(Runner)
    runner.hdc = object()
    runner.on_event = None
    record = RunRecord(
        run_id="run-demo",
        contract_id="contract-demo",
        started_at=0.0,
    )

    runner._wait_for_hilog_expectations(
        ["must_not_contain", "optional"],
        anchor_time=0.0,
        record=record,
        run_id="run-demo",
        poll_interval=0.0,
        max_wait=0.0,
    )

    assert record.hilog_hits == []


def test_runner_rejects_malformed_hilog_before_device_commands(tmp_path):
    """旧/直加载契约也必须在安装 HAP 前失败，并留下可读错误。"""
    class _NoDevice:
        def command_count(self):
            return 0

        def shell(self, *args, **kwargs):
            raise AssertionError("格式错误契约不应执行设备命令")

    contract = load_contract("DP-02")
    contract.oracle.hilog_expectations = ["must_not_contain"]
    runner = Runner(_NoDevice(), artifacts_root=tmp_path)

    record = runner.run(contract)

    assert record.state == "COMPILED"
    assert "hilog_expectations 格式非法" in record.error
    assert list(tmp_path.glob("*.json"))
