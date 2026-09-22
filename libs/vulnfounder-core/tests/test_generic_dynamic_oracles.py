"""通用动态预言机的无设备契约测试。

这些测试只验证观测值到判定的映射，不把任何具体服务名、端口或样本写进
运行器逻辑。设备侧命令仍由 Runner 通过 HDCClient 执行。
"""

from __future__ import annotations

from utilities.openharmony_dynamic.models import ArtifactForm, OracleSpec
from utilities.openharmony_dynamic.observation.oracles import evaluate_declared_oracle
from utilities.openharmony_dynamic.observation.snapshot import FileSnapshot


def test_readback_oracle_requires_new_response_signal():
    spec = OracleSpec(
        kind="readback_differential",
        config={"content_contains": "vf-response"},
    )
    result = evaluate_declared_oracle(
        spec,
        {},
        {},
        response_before="denied",
        response_after="ok vf-response",
    )
    assert result.effect_observed is True
    assert result.details["before_contains"] is False
    assert result.details["after_contains"] is True


def test_resource_oracle_reports_delta_and_threshold():
    spec = OracleSpec(
        kind="resource_delta",
        config={"metric": "fd_count", "min_delta": 2},
    )
    result = evaluate_declared_oracle(
        spec,
        {},
        {},
        process_before={"alive": True, "fd_count": 10},
        process_after={"alive": True, "fd_count": 12},
    )
    assert result.effect_observed is True
    assert result.details["delta"] == 2
    assert result.forms["resource_growth"] is True


def test_crash_oracle_requires_fault_correlation_by_default():
    spec = OracleSpec(kind="crash_correlated")
    result = evaluate_declared_oracle(
        spec,
        {},
        {},
        process_before={"alive": True},
        process_after={"alive": False},
    )
    assert result.effect_observed is False
    assert result.details["faultlog_match"] is False


def test_state_oracle_preserves_changed_keys():
    spec = OracleSpec(kind="state_differential", config={"keys": ["mode"]})
    result = evaluate_declared_oracle(
        spec,
        {},
        {},
        state_before={"mode": "idle"},
        state_after={"mode": "active"},
    )
    assert result.effect_observed is True
    assert result.details["changes"]["mode"] == {
        "before": "idle", "after": "active"
    }


def test_artifact_oracle_keeps_existing_semantics():
    marker = FileSnapshot(path="/data/local/tmp/vf/marker", exists=True, content="vf-run")
    missing = FileSnapshot(path="/data/local/tmp/vf/marker", exists=False)
    spec = OracleSpec(
        kind="artifact_differential",
        artifact_forms=[ArtifactForm(
            form="create",
            path="/data/local/tmp/vf/marker",
            content_contains="vf-run",
        )],
    )
    result = evaluate_declared_oracle(spec, {spec.artifact_forms[0].path: missing}, {spec.artifact_forms[0].path: marker})
    assert result.effect_observed is True
    assert result.kind == "artifact_differential"
