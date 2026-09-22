"""scan-artifact 失败与成功路径的标准化产物契约。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from core.scan_artifact_bridge import (  # noqa: E402
    ScanDynamicResult,
    _persist_standard_artifacts,
)


def _result() -> ScanDynamicResult:
    entry = SimpleNamespace(
        sample="SAMPLE-1",
        function_analyzed="Service::Handle",
        target_id="unit-1",
    )
    # ScanDynamicResult only uses the three attributes above in the helper;
    # SimpleNamespace keeps this test independent of scan fixture files.
    return ScanDynamicResult(entry=entry, bridge={})


def test_blocked_compile_writes_all_standard_artifacts(tmp_path):
    result = _result()
    result.compile_status = "REQUIRES_PROTOCOL_REVIEW"
    result.descriptor_resolution = {"auto_status": "REJECTED"}
    result.protocol_evidence = {"status": "insufficient"}
    result.status = "BLOCKED_PROTOCOL"

    progress = tmp_path / "progress.jsonl"
    _persist_standard_artifacts(result, progress, phase="compile", reason="missing framing")

    names = {
        "protocol_contract.json", "probe_result.json", "payload_manifest.json",
        "input_influence.json", "oracle_result.json", "dynamic_result.json",
        "cleanup_result.json",
    }
    assert names == {item.name for item in tmp_path.iterdir() if item.name.endswith(".json")}
    dynamic = (tmp_path / "dynamic_result.json").read_text(encoding="utf-8")
    assert "BLOCKED_PROTOCOL" in dynamic
    influence = (tmp_path / "input_influence.json").read_text(encoding="utf-8")
    assert "NOT_RUN" in influence


def test_effect_does_not_automatically_claim_input_influence(tmp_path):
    result = _result()
    result.status = "NOT_REPRODUCED"
    result.verdict = {
        "status": "NOT_REPRODUCED",
        "influence": "SINK_CONTROLLED",
        "oracle": {"kind": "artifact_differential", "effect_observed": False},
    }
    _persist_standard_artifacts(result, tmp_path / "progress.jsonl", phase="run")
    text = (tmp_path / "input_influence.json").read_text(encoding="utf-8")
    assert '"status": "PROVEN"' in text
    oracle = (tmp_path / "oracle_result.json").read_text(encoding="utf-8")
    assert '"status": "ABSENT"' in oracle
