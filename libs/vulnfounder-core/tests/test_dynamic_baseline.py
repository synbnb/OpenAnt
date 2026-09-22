"""阶段 0：动态样本基线和 clean-room 输入边界。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
UTILITIES = CORE / "utilities"
for path in (CORE, UTILITIES):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from openharmony_dynamic.baseline import build_baseline, baseline_item  # noqa: E402
from openharmony_dynamic.finding_input import FindingInput  # noqa: E402


def _finding(tmp_path: Path, *, finding_id: str = "DP-BASELINE-01") -> FindingInput:
    source = tmp_path / "src" / "service.cpp"
    source.parent.mkdir(parents=True)
    source.write_text("void Service::Handle() { LoadCmd(input); }\n", encoding="utf-8")
    return FindingInput(
        finding_id=finding_id,
        unit_id="unit-1",
        vuln_class="command_injection",
        description="外部字段进入命令执行点",
        source_paths=["src/service.cpp"],
        evidence_lines=[[1, 1]],
        sink="SPUtils::LoadCmd",
        entry_hints=["Service::Handle"],
        candidate_attack_chains=[["Socket::Recv", "Service::Handle", "SPUtils::LoadCmd"]],
        repo_root=str(tmp_path),
        analysis_context={
            "source_revision": "sample-revision",
            "reference_revision": "fixed-revision",
            "unresolved_questions": ["设备版本是否匹配"],
        },
    )


def test_clean_room_baseline_hashes_source_and_hides_answer_chain(tmp_path):
    item = baseline_item(_finding(tmp_path), clean_room=True)

    assert item["source_snapshot"][0]["exists"] is True
    assert len(item["source_snapshot"][0]["sha256"]) == 64
    assert item["model_context"]["mode"] == "clean_room"
    assert item["model_context"]["allowed_sources"] == [
        "current_finding", "current_source_evidence"
    ]
    assert "historical_exemplar" in item["model_context"]["forbidden_sources"]
    assert item["candidate_route_count"] == 1
    # 候选链可以供审计核对，但不能通过 model_context 变成模型输入。
    assert "candidate_attack_chains" not in item["model_context"]
    assert item["audit_only"]["candidate_attack_chains_present"] is True


def test_assisted_baseline_explicitly_records_extra_sources(tmp_path):
    item = baseline_item(_finding(tmp_path), clean_room=False)
    assert item["model_context"]["mode"] == "assisted"
    assert item["model_context"]["allowed_sources"][-2:] == ["device_facts", "exemplar"]
    assert item["model_context"]["forbidden_sources"] == []


def test_build_baseline_rejects_duplicate_sample_ids(tmp_path):
    finding = _finding(tmp_path)
    with pytest.raises(ValueError, match="重复 sample_id"):
        build_baseline([finding, finding])


def test_build_baseline_is_serializable_and_preserves_revision(tmp_path):
    payload = build_baseline([_finding(tmp_path)], clean_room=True)
    encoded = json.dumps(payload, ensure_ascii=False)
    assert "sample-revision" in encoded
    assert payload["schema_version"] == "vf.dynamic.baseline.v1"
    assert payload["sample_count"] == 1
