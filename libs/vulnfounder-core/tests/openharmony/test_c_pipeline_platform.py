"""End-to-end C pipeline contract for OpenHarmony scope metadata."""

from __future__ import annotations

import json
import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
C_PARSER_ROOT = CORE_ROOT / "parsers" / "c"
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))
if str(C_PARSER_ROOT) not in sys.path:
    sys.path.insert(0, str(C_PARSER_ROOT))

from parsers.c.test_pipeline import CPipelineTest, ProcessingLevel  # noqa: E402


TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TESTS_ROOT / "fixtures" / "openharmony" / "scope_roles"


def test_c_pipeline_persists_openharmony_scope_in_scan_and_dataset(tmp_path):
    pipeline = CPipelineTest(
        str(FIXTURE_ROOT),
        output_dir=str(tmp_path / "out"),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True
    scan_result = json.loads((tmp_path / "out" / "scan_results.json").read_text())
    dataset = json.loads((tmp_path / "out" / "dataset.json").read_text())
    diagnostics = json.loads(
        (tmp_path / "out" / "call_graph_residuals.json").read_text()
    )

    assert scan_result["scope"]["platform"] == "openharmony"
    assert scan_result["scope"]["coverage"]["roles"]["fuzz"] == 1
    assert scan_result["scope"]["build_metadata"]["build_files"][0]["targets"] == [
        "health_sensor_service"
    ]
    assert dataset["metadata"]["openharmony_scope"] == scan_result["scope"]
    assert diagnostics["platform"] == "openharmony"
    assert diagnostics["status"] == "complete"
    assert diagnostics["summary"]["unresolved_call_sites"] == 0


def test_call_graph_diagnostics_failure_is_recorded_without_failing_parser(
    monkeypatch, tmp_path
):
    def fail_diagnostics(*_args, **_kwargs):
        raise RuntimeError("diagnostic probe failed")

    monkeypatch.setattr(
        "core.platforms.openharmony.call_graph_diagnostics."
        "build_call_graph_diagnostics",
        fail_diagnostics,
    )
    pipeline = CPipelineTest(
        str(FIXTURE_ROOT),
        output_dir=str(tmp_path / "out"),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True

    diagnostics = json.loads(
        (tmp_path / "out" / "call_graph_residuals.json").read_text()
    )
    assert diagnostics["status"] == "failed"
    assert diagnostics["error"] == {
        "type": "RuntimeError",
        "message": "diagnostic probe failed",
    }
    dataset = json.loads((tmp_path / "out" / "dataset.json").read_text())
    assert dataset["metadata"]["openharmony_call_graph_diagnostics"][
        "status"
    ] == "failed"


def test_all_mode_keeps_all_units_but_persists_structural_entry_labels(tmp_path):
    """The all-units checkpoint must remain auditable without LLM reachability."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "entry.cpp").write_text(
        """
class Stub {
public:
    int OnRemoteRequest(unsigned int code) { return static_cast<int>(code); }
};

class Listener {
public:
    int OnReadable(int fd) {
        char buffer[8] = {};
        return recv(fd, buffer, sizeof(buffer), 0);
    }
};
""",
        encoding="utf-8",
    )

    pipeline = CPipelineTest(
        str(repo),
        output_dir=str(tmp_path / "out"),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True
    dataset = json.loads((tmp_path / "out" / "dataset.json").read_text())

    units = {
        unit["id"]: unit
        for unit in dataset["units"]
        if unit.get("is_entry_point") is True
    }
    assert any("OnRemoteRequest" in unit_id for unit_id in units)
    assert any("OnReadable" in unit_id for unit_id in units)
    assert len(dataset["units"]) >= 2
    assert dataset["metadata"]["entry_point_detection"]["processing_level"] == "all"
