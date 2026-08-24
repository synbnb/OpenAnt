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

    assert scan_result["scope"]["platform"] == "openharmony"
    assert scan_result["scope"]["coverage"]["roles"]["fuzz"] == 1
    assert scan_result["scope"]["build_metadata"]["build_files"][0]["targets"] == [
        "health_sensor_service"
    ]
    assert dataset["metadata"]["openharmony_scope"] == scan_result["scope"]
