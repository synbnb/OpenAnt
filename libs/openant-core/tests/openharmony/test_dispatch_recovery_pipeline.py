"""OH-22E-2: persist the dispatch-recovery diff through the C pipeline."""

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


FIXTURE_ROOT = CORE_ROOT / "tests" / "fixtures" / "openharmony" / "scope_roles"

ENTRY = "app.cpp:Main"
STUB = "service.cpp:ServiceStub::OnRemoteRequest"
HANDLER = "service.cpp:Service::Enable"
TX = "idl:transaction:OHOS.IService:ENABLE"


def _semantic_graph() -> dict:
    return {
        "schema_version": 1,
        "nodes": [
            {"id": f"function:{STUB}", "kind": "function"},
            {"id": TX, "kind": "ipc_transaction"},
            {"id": f"function:{HANDLER}", "kind": "function"},
        ],
        "edges": [
            {
                "source_id": f"function:{STUB}",
                "target_id": TX,
                "kind": "stub_to_transaction",
            },
            {
                "source_id": TX,
                "target_id": f"function:{HANDLER}",
                "kind": "transaction_to_handler",
            },
        ],
    }


def test_openharmony_parser_persists_initial_dispatch_diff_artifact(tmp_path):
    output_dir = tmp_path / "out"
    pipeline = CPipelineTest(
        str(FIXTURE_ROOT),
        output_dir=str(output_dir),
        processing_level=ProcessingLevel.ALL,
        platform="openharmony",
    )

    assert pipeline.setup() is True
    assert pipeline.run_parser_pipeline() is True

    report_path = output_dir / "dispatch_recovery_diff.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text())
    assert report["platform"] == "openharmony"
    assert report["status"] == "complete"
    assert report["reachability"]["status"] == "not_evaluated"
    assert report["summary"]["native_edge_count"] == 0
    assert pipeline.dispatch_recovery_diff_file == str(report_path)

    dataset = json.loads((output_dir / "dataset.json").read_text())
    assert dataset["metadata"]["openharmony_dispatch_recovery_diff"] == {
        "path": "dispatch_recovery_diff.json",
        "status": "complete",
        **report["summary"],
    }
    stage_summary = pipeline.results["stages"]["c_parser"]["summary"]
    assert stage_summary["dispatch_recovery_diff"] == {
        "path": "dispatch_recovery_diff.json",
        "status": "complete",
        **report["summary"],
    }


def test_reachability_stage_refreshes_dispatch_diff_with_monotonicity(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    functions = {
        ENTRY: {"name": "Main", "unit_type": "main", "code": "dispatch();"},
        STUB: {"name": "OnRemoteRequest", "unit_type": "method", "code": ""},
        HANDLER: {"name": "Enable", "unit_type": "method", "code": ""},
    }
    call_graph = {
        "functions": functions,
        "call_graph": {ENTRY: [STUB]},
        "reverse_call_graph": {STUB: [ENTRY]},
    }
    units = [
        {
            "id": unit_id,
            "metadata": {
                "direct_calls": [STUB] if unit_id == ENTRY else [],
                "direct_callers": [ENTRY] if unit_id == STUB else [],
            },
        }
        for unit_id in (ENTRY, STUB, HANDLER)
    ]
    (output_dir / "analyzer.json").write_text(json.dumps({"functions": functions}))
    (output_dir / "call_graph.json").write_text(json.dumps(call_graph))
    (output_dir / "dataset.json").write_text(json.dumps({"units": units}))
    (output_dir / "semantic_graph.json").write_text(json.dumps(_semantic_graph()))
    (output_dir / "call_graph_residuals.json").write_text(
        json.dumps({"unresolved_call_sites": [], "orphans": []})
    )

    pipeline = CPipelineTest(
        str(tmp_path),
        output_dir=str(output_dir),
        processing_level=ProcessingLevel.REACHABLE,
        platform="openharmony",
    )
    pipeline.analyzer_output_file = str(output_dir / "analyzer.json")
    pipeline.dataset_file = str(output_dir / "dataset.json")
    pipeline.call_graph_file = str(output_dir / "call_graph.json")
    pipeline.semantic_graph_file = str(output_dir / "semantic_graph.json")
    pipeline.call_graph_residuals_file = str(output_dir / "call_graph_residuals.json")

    assert pipeline.apply_reachability_filter() is True

    report_path = output_dir / "dispatch_recovery_diff.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text())
    assert report["reachability"] == {
        "status": "preserved",
        "baseline_count": 2,
        "recovered_count": 3,
        "added_function_ids": [HANDLER],
        "removed_function_ids": [],
        "missing_from_recovered": [],
    }
    assert report["added_edges"] == [
        {
            "source_id": STUB,
            "target_id": HANDLER,
            "edge_kinds": ["stub_to_transaction", "transaction_to_handler"],
        }
    ]
    assert pipeline.results["stages"]["reachability_filter"]["summary"][
        "dispatch_recovery_diff"
    ]["path"] == "dispatch_recovery_diff.json"


def test_empty_entrypoint_safety_net_is_reflected_in_recovered_diff(tmp_path):
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    first = "worker.cpp:Worker::Compute"
    second = "worker.cpp:Worker::Helper"
    functions = {
        first: {
            "name": "Worker::Compute",
            "unit_type": "method",
            "code": "",
            "isExported": False,
        },
        second: {
            "name": "Worker::Helper",
            "unit_type": "method",
            "code": "",
            "isExported": False,
        },
    }
    call_graph = {
        "functions": functions,
        "call_graph": {first: [second]},
        "reverse_call_graph": {second: [first]},
    }
    units = [
        {
            "id": unit_id,
            "metadata": {
                "direct_calls": [second] if unit_id == first else [],
                "direct_callers": [first] if unit_id == second else [],
            },
        }
        for unit_id in (first, second)
    ]
    (output_dir / "analyzer.json").write_text(json.dumps({"functions": functions}))
    (output_dir / "call_graph.json").write_text(json.dumps(call_graph))
    (output_dir / "dataset.json").write_text(json.dumps({"units": units}))

    pipeline = CPipelineTest(
        str(tmp_path),
        output_dir=str(output_dir),
        processing_level=ProcessingLevel.REACHABLE,
        platform="openharmony",
    )
    pipeline.analyzer_output_file = str(output_dir / "analyzer.json")
    pipeline.dataset_file = str(output_dir / "dataset.json")
    pipeline.call_graph_file = str(output_dir / "call_graph.json")

    assert pipeline.apply_reachability_filter() is True

    report = json.loads(
        (output_dir / "dispatch_recovery_diff.json").read_text()
    )
    assert report["reachability"]["status"] == "preserved"
    assert report["reachability"]["baseline_count"] == 0
    assert report["reachability"]["recovered_count"] == 2
