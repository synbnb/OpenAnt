"""Tests for deterministic evidence line reconciliation."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.evidence_line_resolver import (  # noqa: E402
    normalize_recovery_evidence,
    resolve_evidence_item,
    summarize_line_resolution,
)


def test_unique_registration_text_corrects_off_by_one_line(tmp_path: Path):
    source = tmp_path / "parser.cpp"
    source.write_text(
        "\n".join(
            [
                "void Parser::Decode() {}",
                "void Parser::Initialize() {",
                "    parseTable_ = {",
                "        {Kind::A, Parser::ParseA},",
                "    };",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    evidence = resolve_evidence_item(
        {
            "kind": "registration",
            "file": "parser.cpp",
            "start_line": 3,
            "end_line": 3,
            "text": "{Kind::A, Parser::ParseA},",
        },
        repository=tmp_path,
    )

    assert evidence["start_line"] == 4
    assert evidence["end_line"] == 4
    assert evidence["reported_start_line"] == 3
    assert evidence["line_match_count"] == 1
    assert evidence["line_resolution"] == "exact"


def test_ambiguous_text_keeps_reported_span_and_is_marked(tmp_path: Path):
    source = tmp_path / "parser.cpp"
    source.write_text(
        "\n".join(
            [
                "table[0] = Parser::ParseA;",
                "table[1] = Parser::ParseA;",
            ]
        ),
        encoding="utf-8",
    )
    evidence = resolve_evidence_item(
        {
            "kind": "registration",
            "file": "parser.cpp",
            "start_line": 1,
            "end_line": 1,
            "text": "Parser::ParseA",
        },
        repository=tmp_path,
    )

    assert evidence["start_line"] == 1
    assert evidence["end_line"] == 1
    assert evidence["line_match_count"] == 2
    assert evidence["line_resolution"] == "ambiguous"


def test_target_uses_index_span_when_model_quote_is_formatted_differently(
    tmp_path: Path,
):
    source = tmp_path / "service.cpp"
    source.write_text(
        "\n".join(
            [
                "void Service::Handle(",
                "    int value)",
                "{",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    target_id = "service.cpp:Service::Handle"
    evidence = resolve_evidence_item(
        {
            "kind": "target",
            "function_id": target_id,
            "file": "service.cpp",
            "start_line": 99,
            "end_line": 100,
            "text": "void Service::Handle(int value) {}",
        },
        repository=tmp_path,
        functions={
            target_id: {
                "file_path": "service.cpp",
                "start_line": 1,
                "end_line": 4,
            }
        },
    )

    assert evidence["start_line"] == 1
    assert evidence["end_line"] == 4
    assert evidence["line_resolution"] == "function_index"


def test_target_fallback_uses_proposal_target_id_when_function_id_is_omitted(
    tmp_path: Path,
):
    source = tmp_path / "service.cpp"
    source.write_text("void Service::Handle() {}\n", encoding="utf-8")
    target_id = "service.cpp:Service::Handle"
    evidence = resolve_evidence_item(
        {
            "kind": "target",
            "file": "service.cpp",
            "start_line": 99,
            "end_line": 99,
            "text": "Service::Handle(...)",
        },
        repository=tmp_path,
        functions={
            target_id: {
                "file_path": "service.cpp",
                "start_line": 1,
                "end_line": 1,
            }
        },
        target_id=target_id,
    )

    assert evidence["line_resolution"] == "function_index"
    assert evidence["start_line"] == 1


def test_normalize_recovery_evidence_preserves_decisions_and_summarizes(
    tmp_path: Path,
):
    source = tmp_path / "service.cpp"
    source.write_text(
        "void Service::Call() {\n    table[1] = &Service::Handle;\n}\n",
        encoding="utf-8",
    )
    target_id = "service.cpp:Service::Handle"
    proposal = {
        "site_id": "native:1:test",
        "decision": "add_edge",
        "target_id": target_id,
        "confidence": "high",
        "evidence": [
            {
                "kind": "registration",
                "file": "service.cpp",
                "start_line": 2,
                "end_line": 2,
                "text": "table[1] = &Service::Handle;",
            }
        ],
    }
    result = normalize_recovery_evidence(
        [proposal],
        [{"site_id": "native:1:test"}],
        {target_id: {"file_path": "service.cpp", "start_line": 1, "end_line": 1}},
        repository=tmp_path,
    )

    assert result[0]["decision"] == "add_edge"
    assert result[0]["target_id"] == target_id
    assert result[0]["evidence"][0]["line_resolution"] == "exact"
    assert summarize_line_resolution(result) == {"exact": 1}
