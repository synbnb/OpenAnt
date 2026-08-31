"""Tests for bounded cross-function registration context collection."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[2]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from core.platforms.openharmony.registration_context import (  # noqa: E402
    build_registration_context,
)


def _site(*, caller_id: str, caller_file: str, dispatch_table: str, targets: list[str]):
    return {
        "site_id": "native:1:test",
        "caller_id": caller_id,
        "file": caller_file,
        "line": 8,
        "expression": "it->second(value)",
        "symbols": {"dispatch_table": dispatch_table, "target_variable": "it->second"},
        "candidate_target_ids": targets,
    }


def _function(name: str, file_path: str, start_line: int = 1) -> dict:
    return {
        "name": name,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line + 2,
        "code": f"void {name}() {{}}",
    }


def test_collects_table_initialization_and_registration_lines(tmp_path: Path):
    source = tmp_path / "services" / "parser.cpp"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            [
                "void Parser::Initialize() {}",
                "void Parser::Process() {",
                "    auto it = parseTable_.find(kind);",
                "    it->second(value);",
                "}",
                "void Parser::InitializeParseTable() {",
                "    parseTable_ = {",
                "        {Kind::A, Parser::ParseA},",
                "        {Kind::B, Parser::ParseB},",
                "    };",
                "}",
                "void Parser::ParseA() {}",
                "void Parser::ParseB() {}",
            ]
        ),
        encoding="utf-8",
    )
    caller_id = "services/parser.cpp:Parser::Process"
    target_a = "services/parser.cpp:Parser::ParseA"
    target_b = "services/parser.cpp:Parser::ParseB"
    result = build_registration_context(
        _site(
            caller_id=caller_id,
            caller_file="services/parser.cpp",
            dispatch_table="parseTable_",
            targets=[target_a, target_b],
        ),
        {
            caller_id: _function("Parser::Process", "services/parser.cpp", 2),
            target_a: _function("Parser::ParseA", "services/parser.cpp", 11),
            target_b: _function("Parser::ParseB", "services/parser.cpp", 12),
        },
        repository=tmp_path,
    )

    assert result["status"] == "found"
    assert result["dispatch_table"] == "parseTable_"
    assert any(
        "parseTable_ =" in snippet["text"]
        and "candidate_name" in snippet["match_reasons"]
        for snippet in result["snippets"]
    )
    assert any(
        "4 |" in snippet["line_numbered_text"]
        and "Kind::A, Parser::ParseA" in snippet["line_numbered_text"]
        for snippet in result["snippets"]
    )
    assert any("it->second(value)" in snippet["text"] for snippet in result["snippets"])
    assert all(not Path(snippet["file"]).is_absolute() for snippet in result["snippets"])


def test_collects_cross_file_constructor_and_default_registration(tmp_path: Path):
    factory = tmp_path / "tools" / "factory.cpp"
    header = tmp_path / "tools" / "factory.h"
    factory.parent.mkdir(parents=True)
    factory.write_text(
        "\n".join(
            [
                "std::shared_ptr<Stream> Factory::Create(uint32_t type) {",
                "    auto it = creators_.find(type);",
                "    return it->second();",
                "}",
                "void Factory::RegisterDefaultCreator() {",
                "    RegisterCreator(Type::A, StreamA::Instance);",
                "    RegisterCreator(Type::B, StreamB::Instance);",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    header.write_text(
        "\n".join(
            [
                "class Factory {",
                "    Factory() { RegisterDefaultCreator(); }",
                "};",
            ]
        ),
        encoding="utf-8",
    )
    caller_id = "tools/factory.cpp:Factory::Create"
    target_a = "tools/stream.h:StreamA::Instance"
    target_b = "tools/stream.h:StreamB::Instance"
    result = build_registration_context(
        _site(
            caller_id=caller_id,
            caller_file="tools/factory.cpp",
            dispatch_table="creators_",
            targets=[target_a, target_b],
        ),
        {
            caller_id: _function("Factory::Create", "tools/factory.cpp"),
            target_a: _function("StreamA::Instance", "tools/stream.h"),
            target_b: _function("StreamB::Instance", "tools/stream.h"),
        },
        repository=tmp_path,
    )

    assert result["status"] == "found"
    files = {snippet["file"] for snippet in result["snippets"]}
    assert "tools/factory.cpp" in files
    assert "tools/factory.h" in files
    combined = "\n".join(snippet["text"] for snippet in result["snippets"])
    assert "RegisterCreator(Type::A" in combined
    assert "RegisterDefaultCreator();" in combined


def test_missing_or_out_of_root_source_is_safe(tmp_path: Path):
    caller_id = "missing.cpp:Caller::Call"
    result = build_registration_context(
        _site(
            caller_id=caller_id,
            caller_file="missing.cpp",
            dispatch_table="table_",
            targets=[],
        ),
        {caller_id: _function("Caller::Call", "missing.cpp")},
        repository=tmp_path / "does-not-exist",
    )

    assert result["status"] == "source_unavailable"
    assert result["snippets"] == []
