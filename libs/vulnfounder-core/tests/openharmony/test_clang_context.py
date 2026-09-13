"""Tests for bounded OpenHarmony Clang-context discovery."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from core.platforms.openharmony.clang_context import prepare_clang_context


def _write_database(root: Path) -> Path:
    source = root / "sample.cpp"
    source.write_text("void sample() {}\n", encoding="utf-8")
    database = root / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": "sample.cpp",
                    "arguments": ["clang++", "-c", "sample.cpp", "-o", "sample.o"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return database


def test_prepare_uses_explicit_compile_database(tmp_path):
    database = _write_database(tmp_path)

    result = prepare_clang_context(
        tmp_path,
        explicit_compile_commands=database,
        output_dir=tmp_path / "context",
    )

    assert result["status"] == "compile_database_found"
    assert result["source"] == "explicit"
    assert result["compile_commands"] == str(database.resolve())
    assert result["diagnostics"][-1]["existing_source_entries"] == 1


def test_prepare_reports_unavailable_without_build_context(tmp_path):
    result = prepare_clang_context(tmp_path, output_dir=tmp_path / "context")

    assert result["status"] == "context_unavailable"
    assert result["compile_commands"] is None
    assert any(
        item.get("error") == "no_compile_database_or_ninja_build_output"
        for item in result["diagnostics"]
    )


def test_prepare_reconstructs_candidate_commands_from_build_gn(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void sample() {}\n", encoding="utf-8")
    (tmp_path / "BUILD.gn").write_text(
        'executable("sample") {\n'
        '  sources = [ "sample.cpp" ]\n'
        '  include_dirs = [ "." ]\n'
        '  defines = [ "SAMPLE_DEFINE=1" ]\n'
        '}\n',
        encoding="utf-8",
    )

    result = prepare_clang_context(
        tmp_path,
        output_dir=tmp_path / "context",
        requested_files=["sample.cpp"],
    )

    assert result["status"] == "reconstructed_candidate"
    assert result["source"] == "build_gn_reconstruction"
    assert result["build_admission"] == "candidate_only"
    database = json.loads(Path(result["compile_commands"]).read_text(encoding="utf-8"))
    assert len(database) == 1
    assert "-DSAMPLE_DEFINE=1" in database[0]["arguments"]


def test_prepare_reconstruction_keeps_priority_source_with_small_budget(tmp_path):
    for name in ("first.cpp", "second.cpp", "hot.cpp"):
        (tmp_path / name).write_text("void value() {}\n", encoding="utf-8")
    (tmp_path / "BUILD.gn").write_text(
        'executable("sample") {\n'
        '  sources = [ "first.cpp", "second.cpp", "hot.cpp" ]\n'
        '}\n',
        encoding="utf-8",
    )

    result = prepare_clang_context(
        tmp_path,
        output_dir=tmp_path / "context",
        requested_files=["first.cpp", "second.cpp", "hot.cpp"],
        priority_files=["hot.cpp"],
        max_files=1,
    )

    database = json.loads(Path(result["compile_commands"]).read_text(encoding="utf-8"))
    assert len(database) == 1
    assert database[0]["file"].endswith("/hot.cpp")


def test_prepare_reconstruction_inherits_config_include_dirs_and_cflags(tmp_path):
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    (include_dir / "local_header.h").write_text(
        "#pragma once\n#define FROM_CONFIG 1\n", encoding="utf-8"
    )
    source = tmp_path / "sample.cpp"
    source.write_text('#include "local_header.h"\nint sample() { return FROM_CONFIG; }\n', encoding="utf-8")
    (tmp_path / "BUILD.gn").write_text(
        'config("headers") {\n'
        '  include_dirs = [ "include" ]\n'
        '  cflags_cc = [ "-DCONFIG_ENABLED" ]\n'
        '}\n'
        'executable("sample") {\n'
        '  sources = [ "sample.cpp" ]\n'
        '  public_configs = [ ":headers" ]\n'
        '}\n',
        encoding="utf-8",
    )

    result = prepare_clang_context(
        tmp_path,
        output_dir=tmp_path / "context",
        requested_files=["sample.cpp"],
    )

    assert result["status"] == "reconstructed_candidate"
    database = json.loads(Path(result["compile_commands"]).read_text(encoding="utf-8"))
    arguments = database[0]["arguments"]
    assert f"-I{include_dir.resolve()}" in arguments
    assert "-DCONFIG_ENABLED" in arguments


@pytest.mark.skipif(shutil.which("ninja") is None, reason="ninja is unavailable")
def test_prepare_exports_existing_ninja_compdb(tmp_path):
    source = tmp_path / "sample.cpp"
    source.write_text("void sample() {}\n", encoding="utf-8")
    (tmp_path / "build.ninja").write_text(
        "rule cxx\n"
        "  command = clang++ -c $in -o $out\n"
        "build sample.o: cxx sample.cpp\n",
        encoding="utf-8",
    )

    result = prepare_clang_context(tmp_path, output_dir=tmp_path / "context")

    assert result["status"] == "ninja_compdb_exported"
    exported = Path(result["compile_commands"])
    assert exported.is_file()
    assert result["diagnostics"][-1]["entries"] == 1
