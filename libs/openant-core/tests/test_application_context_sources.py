"""Regression tests for bounded application-context source collection."""

from __future__ import annotations

from pathlib import Path

import context.application_context as application_context


def _disable_derived_sources(monkeypatch):
    monkeypatch.setattr(application_context, "get_directory_structure", lambda *_a, **_k: "")
    monkeypatch.setattr(application_context, "detect_entry_points", lambda *_a, **_k: "")


def test_readme_under_new_limit_is_kept(tmp_path: Path, monkeypatch):
    _disable_derived_sources(monkeypatch)
    readme = "A" * 18_090
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")

    sources = application_context.gather_context_sources(tmp_path)

    assert sources["README.md"] == readme
    assert "[context_budget]" not in sources


def test_oversized_priority_file_is_truncated_and_marked(tmp_path: Path, monkeypatch):
    _disable_derived_sources(monkeypatch)
    monkeypatch.setattr(application_context, "CONTEXT_FILE_MAX_BYTES", 20)
    monkeypatch.setattr(application_context, "CONTEXT_TOTAL_MAX_BYTES", 100)
    (tmp_path / "README.md").write_text("R" * 40, encoding="utf-8")

    sources = application_context.gather_context_sources(tmp_path)

    assert sources["README.md"].startswith("R" * 20)
    assert sources["README.md"].endswith("[... truncated ...]")


def test_total_context_budget_is_visible_and_stops_later_files(
    tmp_path: Path, monkeypatch
):
    _disable_derived_sources(monkeypatch)
    monkeypatch.setattr(application_context, "CONTEXT_FILE_MAX_BYTES", 10)
    monkeypatch.setattr(application_context, "CONTEXT_TOTAL_MAX_BYTES", 10)
    (tmp_path / "README.md").write_text("R" * 10, encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("C" * 10, encoding="utf-8")

    sources = application_context.gather_context_sources(tmp_path)

    assert "README.md" in sources
    assert "CLAUDE.md" not in sources
    assert "[context_budget]" in sources
    assert "10 bytes" in sources["[context_budget]"]
