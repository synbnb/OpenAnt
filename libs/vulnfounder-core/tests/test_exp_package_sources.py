"""源码交付快照的安全边界与可复现清单测试。"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from core.exp_package import _package_source_snapshot  # noqa: E402


def test_package_source_snapshot_contains_project_and_excludes_host_files(tmp_path: Path):
    project = tmp_path / "project"
    (project / "Entry/src/main/ets/pages").mkdir(parents=True)
    (project / "build").mkdir()
    (project / "Entry/src/main/ets/pages/Index.ets").write_text(
        "export struct Index {}\n", encoding="utf-8")
    (project / "module.json5").write_text("{}\n", encoding="utf-8")
    (project / "local.properties").write_text("sdk.dir=/private/host/path\n", encoding="utf-8")
    (project / "build/generated.txt").write_text("cache", encoding="utf-8")

    out = tmp_path / "deliverables"
    out.mkdir()
    snapshot = _package_source_snapshot(project, out, "poc")
    assert snapshot["file_count"] == 3  # two source files + sanitized example
    manifest = json.loads((out / "poc_source_manifest.json").read_text(encoding="utf-8"))
    paths = {entry["path"] for entry in manifest["files"]}
    assert "Entry/src/main/ets/pages/Index.ets" in paths
    assert "module.json5" in paths
    assert "local.properties.example" in paths
    assert all("/private/host/path" not in p for p in paths)
    assert not (out / "poc_source" / "build" / "generated.txt").exists()

    with zipfile.ZipFile(out / "poc_source.zip") as archive:
        names = set(archive.namelist())
        assert "poc_source/Entry/src/main/ets/pages/Index.ets" in names
        assert "poc_source/local.properties.example" in names
        assert all("build/" not in name for name in names)
