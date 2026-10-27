"""源码交付快照的安全边界与可复现清单测试。"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))
sys.path.insert(0, str(_CORE_ROOT / "utilities"))

from core.exp_package import (  # noqa: E402
    _create_hvigor_safe_tempdir,
    build_deliverables,
    _package_poc_only,
    _package_source_snapshot,
)


def test_hvigor_build_tempdir_avoids_unicode_run_path(tmp_path: Path):
    run_dir = tmp_path / "项目目录" / "runs" / "run-1"
    run_dir.mkdir(parents=True)

    build_temp = _create_hvigor_safe_tempdir()
    try:
        build_root = Path(build_temp.name).resolve()
        assert run_dir.resolve() not in build_root.parents
        assert all(
            char.isascii() and (char.isalnum() or char in "/._() @-")
            for char in str(build_root)
        )
    finally:
        build_temp.cleanup()


def test_hvigor_build_tempdir_falls_back_when_system_temp_has_unicode(
    tmp_path: Path, monkeypatch,
):
    from core import exp_package

    unsafe_temp = tmp_path / "临时目录"
    unsafe_temp.mkdir()
    monkeypatch.setattr(exp_package.tempfile, "gettempdir", lambda: str(unsafe_temp))

    build_temp = _create_hvigor_safe_tempdir()
    try:
        build_root = Path(build_temp.name).resolve()
        assert all(
            char.isascii() and (char.isalnum() or char in "/._() @-")
            for char in str(build_root)
        )
    finally:
        build_temp.cleanup()


def test_exp_build_failure_keeps_confirmed_poc_source_downloadable(
    tmp_path: Path, monkeypatch,
):
    from openharmony_dynamic.transports import hap

    run_dir = tmp_path / "中文项目" / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    poc_project = tmp_path / "poc-build" / "project"
    index = poc_project / "Entry/src/main/ets/pages/Index.ets"
    index.parent.mkdir(parents=True)
    index.write_text("export struct Index { build() {} }\n", encoding="utf-8")
    poc_hap = tmp_path / "poc-build" / "entry-default-signed.hap"
    poc_hap.parent.mkdir(parents=True, exist_ok=True)
    poc_hap.write_bytes(b"signed-poc")

    seen_work_roots = []

    class FailingExpTransport:
        def __init__(self, _hdc, *, work_root):
            self.work_root = Path(work_root)
            seen_work_roots.append(self.work_root)

        def build(self, _field_values, *, contract_id):
            assert contract_id == "EXP-test"
            raise RuntimeError("Hvigor 00306003 invalid project path")

    monkeypatch.setattr(hap, "HapTransport", FailingExpTransport)

    class FakeHdc:
        def run(self, _argv, *, purpose):
            if purpose == "exp:probe-victim":
                return SimpleNamespace(returncode=1, stdout="No such file")
            raise AssertionError(f"unexpected HDC call: {purpose}")

    contract = {
        "contract_id": "GEN-test",
        "protocol": {
            "descriptor_id": "dynamic_text",
            "field_values": {
                "mode": "udp", "host": "127.0.0.1", "port": 8283,
                "target": "GEN-test", "set_pkgName": "smartperf",
            },
            "param_space": {"frame_first_template": "set_pkgName::smartperf"},
        },
        "fault": {"description": "confirmed test finding", "evidence": "fixture"},
        "oracle": {"kind": "artifact_differential"},
    }

    pkg = build_deliverables(
        run_dir=run_dir,
        poc_contract=contract,
        poc_hap=poc_hap,
        vuln_class="command_injection",
        finding={},
        hdc=FakeHdc(),
    )

    assert pkg.status == "poc_only"
    assert "Exp HAP 构建失败" in pkg.reason
    assert {item["name"] for item in pkg.files} >= {
        "poc.hap", "poc_source.zip", "poc_source_manifest.json", "contract_poc.json",
    }
    assert (run_dir / "deliverables" / "poc_source.zip").is_file()
    assert len(seen_work_roots) == 1
    assert "中文" not in str(seen_work_roots[0])
    assert not seen_work_roots[0].exists()


def test_confirmed_run_packages_poc_and_exp_sources_from_unicode_run_dir(
    tmp_path: Path, monkeypatch,
):
    from openharmony_dynamic.transports import hap
    import time

    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    run_dir = tmp_path / "中文项目" / "runs" / "run-2"
    run_dir.mkdir(parents=True)
    poc_build = tmp_path / "poc-build"
    poc_project = poc_build / "project"
    (poc_project / "Entry/src/main/ets/pages").mkdir(parents=True)
    (poc_project / "Entry/src/main/ets/pages/Index.ets").write_text(
        "export struct POCIndex { build() {} }\n", encoding="utf-8")
    poc_hap = poc_build / "entry-default-signed.hap"
    poc_hap.write_bytes(b"signed-poc")

    seen_work_roots = []

    class SuccessfulExpTransport:
        def __init__(self, _hdc, *, work_root):
            self.work_root = Path(work_root)
            seen_work_roots.append(self.work_root)

        def build(self, _field_values, *, contract_id):
            build_dir = self.work_root / f"vf-hap-{contract_id}"
            project = build_dir / "project"
            (project / "Entry/src/main/ets/pages").mkdir(parents=True)
            (project / "Entry/src/main/ets/pages/Index.ets").write_text(
                "export struct EXPIndex { build() {} }\n", encoding="utf-8")
            (project / "module.json5").write_text("{}\n", encoding="utf-8")
            signed = build_dir / "entry-default-signed.hap"
            build_dir.mkdir(parents=True, exist_ok=True)
            signed.write_bytes(b"signed-exp")
            return signed

        def install_and_start(self, _hap_path):
            return SimpleNamespace(reachability="INPUT_DELIVERED")

        def cleanup(self):
            return None

    monkeypatch.setattr(hap, "HapTransport", SuccessfulExpTransport)

    class FakeHdc:
        def run(self, _argv, *, purpose):
            if purpose == "exp:probe-victim":
                return SimpleNamespace(returncode=1, stdout="No such file")
            if purpose == "exp:verify-takeout":
                return SimpleNamespace(returncode=0, stdout="artifact exists")
            raise AssertionError(f"unexpected HDC call: {purpose}")

    contract = {
        "contract_id": "GEN-test",
        "protocol": {
            "descriptor_id": "dynamic_text",
            "field_values": {
                "mode": "udp", "host": "127.0.0.1", "port": 8283,
                "target": "GEN-test", "set_pkgName": "smartperf",
            },
            "param_space": {"frame_first_template": "set_pkgName::smartperf"},
        },
        "fault": {"description": "confirmed test finding", "evidence": "fixture"},
        "oracle": {"kind": "artifact_differential"},
    }

    pkg = build_deliverables(
        run_dir=run_dir,
        poc_contract=contract,
        poc_hap=poc_hap,
        vuln_class="command_injection",
        finding={},
        hdc=FakeHdc(),
    )

    assert pkg.status == "packaged"
    assert {item["name"] for item in pkg.files} >= {
        "poc.hap", "exp.hap", "poc_source.zip", "exp_source.zip",
    }
    assert (run_dir / "deliverables" / "poc_source.zip").is_file()
    assert (run_dir / "deliverables" / "exp_source.zip").is_file()
    assert "中文" not in str(seen_work_roots[0])
    assert not seen_work_roots[0].exists()


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


def test_package_poc_only_keeps_poc_when_exp_template_is_unavailable(tmp_path: Path):
    project = tmp_path / "poc-build" / "project"
    (project / "Entry/src/main/ets/pages").mkdir(parents=True)
    (project / "Entry/src/main/ets/pages/Index.ets").write_text(
        "const FIRST = 'set_pkgName::test';\n", encoding="utf-8")
    hap = project.parent / "entry-default-signed.hap"
    hap.write_bytes(b"fake-hap")
    out = tmp_path / "deliverables"
    out.mkdir()
    contract = {
        "contract_id": "GEN-test",
        "protocol": {"descriptor_id": "dynamic_text"},
    }

    pkg = _package_poc_only(
        out_dir=out, poc_contract=contract, poc_hap=hap,
        reason="没有可验证的升级模板",
    )

    assert pkg.status == "poc_only"
    names = {item["name"] for item in pkg.files}
    assert {"poc.hap", "contract_poc.json", "README.md",
            "poc_source.zip", "poc_source_manifest.json"} <= names
    assert not (out / "exp.hap").exists()
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "仅 PoC" in readme
    assert "未经验证的" in readme and "Exp" in readme
