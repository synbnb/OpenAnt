from __future__ import annotations

import json

from utilities.openharmony_dynamic import toolchain


def _make_toolchain(root, name: str, version: str):
    path = root / "runtime" / "openharmony" / name
    (path / "sdk/default/openharmony/toolchains").mkdir(parents=True)
    (path / "manifest.json").write_text(
        json.dumps({"openharmony_version": version}), encoding="utf-8"
    )
    return path


def test_default_target_is_openharmony_7():
    assert toolchain.target_openharmony_version({}) == "7.0"
    assert toolchain.target_openharmony_revision({}) == "OpenHarmony-7.0-Release"


def test_revision_style_environment_is_normalized():
    env = {"VULNFOUNDER_OPENHARMONY_VERSION": "OpenHarmony-6.1-LTS"}
    assert toolchain.target_openharmony_version(env) == "6.1-LTS"


def test_toolchain_selection_does_not_silently_choose_old_version(tmp_path, monkeypatch):
    old = _make_toolchain(tmp_path, "macos-arm64-6.1", "6.1")
    new = _make_toolchain(tmp_path, "macos-arm64-7.0", "7.0")
    monkeypatch.setattr(toolchain, "project_root", lambda: tmp_path)
    monkeypatch.delenv("VULNFOUNDER_DYNAMIC_TOOLCHAIN", raising=False)
    monkeypatch.delenv("OPENANT_DYNAMIC_TOOLCHAIN", raising=False)
    monkeypatch.delenv("VULNFOUNDER_OPENHARMONY_VERSION", raising=False)
    monkeypatch.delenv("OPENANT_OPENHARMONY_VERSION", raising=False)
    assert toolchain.toolchain_root() == new
    assert toolchain.toolchain_root() != old


def test_explicit_toolchain_override_is_respected(tmp_path, monkeypatch):
    old = _make_toolchain(tmp_path, "macos-arm64-6.1", "6.1")
    monkeypatch.setenv("VULNFOUNDER_DYNAMIC_TOOLCHAIN", str(old))
    assert toolchain.toolchain_root() == old


def test_explicit_revision_has_priority_over_version(monkeypatch):
    monkeypatch.setenv("VULNFOUNDER_OPENHARMONY_VERSION", "7.0")
    monkeypatch.setenv("VULNFOUNDER_OPENHARMONY_REVISION", "OpenHarmony-7.0-Release-custom")
    assert toolchain.target_openharmony_revision() == "OpenHarmony-7.0-Release-custom"


def test_device_run_rejects_stale_builtin_descriptor(monkeypatch):
    import utilities.openharmony_dynamic.contract_compiler as compiler
    from utilities.openharmony_dynamic.finding_input import FindingInput

    monkeypatch.delenv("VULNFOUNDER_OPENHARMONY_REVISION", raising=False)
    monkeypatch.delenv("OPENANT_OPENHARMONY_REVISION", raising=False)
    monkeypatch.setattr(compiler, "_llm_binding", lambda: None)
    finding = FindingInput(
        finding_id="revision-check",
        unit_id="revision-check",
        vuln_class="command_injection",
        sink="SPUtils::LoadCmd",
        entry_hints=["sp_daemon_text", "hap_udp 127.0.0.1:8283"],
    )
    result = compiler.compile_contract(finding, hdc=object())
    assert result.compile_status == "SOURCE_FIRMWARE_MISMATCH"
    assert result.descriptor_resolution["version_compatibility"] == "mismatch"
