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


def _write_api_metadata(path, api_version: str):
    sdk = path / "sdk/default/openharmony"
    for component in ("ets", "js", "native", "toolchains", "previewer"):
        component_dir = sdk / component
        component_dir.mkdir(parents=True, exist_ok=True)
        (component_dir / "oh-uni-package.json").write_text(
            json.dumps({"apiVersion": api_version}), encoding="utf-8"
        )


def _make_build_tools(path, api_version: str):
    _write_api_metadata(path, api_version)
    (path / "sdk/default/sdk-pkg.json").parent.mkdir(parents=True, exist_ok=True)
    (path / "sdk/default/sdk-pkg.json").write_text(
        json.dumps({"data": {"apiVersion": api_version}}), encoding="utf-8"
    )
    hvigor = path / "hvigor/bin/hvigorw"
    node = path / "tool/node/bin/node"
    hvigor.parent.mkdir(parents=True, exist_ok=True)
    node.parent.mkdir(parents=True, exist_ok=True)
    hvigor.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
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


def test_build_tools_pair_with_target_sdk_by_api_version(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime" / "openharmony"
    sdk = _make_toolchain(tmp_path, "macos-arm64-7.0", "7.0")
    _write_api_metadata(sdk, "26")
    clt = _make_build_tools(
        runtime / "macos-arm64-clt-26.0.0.851" / "command-line-tools", "26"
    )
    # A complete but incompatible older CLT must not be selected over API 26.
    _make_build_tools(
        runtime / "macos-arm64-clt-23" / "command-line-tools", "23"
    )
    monkeypatch.setattr(toolchain, "project_root", lambda: tmp_path)
    for name in (
        "VULNFOUNDER_DYNAMIC_TOOLCHAIN", "OPENANT_DYNAMIC_TOOLCHAIN",
        "VULNFOUNDER_DYNAMIC_BUILD_TOOLS", "OPENANT_DYNAMIC_BUILD_TOOLS",
        "VULNFOUNDER_OPENHARMONY_VERSION", "OPENANT_OPENHARMONY_VERSION",
    ):
        monkeypatch.delenv(name, raising=False)

    assert toolchain.toolchain_root() == sdk
    assert toolchain.build_tools_root() == clt
    assert toolchain.hap_build_toolchain_issues() == []


def test_explicit_build_tools_override_is_respected(tmp_path, monkeypatch):
    explicit = _make_build_tools(tmp_path / "custom-clt", "26")
    monkeypatch.setenv("VULNFOUNDER_DYNAMIC_BUILD_TOOLS", str(explicit))
    assert toolchain.build_tools_root() == explicit.resolve()


def test_missing_hap_build_tools_are_reported_explicitly(tmp_path):
    issues = toolchain.hap_build_toolchain_issues(tmp_path)
    assert len(issues) == 2
    assert any("Hvigor" in issue and "hvigorw" in issue for issue in issues)
    assert any("Node.js" in issue and "node" in issue for issue in issues)


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
