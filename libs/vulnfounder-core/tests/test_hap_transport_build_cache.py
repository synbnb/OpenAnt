"""HAP 构建缓存隔离测试。

Hvigor 默认使用宿主机的 ``~/.hvigor``。动态测试不能依赖该目录可写，
也不能让并发样本共享缓存；因此构建必须把 ``HVIGOR_USER_HOME`` 指向本次
运行目录，并将该路径传给 Hvigor 子进程。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _populate_fake_sdk(sdk: Path, api_version: str = "26") -> None:
    import json

    default = sdk / "default"
    oh_sdk = default / "openharmony"
    default.mkdir(parents=True, exist_ok=True)
    (default / "sdk-pkg.json").write_text(
        json.dumps({"data": {"apiVersion": api_version,
                              "platformVersion": f"{api_version}.0.0"}}),
        encoding="utf-8",
    )
    for component in ("ets", "js", "native", "previewer", "toolchains"):
        component_dir = oh_sdk / component
        component_dir.mkdir(parents=True, exist_ok=True)
        (component_dir / "oh-uni-package.json").write_text(
            json.dumps({"path": component, "apiVersion": api_version,
                        "platformVersion": "7.0.0", "version": "26.0.0.1",
                        "displayName": component}),
            encoding="utf-8",
        )

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def test_hap_build_isolates_hvigor_user_home(tmp_path, monkeypatch):
    import utilities.openharmony_dynamic.transports.hap as hap

    template = tmp_path / "template"
    (template / "Entry/src/main/ets/pages").mkdir(parents=True)
    (template / "Entry/src/main/ets/pages/Index.ets").write_text(
        "const host = '__HOST__'; const port = __PORT__; const marker = '__MARKER__';\n",
        encoding="utf-8",
    )
    stale_hvigor = template / "node_modules/@ohos/hvigor/src/base/internal/task/build/tasks.js"
    stale_hvigor.parent.mkdir(parents=True)
    stale_hvigor.write_text("stale template package", encoding="utf-8")
    (template / "oh-package.json5").write_text(
        '{"modelVersion":"5.0.0"}', encoding="utf-8"
    )
    (template / "hvigor/hvigor-config.json5").parent.mkdir(parents=True)
    (template / "hvigor/hvigor-config.json5").write_text(
        '{"modelVersion":"5.0.0"}', encoding="utf-8"
    )
    (template / "build-profile.json5").write_text(
        '{"app":{"signingConfigs":[{"name":"default","material":{'
        '"certpath":"old-cert","storePassword":"old","keyAlias":"old",'
        '"keyPassword":"old","profile":"old-profile",'
        '"signAlg":"SHA256withECDSA","storeFile":"old-store"}}],'
        '"products":[{"name":"default","signingConfig":"default",'
        '"compileSdkVersion":23,"compatibleSdkVersion":23,"targetSdkVersion":23}]}}',
        encoding="utf-8",
    )
    template_index = tmp_path / "Index.ets.in"
    template_index.write_text(
        "const host = '__HOST__'; const port = __PORT__; const marker = '__MARKER__';\n",
        encoding="utf-8",
    )
    toolchain = tmp_path / "toolchain"
    node = toolchain / "node"
    hvigor = toolchain / "hvigorw"
    sign_jar = toolchain / "hap-sign-tool.jar"
    sdk = toolchain / "sdk"
    for path in (node, hvigor, sign_jar):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    sdk.mkdir()
    _populate_fake_sdk(sdk)
    cert_dir = tmp_path / "cert"
    cert_dir.mkdir()
    for name in ("oh_release_chain.cer", "oh_profile8.p7b", "oh_release.p12"):
        (cert_dir / name).write_bytes(b"test-signing-material")

    monkeypatch.setattr(hap, "_TEMPLATE_PROJECT", template)
    monkeypatch.setattr(hap, "_TEMPLATE_INDEX", template_index)
    monkeypatch.setattr(hap, "_TOOLCHAIN_ROOT", toolchain)
    monkeypatch.setattr(hap, "_NODE", node)
    monkeypatch.setattr(hap, "_HVIGORW", hvigor)
    monkeypatch.setattr(hap, "_SIGN_JAR", sign_jar)
    monkeypatch.setattr(hap, "CERT_DIR", cert_dir)

    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if argv[0] == str(hvigor):
            project = Path(kwargs["cwd"])
            assert not (project / "node_modules/@ohos/hvigor/src/base/internal/task/build/tasks.js").exists()
            profile = (project / "build-profile.json5").read_text(encoding="utf-8")
            assert re.search(r'"products"\s*:\s*\[\s*\{\s*"buildOption"', profile)
            assert '"buildAppSkipSignHap": true' in profile
            assert not re.search(r'"signingConfig"\s*:', profile)
            assert not (project / "signing").exists()
            (project / "entry-default-unsigned.hap").write_bytes(b"unsigned")
        else:
            assert argv[argv.index("-signCode") + 1] == "1"
            out_file = Path(argv[argv.index("-outFile") + 1])
            out_file.write_bytes(b"signed")
        return SimpleNamespace(stdout=b"ok", returncode=0)

    monkeypatch.setattr(hap.subprocess, "run", fake_run)

    transport = hap.HapTransport(object(), work_root=tmp_path / "runs")
    signed = transport.build(
        {"mode": "udp", "host": "127.0.0.1", "port": 8283,
         "target": "demo", "marker": "/tmp/marker"},
        contract_id="CACHE-TEST",
    )

    assert signed.read_bytes() == b"signed"
    assert not (signed.parent / "project/signing").exists()
    assert len(calls) == 2
    env = calls[0][1]["env"]
    expected = tmp_path / "runs/vf-hap-CACHE-TEST/.hvigor-user"
    assert env["HVIGOR_USER_HOME"] == str(expected)
    assert expected.is_dir()
    # 不覆盖调用方已有的环境变量，只增加本次构建的隔离变量。
    assert env["NODE_HOME"] == str(node)


def test_hap_build_uses_ascii_sdk_alias_when_toolchain_path_is_unicode(tmp_path, monkeypatch):
    """Hvigor receives an ASCII SDK alias even when the installed toolchain path is Unicode."""

    import utilities.openharmony_dynamic.transports.hap as hap

    template = tmp_path / "template"
    (template / "Entry/src/main/ets/pages").mkdir(parents=True)
    (template / "Entry/src/main/ets/pages/Index.ets").write_text(
        "const host = '__HOST__'; const port = __PORT__; const marker = '__MARKER__';\n",
        encoding="utf-8",
    )
    (template / "oh-package.json5").write_text(
        '{"modelVersion":"5.0.0"}', encoding="utf-8"
    )
    (template / "hvigor/hvigor-config.json5").parent.mkdir(parents=True)
    (template / "hvigor/hvigor-config.json5").write_text(
        '{"modelVersion":"5.0.0"}', encoding="utf-8"
    )
    (template / "build-profile.json5").write_text(
        '{"app":{"signingConfigs":[{"name":"default","material":{'
        '"certpath":"old-cert","storePassword":"old","keyAlias":"old",'
        '"keyPassword":"old","profile":"old-profile",'
        '"signAlg":"SHA256withECDSA","storeFile":"old-store"}}],'
        '"products":[{"name":"default","signingConfig":"default",'
        '"compileSdkVersion":23,"compatibleSdkVersion":23,"targetSdkVersion":23}]}}',
        encoding="utf-8",
    )
    template_index = tmp_path / "Index.ets.in"
    template_index.write_text(
        "const host = '__HOST__'; const port = __PORT__; const marker = '__MARKER__';\n",
        encoding="utf-8",
    )
    toolchain = tmp_path / "工具链目录"
    node = toolchain / "tool/node"
    hvigor = toolchain / "hvigor/bin/hvigorw"
    sign_jar = toolchain / "sdk/default/openharmony/toolchains/lib/hap-sign-tool.jar"
    sdk = toolchain / "sdk"
    for path in (node, hvigor, sign_jar):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    sdk.mkdir(parents=True, exist_ok=True)
    _populate_fake_sdk(sdk)
    cert_dir = tmp_path / "cert"
    cert_dir.mkdir()
    for name in ("oh_release_chain.cer", "oh_profile8.p7b", "oh_release.p12"):
        (cert_dir / name).write_bytes(b"test-signing-material")

    monkeypatch.setattr(hap, "_TEMPLATE_PROJECT", template)
    monkeypatch.setattr(hap, "_TEMPLATE_INDEX", template_index)
    monkeypatch.setattr(hap, "_TOOLCHAIN_ROOT", toolchain)
    monkeypatch.setattr(hap, "_NODE", node)
    monkeypatch.setattr(hap, "_HVIGORW", hvigor)
    monkeypatch.setattr(hap, "_SIGN_JAR", sign_jar)
    monkeypatch.setattr(hap, "CERT_DIR", cert_dir)

    observed = {}

    def fake_run(argv, **kwargs):
        if argv[0] == str(hvigor):
            project = Path(kwargs["cwd"])
            properties = dict(
                line.split("=", 1)
                for line in (project / "local.properties").read_text(encoding="utf-8").splitlines()
                if "=" in line
            )
            sdk_alias = Path(properties["sdk.dir"])
            observed["sdk_alias"] = sdk_alias
            assert str(sdk_alias).isascii()
            assert sdk_alias.is_dir() and not sdk_alias.is_symlink()
            assert (sdk_alias / "26.0.0" / "ets").is_dir()
            assert (sdk_alias / "26.0.0" / "ets").resolve() == sdk / "default/openharmony/ets"
            profile = (project / "build-profile.json5").read_text(encoding="utf-8")
            assert re.search(r'"products"\s*:\s*\[\s*\{\s*"buildOption"', profile)
            assert '"buildAppSkipSignHap": true' in profile
            assert not re.search(r'"signingConfig"\s*:', profile)
            assert not (project / "signing").exists()
            assert '"compileSdkVersion":"26.0.0"' in profile
            assert '"compatibleSdkVersion":"26.0.0"' in profile
            assert '"targetSdkVersion":"26.0.0"' in profile
            assert '"modelVersion":"6.0.0"' in (
                project / "hvigor/hvigor-config.json5"
            ).read_text(encoding="utf-8")
            assert '"modelVersion":"6.0.0"' in (
                project / "oh-package.json5"
            ).read_text(encoding="utf-8")
            (project / "entry-default-unsigned.hap").write_bytes(b"unsigned")
        else:
            out_file = Path(argv[argv.index("-outFile") + 1])
            out_file.write_bytes(b"signed")
        return SimpleNamespace(stdout=b"ok", returncode=0)

    monkeypatch.setattr(hap.subprocess, "run", fake_run)

    signed = hap.HapTransport(object(), work_root=tmp_path / "runs").build(
        {"mode": "udp", "host": "127.0.0.1", "port": 8283,
         "target": "demo", "marker": "/tmp/marker"},
        contract_id="UNICODE-TOOLCHAIN",
    )

    assert signed.read_bytes() == b"signed"
    assert not (signed.parent / "project/signing").exists()
    assert not observed["sdk_alias"].exists()


def test_sdk_overlay_maps_default_components_to_api_version_paths(tmp_path, monkeypatch):
    import utilities.openharmony_dynamic.transports.hap as hap

    toolchain = tmp_path / "工具链目录"
    sdk = toolchain / "sdk"
    _populate_fake_sdk(sdk, api_version="26")
    monkeypatch.setattr(hap, "_TOOLCHAIN_ROOT", toolchain)

    with hap._temporary_ascii_sdk_alias() as sdk_alias:
        assert str(sdk_alias).isascii()
        assert (sdk_alias / "26.0.0" / "ets" / "oh-uni-package.json").is_file()
        assert (sdk_alias / "26.0.0" / "toolchains").resolve() == (
            sdk / "default/openharmony/toolchains"
        )

    assert not sdk_alias.exists()


def test_offline_pnpm_wrapper_uses_hvigor_versioned_cache_path(tmp_path, monkeypatch):
    """Hvigor must see pnpm in its own versioned wrapper directory offline."""

    import json

    import utilities.openharmony_dynamic.transports.hap as hap

    toolchain = tmp_path / "toolchain"
    hvigor_pkg = toolchain / "hvigor/hvigor"
    plugin_pkg = toolchain / "hvigor/hvigor-ohos-plugin"
    (hvigor_pkg / "src/common/const").mkdir(parents=True)
    (plugin_pkg).mkdir(parents=True)
    (hvigor_pkg / "src/common/const/path-const.js").write_text(
        'exports.PNPM_VERSION="10.28.2";', encoding="utf-8"
    )
    fake_pnpm = tmp_path / "pnpm"
    fake_pnpm.write_text("#!/bin/sh\nprintf '10.33.2\\n'\n", encoding="utf-8")
    fake_pnpm.chmod(0o755)
    monkeypatch.setattr(hap, "_TOOLCHAIN_ROOT", toolchain)
    monkeypatch.setattr(
        hap.shutil,
        "which",
        lambda name: str(fake_pnpm) if name == "pnpm" else None,
    )

    project = tmp_path / "project"
    project.mkdir()
    hvigor_user_home = tmp_path / "hvigor-user"
    hap.HapTransport._stage_offline_hvigor_dependencies(project, hvigor_user_home)

    expected_tools = hvigor_user_home / "wrapper/tools/10.28.2"
    pnpm_link = expected_tools / "node_modules/.bin/pnpm"
    package_json = expected_tools / "node_modules/pnpm/package.json"
    assert pnpm_link.is_symlink()
    assert pnpm_link.resolve() == fake_pnpm
    assert json.loads(package_json.read_text(encoding="utf-8"))["version"] == "10.33.2"
    assert not (hvigor_user_home / "wrapper/tools/node_modules/.bin/pnpm").exists()


def test_project_config_skips_hvigor_signing_in_isolated_copy(tmp_path):
    import utilities.openharmony_dynamic.transports.hap as hap

    project = tmp_path / "project"
    project.mkdir()
    profile_path = project / "build-profile.json5"
    profile_path.write_text(
        '{\n  "app": {"products": [{"name": "default"}]}\n}\n',
        encoding="utf-8",
    )

    hap._configure_project_skip_internal_signing(project)

    profile = profile_path.read_text(encoding="utf-8")
    assert '"buildAppSkipSignHap": true' in profile
    assert re.search(r'"products"\s*:\s*\[\s*\{\s*"buildOption"', profile)
    assert not re.search(r'"signingConfig"\s*:', profile)


def test_skip_internal_signing_refuses_to_overwrite_existing_build_options(tmp_path):
    import utilities.openharmony_dynamic.transports.hap as hap

    project = tmp_path / "project"
    project.mkdir()
    (project / "build-profile.json5").write_text(
        '{"buildOption":{"debuggable":true},"app":{}}', encoding="utf-8"
    )

    with pytest.raises(hap.TransportError, match="已声明 buildOption"):
        hap._configure_project_skip_internal_signing(project)


def test_nonzero_hvigor_exit_is_not_accepted_even_when_unsigned_hap_exists():
    import utilities.openharmony_dynamic.transports.hap as hap

    failed = SimpleNamespace(returncode=1, stdout=b"BUILD FAILED: signing validation")
    with pytest.raises(hap.TransportError, match="Hvigor 构建失败"):
        hap._require_successful_process(failed, "Hvigor 构建")


def test_sdk_debug_profile_uses_sdk_profile_certificate_and_key(tmp_path, monkeypatch):
    """Debug profiles must use the SDK's paired certificate chain and keystore alias."""

    import json

    import utilities.openharmony_dynamic.transports.hap as hap

    sdk_lib = tmp_path / "sdk-lib"
    sdk_lib.mkdir()
    sign_jar = sdk_lib / "hap-sign-tool.jar"
    sign_jar.write_bytes(b"test jar")
    signing_p12 = sdk_lib / "OpenHarmony.p12"
    signing_p12.write_bytes(b"test key store")
    profile_cert = sdk_lib / "OpenHarmonyProfileDebug.pem"
    profile_cert.write_text("SDK debug profile certificate chain\n", encoding="utf-8")
    (sdk_lib / "UnsgnedDebugProfileTemplate.json").write_text(
        json.dumps({
            "type": "debug",
            "bundle-info": {"bundle-name": "com.example.template"},
            "debug-info": {"device-ids": [], "device-id-type": "udid"},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(hap, "_SIGN_JAR", sign_jar)
    monkeypatch.setattr(hap, "_SDK_SIGNING_P12", signing_p12)
    monkeypatch.setattr(hap, "_SDK_PROFILE_DEBUG_CERT_CHAIN", profile_cert)
    monkeypatch.setattr(hap, "_SDK_SIGNING_LIB", sdk_lib)
    monkeypatch.setattr(hap, "_JAVA", "test-java")
    monkeypatch.setattr(hap, "_KEYTOOL", "test-keytool")
    monkeypatch.setattr(
        hap.shutil,
        "which",
        lambda name: f"/tools/{name}" if name in {"test-java", "test-keytool"} else None,
    )

    sign_calls = []
    keytool_calls = []

    def fake_sign_tool(arguments, *, timeout=90):
        sign_calls.append(list(arguments))
        if "-outFile" in arguments:
            Path(arguments[arguments.index("-outFile") + 1]).write_bytes(b"signed profile")
        if arguments[0] == "verify-profile":
            return '{"verifiedPassed": true}'
        return "ok"

    def fake_keytool(arguments, *, timeout=60):
        keytool_calls.append(list(arguments))
        Path(arguments[arguments.index("-file") + 1]).write_text(
            "exported SDK certificate\n", encoding="utf-8"
        )
        return "ok"

    monkeypatch.setattr(hap, "_run_sign_tool", fake_sign_tool)
    monkeypatch.setattr(hap, "_run_keytool", fake_keytool)

    generated = tmp_path / "contract" / "sdk-debug-signing"
    app_cert, signed_profile, _keystore, _app_alias, _password, profile_name = (
        hap._generate_sdk_debug_signing_material(
            tmp_path / "contract",
            device_udid="A" * 64,
            contract_id="SDK-DEBUG-PROFILE-TEST",
        )
    )

    profile_sign = next(call for call in sign_calls if call[0] == "sign-profile")
    app_cert_sign = next(call for call in sign_calls if call[0] == "generate-app-cert")
    assert profile_name == "sdk-generated-debug"
    assert profile_sign[profile_sign.index("-keyAlias") + 1] == (
        "openharmony application profile debug"
    )
    assert profile_sign[profile_sign.index("-profileCertFile") + 1] == str(profile_cert)
    assert profile_sign[profile_sign.index("-inFile") + 1] == str(generated / "profile.json")
    assert app_cert_sign[app_cert_sign.index("-outForm") + 1] == "certChain"
    assert app_cert_sign[app_cert_sign.index("-rootCaCertFile") + 1] == str(generated / "root.cer")
    assert app_cert_sign[app_cert_sign.index("-subCaCertFile") + 1] == str(generated / "app-ca.cer")
    assert not any(call[0] == "generate-cert" for call in sign_calls)
    assert not any("profile-ca" in " ".join(call) for call in sign_calls)
    assert not any("profile-cert.cer" in " ".join(call) for call in sign_calls)
    profile_json = json.loads((generated / "profile.json").read_text(encoding="utf-8"))
    assert profile_json["type"] == "debug"
    assert profile_json["debug-info"]["device-ids"] == ["A" * 64]
    assert signed_profile.read_bytes() == b"signed profile"
    assert app_cert.read_bytes() == b"signed profile"
    assert len(keytool_calls) == 2
