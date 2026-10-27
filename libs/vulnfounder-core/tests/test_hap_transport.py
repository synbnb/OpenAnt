"""HAP 传输契约标识回归测试。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def test_build_and_run_injects_contract_target_before_render(monkeypatch, tmp_path):
    """主运行路径必须在构建 HAP 前把契约 ID注入 TARGET 槽位。"""

    from utilities.openharmony_dynamic.transports import hap
    from utilities.openharmony_dynamic.transports.base import INPUT_DELIVERED, SendResult

    transport = hap.HapTransport(object(), work_root=tmp_path)
    rendered_values = {}

    def fake_build(field_values, *, contract_id):
        rendered_values.update(field_values)
        return tmp_path / "signed.hap"

    def fake_install(_hap):
        return SendResult(
            reachability=INPUT_DELIVERED,
            detail="started",
            transport={"kind": "hap"},
        )

    def fake_wait(*, target, seconds, poll_interval=1.0):
        assert target == "GEN-TARGET-001"
        return True, "HAP_POC_SENT GEN-TARGET-001"

    monkeypatch.setattr(transport, "build", fake_build)
    monkeypatch.setattr(transport, "install_and_start", fake_install)
    monkeypatch.setattr(transport, "wait_completion", fake_wait)

    transport.build_and_run(
        {"mode": "udp", "host": "127.0.0.1", "port": 8283},
        contract_id="GEN-TARGET-001",
    )

    assert rendered_values["target"] == "GEN-TARGET-001"


def test_build_and_run_preserves_explicit_target(monkeypatch, tmp_path):
    """调用方提供样本/契约标识时，不能被默认契约 ID 覆盖。"""

    from utilities.openharmony_dynamic.transports import hap
    from utilities.openharmony_dynamic.transports.base import INPUT_DELIVERED, SendResult

    transport = hap.HapTransport(object(), work_root=tmp_path)
    rendered_values = {}

    def fake_build(field_values, *, contract_id):
        rendered_values.update(field_values)
        return tmp_path / "signed.hap"

    monkeypatch.setattr(transport, "build", fake_build)
    monkeypatch.setattr(
        transport,
        "install_and_start",
        lambda _hap: SendResult(INPUT_DELIVERED, "started", {"kind": "hap"}),
    )
    monkeypatch.setattr(
        transport,
        "wait_completion",
        lambda *, target, seconds, poll_interval=1.0: (
            True,
            f"HAP_POC_SENT {target}",
        ),
    )

    transport.build_and_run(
        {
            "target": "SAMPLE-001",
            "mode": "udp",
            "host": "127.0.0.1",
            "port": 8283,
        },
        contract_id="GEN-TARGET-001",
    )

    assert rendered_values["target"] == "SAMPLE-001"


def test_build_and_run_records_runtime_frames(monkeypatch, tmp_path):
    """运行记录必须保存 HAP 实际交给 socket.send 的展开后帧。"""

    from utilities.openharmony_dynamic.transports import hap
    from utilities.openharmony_dynamic.transports.base import INPUT_DELIVERED, SendResult

    transport = hap.HapTransport(object(), work_root=tmp_path)

    monkeypatch.setattr(transport, "build", lambda *_args, **_kwargs: tmp_path / "signed.hap")
    monkeypatch.setattr(
        transport,
        "install_and_start",
        lambda _hap: SendResult(INPUT_DELIVERED, "started", {"kind": "hap"}),
    )
    monkeypatch.setattr(
        transport,
        "wait_completion",
        lambda **_kwargs: (True, "HAP_POC_SENT SAMPLE-001"),
    )

    result = transport.build_and_run(
        {
            "target": "SAMPLE-001",
            "mode": "udp",
            "host": "127.0.0.1",
            "port": 8283,
            "first": "set_pkgName::vf-marker",
            "second": "catch_network_traffic::x",
        },
        contract_id="SAMPLE-001",
        frame_interval_seconds=0.45,
    )
    frames = result.transport["sent_frames"]
    assert [item["payload"] for item in frames] == [
        "set_pkgName::vf-marker",
        "catch_network_traffic::x",
    ]
    assert frames[1]["delay_before_seconds"] == 0.45
    assert result.transport["frame_count"] == 2
    assert result.transport["frame_interval_seconds"] == 0.45


def test_build_rejects_missing_target_before_creating_hap(tmp_path):
    """直接调用底层构建器也不能产出空 TARGET 的 HAP。"""

    from utilities.openharmony_dynamic.transports import hap
    from utilities.openharmony_dynamic.transports.base import TransportError

    transport = hap.HapTransport(object(), work_root=tmp_path)
    with pytest.raises(TransportError, match=r"target"):
        transport.build(
            {"mode": "udp", "host": "127.0.0.1", "port": 8283},
            contract_id="GEN-TARGET-001",
        )


def test_sdk_debug_profile_uses_device_udid_not_hdc_serial():
    """profile 的设备绑定值来自 bm get -u，而不是 HDC 连接 serial。"""

    from types import SimpleNamespace

    from utilities.openharmony_dynamic.transports.hap import _current_device_udid

    expected_udid = "55014CF4ECE2D820D8AE5DF49436C6558E62857ACC3A2F9A0DCA6B28873DB7E4"

    class FakeHDC:
        serial = "150100424a5444345209d945be14b900"

        def __init__(self):
            self.calls = []

        def shell(self, argv, *, purpose="", timeout_seconds=None):
            self.calls.append((argv, purpose))
            return SimpleNamespace(
                returncode=0,
                stdout=f"udid of current device is :\n{expected_udid}\n",
                stderr="",
            )

    hdc = FakeHDC()
    assert _current_device_udid(hdc) == expected_udid
    assert hdc.calls == [(["bm", "get", "-u"], "读取 HAP debug profile 所需的设备 UDID")]


def test_sdk_debug_profile_rejects_missing_or_malformed_udid():
    """不能把空值、HDC serial 或任意输出误写成 profile 设备身份。"""

    from types import SimpleNamespace

    from utilities.openharmony_dynamic.transports.base import TransportError
    from utilities.openharmony_dynamic.transports.hap import _current_device_udid

    class FakeHDC:
        serial = "150100424a5444345209d945be14b900"

        def __init__(self, output):
            self.output = output

        def shell(self, *_args, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=self.output, stderr="")

    with pytest.raises(TransportError, match="未返回有效的 64 位"):
        _current_device_udid(FakeHDC(""))
    with pytest.raises(TransportError, match="未返回有效的 64 位"):
        _current_device_udid(FakeHDC("udid: 150100424a5444345209d945be14b900"))


def test_install_retries_after_removing_only_owned_bundle_with_stale_signature(tmp_path):
    """临时签名轮换后，仅清理并重装本工具自己的旧测试包。"""

    import json
    from types import SimpleNamespace

    from utilities.openharmony_dynamic.transports import hap

    class FakeHDC:
        serial = "device-1"

        def __init__(self):
            self.calls = []

        def run(self, argv, *, purpose="", timeout_seconds=None):
            self.calls.append((argv, purpose))
            if argv[:2] == ["install", "-r"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="error: install sign info inconsistent.",
                    stderr="",
                )
            if argv == ["shell", "bm", "dump", "-n", hap.BUNDLE_NAME]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        f"{hap.BUNDLE_NAME}:\n"
                        + json.dumps({
                            "bundleName": hap.BUNDLE_NAME,
                            "applicationInfo": {"vendor": "security_research"},
                        })
                        + "\n[W] FreeChannelContinue handle->data is nullptr\n"
                    ),
                    stderr="",
                )
            if argv == ["uninstall", hap.BUNDLE_NAME]:
                return SimpleNamespace(
                    returncode=0, stdout="uninstall bundle successfully", stderr=""
                )
            if argv == ["install", str(tmp_path / "carrier.hap")]:
                return SimpleNamespace(
                    returncode=0, stdout="install bundle successfully", stderr=""
                )
            if argv[:3] == ["shell", "aa", "force-stop"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if argv[:3] == ["shell", "aa", "start"]:
                return SimpleNamespace(returncode=0, stdout="start ability successfully", stderr="")
            raise AssertionError(f"unexpected HDC command: {argv!r}")

    hdc = FakeHDC()
    transport = hap.HapTransport(hdc, work_root=tmp_path)
    result = transport.install_and_start(tmp_path / "carrier.hap")

    assert result.transport["bundle"] == hap.BUNDLE_NAME
    assert [call[0] for call in hdc.calls[:4]] == [
        ["install", "-r", str(tmp_path / "carrier.hap")],
        ["shell", "bm", "dump", "-n", hap.BUNDLE_NAME],
        ["uninstall", hap.BUNDLE_NAME],
        ["install", str(tmp_path / "carrier.hap")],
    ]


def test_build_escapes_shell_payload_before_arkts_render(monkeypatch, tmp_path):
    """模型生成的 shell 字符串不能破坏 HAP 模板的 ArkTS 字符串语法。"""

    from utilities.openharmony_dynamic.transports import hap

    template_project = tmp_path / "template"
    (template_project / "Entry/src/main/ets/pages").mkdir(parents=True)
    (template_project / "Entry/src/main/ets/pages/Index.ets").write_text(
        "const FIRST = '__FIRST__';\nconst PORT = __PORT__;\n",
        encoding="utf-8",
    )
    template_index = tmp_path / "HAP_INDEX.ets.in"
    template_index.write_text(
        "const FIRST = '__FIRST__';\nconst PORT = __PORT__;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(hap, "_TEMPLATE_PROJECT", template_project)
    monkeypatch.setattr(hap, "_TEMPLATE_INDEX", template_index)
    monkeypatch.setattr(hap, "_HVIGORW", tmp_path / "hvigorw")
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    for name in ("oh_release_chain.cer", "oh_profile8.p7b", "oh_release.p12"):
        (cert_dir / name).write_bytes(b"fixture")
    monkeypatch.setattr(hap, "CERT_DIR", cert_dir)

    class _Build:
        stdout = b""
        returncode = 0

    monkeypatch.setattr(hap.subprocess, "run", lambda *args, **kwargs: _Build())
    transport = hap.HapTransport(object(), work_root=tmp_path / "out")
    with pytest.raises(hap.TransportError, match="unsigned HAP|签名材料缺失"):
        transport.build(
            {
                "target": "SAMPLE-001",
                "mode": "udp",
                "host": "127.0.0.1",
                "port": 8283,
                "first": "set_pkgName::smartperf;printf '%s' 'vf\\n' > /data/local/tmp/vf/x",
            },
            contract_id="GEN-TARGET-001",
        )
    rendered = (
        tmp_path / "out/vf-hap-GEN-TARGET-001/project/Entry/src/main/ets/pages/Index.ets"
    ).read_text(encoding="utf-8")
    assert "printf \\\'%s\\\' \\\'vf\\\\n\\\'" in rendered
    assert "const PORT = 8283;" in rendered
