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

    class _Build:
        stdout = b""
        returncode = 0

    monkeypatch.setattr(hap.subprocess, "run", lambda *args, **kwargs: _Build())
    transport = hap.HapTransport(object(), work_root=tmp_path / "out")
    with pytest.raises(hap.TransportError, match="unsigned HAP"):
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
