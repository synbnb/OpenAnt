"""HAP 构建缓存隔离测试。

Hvigor 默认使用宿主机的 ``~/.hvigor``。动态测试不能依赖该目录可写，
也不能让并发样本共享缓存；因此构建必须把 ``HVIGOR_USER_HOME`` 指向本次
运行目录，并将该路径传给 Hvigor 子进程。
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

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
    (template / "oh-package.json5").write_text("{}", encoding="utf-8")
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
    cert_dir = tmp_path / "cert"
    cert_dir.mkdir()

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
            (project / "entry-default-unsigned.hap").write_bytes(b"unsigned")
        else:
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
    assert len(calls) == 2
    env = calls[0][1]["env"]
    expected = tmp_path / "runs/vf-hap-CACHE-TEST/.hvigor-user"
    assert env["HVIGOR_USER_HOME"] == str(expected)
    assert expected.is_dir()
    # 不覆盖调用方已有的环境变量，只增加本次构建的隔离变量。
    assert env["NODE_HOME"] == str(node)

