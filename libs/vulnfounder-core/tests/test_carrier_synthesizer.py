"""载体合成器单测（自动化方案 §10.2，不依赖设备与真实 LLM）。

覆盖：import 白名单拒绝危险 API、槽位保持、危险模式扫描、未知占位符、
L3 源码白名单（禁 shell/exec 族）、状态机（REJECTED_VALIDATION /
REQUIRES_HUMAN_APPROVAL / APPROVED）、族级模板入库同 id 不覆盖。
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

cs = importlib.import_module("utilities.openharmony_dynamic.carrier_synthesizer")


# --- L2 validate_hap_carrier -------------------------------------------------

GOOD_ETS = """
import socket from '@ohos.net.socket';
import hilog from '@ohos.hilog';
const MARKER = '__MARKER__';
const HOST = '__HOST__';
const PORT = __PORT__;
@Entry
@Component
struct Index {
  aboutToAppear(): void {
    hilog.info(0x0001, 'VulnFounderHapPoc', `HAP_POC_START ${MARKER}`);
  }
}
"""


def test_hap_carrier_good_passes():
    validation, errors = cs.validate_hap_carrier(GOOD_ETS)
    assert errors == []
    assert "__MARKER__" in validation["placeholders"]


def test_hap_carrier_rejects_dangerous_import():
    bad = GOOD_ETS.replace("@ohos.hilog", "@ohos.net.http")
    validation, errors = cs.validate_hap_carrier(bad)
    assert any("import 白名单外" in e and "@ohos.net.http" in e for e in errors)
    _, errors2 = cs.validate_hap_carrier(GOOD_ETS.replace("@ohos.hilog", "@ohos.request"))
    assert any("@ohos.request" in e for e in errors2)


def test_hap_carrier_rejects_dangerous_patterns():
    for snippet in ("eval('1+1')", "new Function('return 1')", "require(someVar)"):
        _, errors = cs.validate_hap_carrier(GOOD_ETS + "\n" + snippet)
        assert any("危险模式" in e for e in errors), snippet


def test_hap_carrier_slot_retention_and_unknown_placeholder():
    # 槽位保持：删掉 __MARKER__ → 拒绝
    _, errors = cs.validate_hap_carrier(GOOD_ETS.replace("__MARKER__", "marker"))
    assert any("槽位保持失败" in e and "__MARKER__" in e for e in errors)
    # 未知占位符（runner 不支持）→ 拒绝
    _, errors2 = cs.validate_hap_carrier(GOOD_ETS + "\nconst UID = '__UID__';")
    assert any("未知占位符" in e and "__UID__" in e for e in errors2)


def test_hap_carrier_self_check_anchor_required():
    no_anchor = GOOD_ETS.replace("HAP_POC_START", "MY_START")
    _, errors = cs.validate_hap_carrier(no_anchor)
    assert any("自证锚缺失" in e for e in errors)


# --- L3 validate_native_carrier ----------------------------------------------

GOOD_C = """
#include <sys/socket.h>
static void report(const char *c, long r, int e, const char *d) {}
int main(int argc, char **argv) {
    report("sendto", 0, 0, "x");
    report("result", 0, 0, "delivered");
    return 0;
}
"""


def test_native_carrier_good_passes():
    validation, errors = cs.validate_native_carrier(GOOD_C)
    assert errors == []


def test_native_carrier_rejects_shell_exec_family():
    for snippet in ("system(\"rm -rf /\");", "popen(cmd, \"r\");", "execl(\"/bin/sh\", \"sh\", NULL);"):
        _, errors = cs.validate_native_carrier(GOOD_C + "\n" + snippet)
        assert any("禁 shell/exec 族" in e for e in errors), snippet


def test_native_carrier_requires_report_result_lines():
    _, errors = cs.validate_native_carrier("int main(){return 0;}")
    assert any("report()" in e for e in errors)


# --- 状态机与入库 -------------------------------------------------------------

def _approval_ready(kind="hap_index", source=None):
    return cs.CarrierSynthesisResult(
        status="REQUIRES_HUMAN_APPROVAL", kind=kind,
        source=source or (GOOD_ETS if kind == "hap_index" else GOOD_C),
        llm_used=True,
    )


def test_synthesize_offline_skips_selfcheck(tmp_path):
    res = cs.synthesize_hap_carrier("ctx", contract_id="t1", hdc=None, source_override=GOOD_ETS)
    assert res.status == "REQUIRES_HUMAN_APPROVAL"
    assert "skipped" in res.validation["self_check"]


def test_synthesize_rejects_bad_source_before_llm_gate(tmp_path):
    bad = GOOD_ETS.replace("@ohos.hilog", "@ohos.net.http")
    res = cs.synthesize_hap_carrier("ctx", contract_id="t2", hdc=None, source_override=bad)
    assert res.status == "REJECTED_VALIDATION"
    assert any("import 白名单外" in e for e in res.errors)


def test_synthesize_llm_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "_llm_binding", lambda: None)
    res = cs.synthesize_hap_carrier("ctx", contract_id="t3", hdc=None)
    assert res.status == "REQUIRES_PROTOCOL_REVIEW"
    assert "LLM 不可用" in res.errors[0]


def test_approve_register_and_no_overwrite(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "_TEMPLATES_DIR", tmp_path)
    res = _approval_ready()
    path = cs.approve_and_register(res, family="custom_proto")
    assert Path(path).exists()
    assert res.template_path == path
    # 同 family 不覆盖
    res2 = _approval_ready()
    with pytest.raises(Exception):
        cs.approve_and_register(res2, family="custom_proto")
    # L1 复用入口
    assert cs.get_family_template("custom_proto") == GOOD_ETS
    assert cs.get_family_template("missing_family") is None


def test_approve_requires_gate_status(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "_TEMPLATES_DIR", tmp_path)
    rejected = cs.CarrierSynthesisResult(status="REJECTED_VALIDATION", kind="hap_index", source=GOOD_ETS)
    with pytest.raises(Exception):
        cs.approve_and_register(rejected, family="x")


def test_native_synthesize_offline(tmp_path, monkeypatch):
    # 编译器不存在时诚实停 REQUIRES_HUMAN_APPROVAL 带日志（不谎报已构建）
    monkeypatch.setattr(cs, "_CLANG", tmp_path / "no-clang")
    res = cs.synthesize_native_carrier("ctx", contract_id="t4", source_override=GOOD_C)
    assert res.status == "REQUIRES_HUMAN_APPROVAL"
    assert res.errors and "交叉编译失败" in res.errors[0]
    assert "交叉编译器不存在" in res.build_log_tail


def test_build_hap_reuses_isolated_hvigor_home(tmp_path, monkeypatch):
    """L2 自定义载体不能绕过 HAP 传输层的离线/隔离构建设置。"""
    import utilities.openharmony_dynamic.transports.hap as hap

    template = tmp_path / "template"
    (template / "Entry/src/main/ets/pages").mkdir(parents=True)
    (template / "Entry/src/main/ets/pages/Index.ets").write_text("old", encoding="utf-8")
    monkeypatch.setattr(cs, "_HAP_PROJECT", template)

    toolchain = tmp_path / "toolchain"
    hvigorw = toolchain / "hvigor/bin/hvigorw"
    node = toolchain / "node"
    sign_jar = toolchain / "hap-sign-tool.jar"
    sdk = toolchain / "sdk"
    for path in (hvigorw, node, sign_jar):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    sdk.mkdir()
    cert_dir = tmp_path / "cert"
    cert_dir.mkdir()
    monkeypatch.setattr(hap, "_HVIGORW", hvigorw)
    monkeypatch.setattr(hap, "_NODE", node)
    monkeypatch.setattr(hap, "_SIGN_JAR", sign_jar)
    monkeypatch.setattr(hap, "_TOOLCHAIN_ROOT", toolchain)
    monkeypatch.setattr(hap, "CERT_DIR", cert_dir)
    monkeypatch.setattr(cs, "_TOOLCHAIN_ROOT", toolchain)

    staged = []
    monkeypatch.setattr(
        hap.HapTransport,
        "_stage_offline_hvigor_dependencies",
        staticmethod(lambda project, home: staged.append((project, home))),
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if argv[0] == str(hvigorw):
            (Path(kwargs["cwd"]) / "entry-default-unsigned.hap").write_bytes(b"unsigned")
        else:
            out_file = Path(argv[argv.index("-outFile") + 1])
            out_file.write_bytes(b"signed")
        return type("Completed", (), {"stdout": b"ok", "returncode": 0})()

    monkeypatch.setattr(cs.subprocess, "run", fake_run)
    signed, log = cs._build_hap(GOOD_ETS, contract_id="carrier-cache", out_root=tmp_path / "runs")

    assert signed is not None and signed.read_bytes() == b"signed"
    assert staged and staged[0][1].name == ".hvigor-user"
    assert calls[0][1]["env"]["HVIGOR_USER_HOME"] == str(staged[0][1])
    assert calls[0][1]["env"]["NODE_HOME"] == str(node)
