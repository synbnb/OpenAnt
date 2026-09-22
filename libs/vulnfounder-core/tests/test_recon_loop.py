"""侦查 agent loop 单元测试（自动化方案 §9/§11，不依赖设备与真实 LLM）。

覆盖：工具白名单拒绝越权、输出裁剪、路径越界防护、loop 终态（finalize /
预算耗尽 / LLM 不可用 / 非法输出重试）、事实卡沉淀与复核。
"""

from __future__ import annotations

import collections
import importlib
import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

rt = importlib.import_module("utilities.openharmony_dynamic.agent.recon_tools")
rl = importlib.import_module("utilities.openharmony_dynamic.agent.recon_loop")
df = importlib.import_module("utilities.openharmony_dynamic.agent.device_facts")
from utilities.openharmony_dynamic.finding_input import FindingInput  # noqa: E402


# ---------------------------------------------------------------------------
# ReconTools：白名单与裁剪
# ---------------------------------------------------------------------------

@pytest.fixture
def tools(tmp_path):
    return rt.ReconTools(hdc=None, repo_root=tmp_path, max_device_commands=3)


def test_unknown_tool_rejected(tools):
    out = tools.call("rm_rf", {"path": "/"})
    assert out["ok"] is False and "未知工具" in out["error"]


def test_repo_path_escapes_rejected(tools, tmp_path):
    with pytest.raises(ValueError):
        tools._repo_path("../outside")
    with pytest.raises(ValueError):
        tools._repo_path("/etc/passwd")  # 绝对路径不在仓库根内


def test_read_file_offset_and_truncation(tools, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("\n".join(f"line{i}" for i in range(500)), encoding="utf-8")
    out = tools.call("read_file", {"path": "a.txt", "offset": 0, "limit": 10})
    assert out["ok"] and out["total_lines"] == 500 and out["truncated"]
    assert out["next_offset"] == 10
    out2 = tools.call("read_file", {"path": "a.txt", "offset": 495, "limit": 200})
    assert out2["ok"] and not out2["truncated"]


def test_grep_hit_and_no_hit(tools, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.cpp").write_text("int SaveFreezeExtInfoToFile(int a) { return a; }\n", encoding="utf-8")
    out = tools.call("grep", {"pattern": "SaveFreezeExtInfoToFile", "path": "src"})
    assert out["ok"] and out["hits"] == 1 and "x.cpp" in out["output"]
    out2 = tools.call("grep", {"pattern": "not_present_anywhere", "path": "src"})
    assert out2["ok"] and out2["output"] == "(无命中)"


def test_hdc_shell_offline_rejected(tools):
    out = tools.call("hdc_shell", {"argv": ["ls", "/"]})
    assert out["ok"] is False and "离线" in out["error"]


class FakeHdc:
    """最小 hdc 桩：shell() 返回固定输出。"""

    serial = "FAKE-SERIAL-0001"

    def __init__(self, stdout="ok"):
        self._stdout = stdout
        self.calls = []

    def shell(self, argv, *, purpose="", timeout_seconds=None):
        self.calls.append((argv, purpose))
        import collections
        return collections.namedtuple("Rec", "stdout returncode stderr")(self._stdout, 0, "")


def test_hdc_shell_whitelist_rejects_write_commands():
    hdc = FakeHdc()
    tools = rt.ReconTools(hdc=hdc, repo_root=Path("/tmp"), max_device_commands=10)
    for bad in (
        ["rm", "-rf", "/data"],
        ["mkdir", "-p", "/data/x"],
        ["smode"],
        ["kill", "123"],
        ["param", "set", "x", "y"],
        ["reboot"],
        ["touch", "/data/x"],
    ):
        out = tools.call("hdc_shell", {"argv": bad})
        assert out["ok"] is False, f"{bad} 未被拒绝"
        assert "越权" in out["error"] or "仅允许" in out["error"]
    assert hdc.calls == []  # 一条都没真正执行


def test_hdc_shell_allows_readonly_and_counts_budget():
    hdc = FakeHdc("permit root")
    tools = rt.ReconTools(hdc=hdc, repo_root=Path("/tmp"), max_device_commands=3)
    out = tools.call("hdc_shell", {"argv": ["cat", "/system/etc/hiview/freeze_rules.xml"]})
    assert out["ok"] and "permit" in out["output"]
    assert tools.device_commands_used == 1
    # 预算耗尽 → 拒绝且不执行
    for _ in range(3):
        tools.call("hdc_shell", {"argv": ["date"]})
    assert tools.device_commands_used == 3
    out = tools.call("hdc_shell", {"argv": ["date"]})
    assert out["ok"] is False and "预算耗尽" in out["error"]
    assert len(hdc.calls) == 3  # cat + date*2 成功执行 3 次（第4次被预算拒绝）


def test_hdc_shell_truncates_long_single_argument_command_without_index_error():
    # ps 在真实开发板上可能输出数千行，但 argv 只有一个元素；长输出提示不能
    # 无条件访问 argv[1]，否则入口发现会把设备事实误报成 IndexError。
    hdc = FakeHdc("pid cmd\n" + ("1 init\n" * 2000))
    tools = rt.ReconTools(hdc=hdc, repo_root=Path("/tmp"), max_device_commands=10)
    out = tools.call("hdc_shell", {"argv": ["ps"]})
    assert out["ok"] is True
    assert out["truncated"] is True
    assert "IndexError" not in out["output"]
    assert "完整" in out["output"]


def test_hdc_shell_rejects_placeholder_and_dotdot():
    hdc = FakeHdc()
    tools = rt.ReconTools(hdc=hdc, repo_root=Path("/tmp"), max_device_commands=10)
    out = tools.call("hdc_shell", {"argv": ["cat", "/data/__STACK_FILE__"]})
    assert out["ok"] is False and "占位符" in out["error"]
    out2 = tools.call("hdc_shell", {"argv": ["cat", "/data/../etc/passwd"]})
    assert out2["ok"] is False and ".." in out2["error"]


def test_hilog_grep_filters_and_captures():
    lines = "\n".join(
        f"08-04 21:15:4{i}.000   205  1164 E C02d01/FreezeDetector: line{i}" for i in range(80)
    )
    hdc = FakeHdc(lines)
    tools = rt.ReconTools(hdc=hdc, repo_root=Path("/tmp"), max_device_commands=10)
    out = tools.call("hilog_grep", {"tag": "FreezeDetector", "pattern": "line1$"})
    assert out["ok"] and out["hits"] <= rt.MAX_HILOG_LINES
    assert tools.device_commands_used == 1


def test_write_note_and_read_notes_roundtrip(tools):
    out = tools.call("write_note", {"text": "实测：hilog tag 为 C02d01/FreezeDetector"})
    assert out["ok"] and out["notes_count"] == 1
    out2 = tools.call("read_notes", {})
    assert out2["ok"] and "C02d01/FreezeDetector" in out2["output"]


def test_notes_capacity_cap(tools):
    for i in range(rt.MAX_NOTES):
        assert tools.call("write_note", {"text": f"n{i}"})["ok"]
    out = tools.call("write_note", {"text": "overflow"})
    assert out["ok"] is False and "已满" in out["error"]


# ---------------------------------------------------------------------------
# DeviceFacts：L3 事实库
# ---------------------------------------------------------------------------

def test_device_facts_roundtrip_and_staleness(tmp_path):
    facts = df.DeviceFacts("SERIAL-TEST-0001", store_dir=tmp_path)
    facts.put("hilog_tag", "C02d01/FreezeDetector", source="llm-recon", evidence="recon")
    facts.put("hiview_pid", 205, source="llm-recon")
    # 重新加载（模拟跨任务）
    facts2 = df.DeviceFacts("SERIAL-TEST-0001", store_dir=tmp_path)
    assert facts2.get("hilog_tag") == "C02d01/FreezeDetector"
    assert facts2.needs_revalidation("hiview_pid") is True
    assert facts2.needs_revalidation("hilog_tag") is False
    item = facts2.get_item("hilog_tag")
    assert item["source"] == "llm-recon" and item["evidence"] == "recon"
    lines = facts2.to_prompt_lines()
    assert any("volatile-需重验" in l for l in lines)


def test_device_facts_rejects_bad_source(tmp_path):
    facts = df.DeviceFacts("SERIAL-TEST-0002", store_dir=tmp_path)
    with pytest.raises(ValueError):
        facts.put("k", "v", source=" hallucinated")


# ---------------------------------------------------------------------------
# run_recon_loop：mock LLM 的终态语义
# ---------------------------------------------------------------------------

def _finding():
    return FindingInput(finding_id="T-01", unit_id="u", vuln_class="command_injection",
                        sink="SP_daemon Network.cpp:153 popen", entry_hints=["hap_udp 8283"],
                        repo_root=str(CORE))


class ScriptedLLM:
    """按脚本弹出回复的 fake binding（simple_text 同款位置参数签名）。"""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, binding, prompt, system=None, max_tokens=0):
        self.prompts.append(prompt)
        return self.replies.pop(0)


def _bind(script):
    llm = ScriptedLLM(script)
    return ("fake", llm)


def _skeleton():
    return {"contract_id": "GEN-T-01", "protocol": {"descriptor_id": "sp_daemon_text"}}


def test_recon_loop_finalize_with_facts():
    script = [
        json.dumps({"tool": "hdc_shell", "args": {"argv": ["cat", "/system/etc/hiview/freeze_rules.xml"]}}),
        json.dumps({"tool": "write_note", "args": {"text": "实测：token 校验默认关闭"}}),
        json.dumps({"tool": "finalize", "args": {
            "draft": {"protocol": {"field_values": {"mode": "udp"}}},
            "facts": {"hilog_tag": "test-tag", "token_check": "off"},
        }}),
    ]
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text", "fields": []},
        repo_root=CORE, hdc=None, binding_pair=_bind(script),
    )
    assert result.status == "finalized"
    assert result.draft == {"protocol": {"field_values": {"mode": "udp"}}}
    assert result.facts == {"hilog_tag": "test-tag", "token_check": "off"}
    assert any("token 校验" in n for n in result.notes)
    # 非法 hdc_shell 因离线被拒，但 loop 继续而不是中断
    assert result.turns_used == 3


def test_recon_loop_budget_exhausted_honest_stop():
    script = [json.dumps({"tool": "read_notes", "args": {}}) for _ in range(5)]
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
        hdc=None, binding_pair=_bind(script), max_turns=5,
    )
    assert result.status == "budget_exhausted"
    assert result.draft is None
    assert "5 轮未 finalize" in result.error


def test_recon_loop_invalid_output_then_finalize():
    script = [
        "这不是 JSON",
        json.dumps({"tool": "finalize", "args": {"draft": {"fault": {}}, "facts": {}}}),
    ]
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
        hdc=None, binding_pair=_bind(script), max_turns=4,
    )
    assert result.status == "finalized"  # 非法输出被忽略，loop 继续
    assert result.turns_used == 2


def test_recon_loop_suppresses_duplicate_tool_actions():
    script = [
        json.dumps({"tool": "read_notes", "args": {}}),
        json.dumps({"tool": "read_notes", "args": {}}),
        json.dumps({"tool": "finalize", "args": {"draft": {}, "facts": {}}}),
    ]
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
        hdc=None, binding_pair=_bind(script), max_turns=4,
    )
    assert result.status == "finalized"
    assert result.turns_used == 3
    assert result.duplicate_actions == 1


def test_recon_loop_finalize_without_draft_rejected():
    script = [
        json.dumps({"tool": "finalize", "args": {}}),
        json.dumps({"tool": "finalize", "args": {"draft": {"fault": {}}, "facts": {}}}),
    ]
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
        hdc=None, binding_pair=_bind(script), max_turns=4,
    )
    assert result.status == "finalized"


def test_recon_loop_llm_unavailable(monkeypatch):
    # 不依赖本机是否配置了真实模型；否则该单测会意外发起网络请求，
    # 把“无绑定时的诚实终态”变成一个不可控的集成测试。
    monkeypatch.setattr(rl, "_llm_binding", lambda: None)
    result = rl.run_recon_loop(
        finding=_finding(), skeleton=_skeleton(),
        descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
        hdc=None, binding_pair=None,
    )
    assert result.status == "llm_unavailable"


def test_recon_loop_device_facts_injected_into_prompt():
    facts = df.DeviceFacts("SERIAL-TEST-0003", store_dir=Path(CORE) / "utilities" / "openharmony_dynamic" / "contracts" / "generated" / "test_tmp_facts")
    try:
        facts.put("hilog_tag", "C02d01/FreezeDetector", source="validator-verified")
        script = [json.dumps({"tool": "finalize", "args": {"draft": {}, "facts": {}}})]
        bind = _bind(script)
        result = rl.run_recon_loop(
            finding=_finding(), skeleton=_skeleton(),
            descriptor_dict={"descriptor_id": "sp_daemon_text"}, repo_root=CORE,
            hdc=None, binding_pair=bind, device_facts=facts,
        )
        assert result.status == "finalized"
        prompt = bind[1].prompts[0]
        assert "C02d01/FreezeDetector" in prompt
        assert "设备事实库" in prompt
    finally:
        facts.path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 事实卡抽样复核（§11.2）：verify_fact_card 确定性重跑核对
# ---------------------------------------------------------------------------

cval = importlib.import_module("utilities.openharmony_dynamic.contract_validator")


class _Rec(collections.namedtuple("Rec", "stdout returncode stderr")):
    pass


class VerifyHdc:
    """复核用 hdc 桩：按命令串映射返回码，缺省 0（存在）。"""

    serial = "FAKE-SERIAL-VERIFY"

    def __init__(self, rc_map=None):
        self.rc_map = rc_map or {}
        self.calls = []

    def shell(self, argv, *, purpose="", timeout_seconds=None):
        self.calls.append(argv)
        rc = self.rc_map.get(" ".join(argv), 0)
        return _Rec("", rc, "")


def test_verify_fact_card_offline_noop():
    v, f = cval.verify_fact_card({"sock": "/dev/unix/socket/x"}, hdc=None)
    assert v == [] and f == []
    v2, f2 = cval.verify_fact_card({}, hdc=VerifyHdc())
    assert v2 == [] and f2 == []


def test_verify_fact_card_classifies_checkable_only():
    facts = {
        "sock": "/dev/unix/socket/hisysevent",          # socket 形态 → 核
        "rules": "/system/etc/hiview/freeze_rules.xml",  # 绝对路径 → 核
        "pid": 12979,                                    # pid 形态 → 核
        "hilog_tag": "C02d01/FreezeDetector",            # 非路径非 pid → 跳过
        "guess": "推测：UID 5523",                        # 描述性 → 跳过
        "tmpl": "__STACK_FILE__",                        # 占位符 → 跳过
        "rel": "data/log/x",                             # 相对路径 → 跳过
        "evil": "/data/../../etc",                       # 含 .. → 跳过（安全）
    }
    hdc = VerifyHdc()
    v, f = cval.verify_fact_card(facts, hdc=hdc)
    assert f == []
    assert set(v) == {"sock", "rules", "pid"}
    argvs = {" ".join(a) for a in hdc.calls}
    assert "test -S /dev/unix/socket/hisysevent" in argvs
    assert "test -e /system/etc/hiview/freeze_rules.xml" in argvs
    assert "test -d /proc/12979" in argvs


def test_verify_fact_card_failure_reported():
    hdc = VerifyHdc({"test -S /dev/unix/socket/hisysevent": 1})
    v, f = cval.verify_fact_card(
        {"sock": "/dev/unix/socket/hisysevent",
         "rules": "/system/etc/hiview/freeze_rules.xml"}, hdc=hdc)
    assert v == ["rules"]
    assert len(f) == 1 and "sock" in f[0] and "rc=1" in f[0]


def test_verify_fact_card_device_error_skipped():
    class BoomHdc(VerifyHdc):
        def shell(self, argv, *, purpose="", timeout_seconds=None):
            raise RuntimeError("device busy")

    v, f = cval.verify_fact_card({"sock": "/dev/unix/socket/hisysevent"}, hdc=BoomHdc())
    assert v == [] and f == []  # 无法断言真伪 → 诚实跳过，不拦截不谎报


def test_verify_fact_card_sample_budget_cap():
    facts = {f"p{i}": f"/data/local/tmp/vf/f{i}" for i in range(12)}
    hdc = VerifyHdc()
    v, f = cval.verify_fact_card(facts, hdc=hdc)
    assert f == []
    assert len(hdc.calls) == cval._FACT_VERIFY_MAX_COMMANDS  # 抽样预算 8 条
