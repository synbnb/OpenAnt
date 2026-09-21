"""Stage1 finding 适配器单测（不依赖设备与真实 LLM）。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

adapter = importlib.import_module("utilities.openharmony_dynamic.stage_finding_adapter")

REPO_ROOT = str(
    CORE.parent.parent / "evaluation_dataset" / "vulnerability" / "service_scopes"
    / "developtools_profiler_socket_scope"
)

DP02_STAGE = {
    "函数名称": "SPUtils::LoadCmd(const std::string& cmd, std::string& result)",
    "起止位置": "sp_utils.cpp:140-143",
    "所处文件路径": "host/smartperf/client/client_command/sp_utils.cpp",
    "具体漏洞源码与漏洞描述": "该包装函数没有新增校验或安全边界…",
    "完整攻击链": "1) 攻击者复用 UDP 8283 的 set_pkgName::… 与 catch_network_traffic::x 链路…"
                 "3) Network::ThreadGetHapNetwork（Network.cpp:141-163）:153-154 将污染值交给 LoadCmd…",
    "根因分析": "LoadCmd 只是字符串转发…所有上游污点都可在此变成 Shell 语义。",
}

DP02_CONVERT = {
    "vuln_class": "command_injection",
    "description": "set_pkgName 未过滤分号，dubaiPkgName 拼进 popen 命令注入",
    "sink": "popen(pidof + dubaiPkgName) at Network.cpp:153",
    "entry_hints": ["hap_udp 127.0.0.1:8283"],
}


def _convert_override_good(stage_finding):
    return DP02_CONVERT


def test_convert_ok():
    res = adapter.adapt_stage_finding(
        DP02_STAGE, finding_id="DP-02", unit_id="developtools_profiler_dp02",
        repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "CONVERTED"
    f = res.finding
    assert f.vuln_class == "command_injection"
    assert f.source_paths == ["host/smartperf/client/client_command/sp_utils.cpp"]
    assert f.evidence_lines == [[140, 143]]  # 行号来自 Stage1 原文机械解析，不经 LLM
    assert f.entry_hints == ["hap_udp 127.0.0.1:8283"]
    assert "Network.cpp:153" in f.sink
    assert "完整攻击链" in f.analysis_context
    assert f.analysis_context["根因分析"] == DP02_STAGE["根因分析"]


def test_candidate_attack_chains_are_preserved_separately_from_primary_chain():
    stage = {
        **DP02_STAGE,
        "候选攻击链": [
            [
                "sp_thread_socket.cpp:SpThreadSocket::HandleMsg",
                "Network.cpp:Network::ItemData",
                "Network.cpp:Network::ThreadGetHapNetwork",
                "sp_utils.cpp:SPUtils::LoadCmd",
            ]
        ],
    }
    res = adapter.adapt_stage_finding(
        stage, finding_id="DP-02", unit_id="developtools_profiler_dp02",
        repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "CONVERTED"
    assert res.finding.candidate_attack_chains == stage["候选攻击链"]
    assert res.finding.to_dict()["candidate_attack_chains"] == stage["候选攻击链"]
    # 主链仍然来自完整攻击链，候选链不会覆盖它。
    assert res.finding.analysis_context["完整攻击链"] == DP02_STAGE["完整攻击链"]


def test_missing_stage_keys_rejected():
    bad = dict(DP02_STAGE)
    del bad["完整攻击链"]
    res = adapter.adapt_stage_finding(
        bad, finding_id="X", repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "REQUIRES_PROTOCOL_REVIEW"
    assert "完整攻击链" in res.errors[0]


def test_bad_vuln_class_rejected():
    res = adapter.adapt_stage_finding(
        DP02_STAGE, finding_id="X", repo_root=REPO_ROOT,
        convert_override={**DP02_CONVERT, "vuln_class": "sql_injection"})
    assert res.status == "REJECTED_VALIDATION"
    assert "vuln_class 非法" in res.errors[0]


def test_hallucinated_path_rejected():
    # LLM 无法注入路径——路径来自 Stage1 原文。伪造 Stage1 路径（文件不存在）→ 拒绝
    bad_stage = {**DP02_STAGE, "所处文件路径": "host/smartperf/client/client_command/ghost.cpp"}
    res = adapter.adapt_stage_finding(
        bad_stage, finding_id="X", repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "REJECTED_VALIDATION"
    assert "源码文件不存在" in res.errors[0]


def test_out_of_range_lines_rejected():
    bad_stage = {**DP02_STAGE, "起止位置": "sp_utils.cpp:99999-100001"}
    res = adapter.adapt_stage_finding(
        bad_stage, finding_id="X", repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "REJECTED_VALIDATION"
    assert "行号越界" in res.errors[0]


def test_bad_entry_hint_shape_rejected():
    for bad in (["从蓝牙通道进入"],                     # 非网络入口（内部回调当入口）
                ["FreezeDetectorPlugin::OnEventListeningCallback (plugins/x.cpp:225-265)"],
                ["UDP 8283：set_pkgName"],            # 缺 hap_ 前缀
                ["unix_dgram relative/path"],          # socket 路径必须绝对
                ):
        res = adapter.adapt_stage_finding(
            DP02_STAGE, finding_id="X", repo_root=REPO_ROOT,
            convert_override={**DP02_CONVERT, "entry_hints": bad})
        assert res.status == "REJECTED_VALIDATION", bad
        assert "entry_hint 形态不可识别" in res.errors[0]


def test_empty_entry_hints_warning_only():
    res = adapter.adapt_stage_finding(
        DP02_STAGE, finding_id="X", repo_root=REPO_ROOT,
        convert_override={**DP02_CONVERT, "entry_hints": []})
    assert res.status == "CONVERTED"
    assert any("entry_hints 为空" in w for w in res.warnings)


def test_llm_unavailable_honest(tmp_path, monkeypatch):
    monkeypatch.setattr(adapter, "_llm_binding", lambda: None)
    res = adapter.adapt_stage_finding(
        DP02_STAGE, finding_id="X", repo_root=REPO_ROOT)
    assert res.status == "REQUIRES_PROTOCOL_REVIEW"
    assert "LLM 不可用" in res.errors[0]
    assert res.llm_used is True


def test_unparseable_location_falls_back():
    bad_stage = {**DP02_STAGE, "起止位置": "无法解析"}
    res = adapter.adapt_stage_finding(
        bad_stage, finding_id="X", repo_root=REPO_ROOT, convert_override=DP02_CONVERT)
    assert res.status == "CONVERTED"
    assert res.finding.evidence_lines == [[1, 1]]
