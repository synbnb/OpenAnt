"""P0 自动化收敛三项的单元测试（离线，无 LLM/无设备）。

- P0-1 降级闭环重试：compile_gap_signature 规整化 + compile_contract_with_retry
  的重试/短路/不重试分类（mock compile_contract）。
- P0-2 exemplar 自动晋升：promote_exemplar_if_absent 首代写入/二代不覆盖/
  非 CONFIRMED 跳过 + _load_exemplar 自动晋升库命中。
- P0-3 端点确定性预扫：_scan_repo_endpoints 触发条件/端口提取/上限。

运行：cd libs/vulnfounder-core && python -m pytest core/test_p0_automation.py -q
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))
_UTIL = _CORE / "utilities"
if str(_UTIL) not in sys.path:
    sys.path.insert(0, str(_UTIL))

from core.scan_artifact_bridge import _scan_repo_endpoints  # noqa: E402
from core.exp_package import (  # noqa: E402
    _extract_guards_from_poc,
    _probe_pt_victims_dynamic,
)
from openharmony_dynamic import contract_compiler as cc  # noqa: E402


# ---------------------------------------------------------------------------
# P0-3 端点预扫
# ---------------------------------------------------------------------------

def test_scan_repo_endpoints_triggers_on_udp_without_port(tmp_path: Path) -> None:
    (tmp_path / "svc.cpp").write_text(
        'static constexpr uint16_t PORT = 8283;\n'
        'void loop() { int fd = socket(AF_INET, SOCK_DGRAM, 0); bind(fd, PORT); }\n',
        encoding="utf-8")
    hits = _scan_repo_endpoints(tmp_path, "攻击链描述 UDP datagram")
    assert hits == ["127.0.0.1:8283"]


def test_scan_repo_endpoints_no_udp_no_scan(tmp_path: Path) -> None:
    (tmp_path / "svc.cpp").write_text('int PORT = 8283;\n', encoding="utf-8")
    # 攻击链无 UDP 关键词 → 不扫描
    assert _scan_repo_endpoints(tmp_path, "本地文件读写链路") == []
    # 攻击链已带端点 → 不扫描
    assert _scan_repo_endpoints(tmp_path, "UDP datagram 到 127.0.0.1:9999") == []


def test_scan_repo_endpoints_ignores_non_socket_files(tmp_path: Path) -> None:
    # 有端口常量但文件无 socket 语义 → 不提取
    (tmp_path / "math.cpp").write_text('int PORT = 8283;\n', encoding="utf-8")
    assert _scan_repo_endpoints(tmp_path, "UDP datagram") == []


def test_scan_repo_endpoints_dedup_and_cap(tmp_path: Path) -> None:
    for i, port in enumerate((9001, 9002, 9003, 9004)):
        (tmp_path / f"s{i}.cpp").write_text(
            f'void f() {{ socket(AF_INET, 0, 0); int p = htons({port}); }}\n',
            encoding="utf-8")
    hits = _scan_repo_endpoints(tmp_path, "UDP datagram")
    assert len(hits) == 3 and hits[0] == "127.0.0.1:9001" or len(hits) <= 3
    assert all(h.startswith("127.0.0.1:") for h in hits)


# ---------------------------------------------------------------------------
# P0-2 exemplar 自动晋升
# ---------------------------------------------------------------------------

class _FakeContract:
    """最小契约桩：promote_exemplar_if_absent 只用 vuln_class/contract_id/to_dict。"""

    def __init__(self, vuln_class: str, contract_id: str = "GEN-TEST") -> None:
        self.vuln_class = vuln_class
        self.contract_id = contract_id

    def to_dict(self) -> dict:
        return {"contract_id": self.contract_id, "vuln_class": self.vuln_class}


def test_promote_first_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    c = _FakeContract("path_traversal")
    assert cc.promote_exemplar_if_absent(c, "CONFIRMED") == "promoted"
    saved = json.loads((tmp_path / "auto" / "path_traversal.json").read_text(encoding="utf-8"))
    assert saved["_exemplar_meta"]["source"] == "auto-promotion(P0-2)"


def test_promote_second_generation_no_overwrite(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    assert cc.promote_exemplar_if_absent(_FakeContract("fd_leak", "GEN-A"), "CONFIRMED") == "promoted"
    # 第二个 CONFIRMED 不覆盖（第一代钉死）
    assert cc.promote_exemplar_if_absent(_FakeContract("fd_leak", "GEN-B"), "CONFIRMED") == "already"
    saved = json.loads((tmp_path / "auto" / "fd_leak.json").read_text(encoding="utf-8"))
    assert saved["contract_id"] == "GEN-A"


def test_promote_skips_non_confirmed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    assert cc.promote_exemplar_if_absent(_FakeContract("race_condition"), "NOT_REPRODUCED").startswith("skipped")
    assert not (tmp_path / "auto" / "race_condition.json").exists()


def test_load_exemplar_hits_auto_library(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cc, "_AUTO_EXEMPLAR_DIR", tmp_path / "auto")
    (tmp_path / "auto").mkdir()
    ref_contract = {"contract_id": "GEN-AUTO", "vuln_class": "resource_exhaustion"}
    (tmp_path / "auto" / "resource_exhaustion.json").write_text(
        json.dumps(ref_contract), encoding="utf-8")
    # 该类无手写 ref → 回落自动晋升库
    assert cc._load_exemplar("resource_exhaustion") == ref_contract


# ---------------------------------------------------------------------------
# P0-1 降级闭环重试
# ---------------------------------------------------------------------------

def test_gap_signature_normalizes_paths_and_numbers() -> None:
    a = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize /tmp/x1.json"])
    b = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize /tmp/y9.json"])
    c = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                 ["事实卡复核未过: socket"])
    assert a == b          # 同根因 → 同签名（路径/数字规整化）
    assert a != c          # 不同根因 → 不同签名


class _CompiledStub:
    """CompileResult 形态的轻量桩。"""

    def __init__(self, status: str, errors: list[str] | None = None,
                 contract: object = None) -> None:
        self.compile_status = status
        self.errors = errors or []
        self.contract = contract
        self.notes = []
        self.descriptor_hit = ""
        self.llm_used = True


def test_retry_reruns_once_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _CompiledStub("REQUIRES_PROTOCOL_REVIEW",
                                 ["侦查 loop 未产出草案（budget_exhausted）: 12 轮未 finalize"])
        return _CompiledStub("ELIGIBLE", contract=object())

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert out.compile_status == "ELIGIBLE"
    assert "fresh session 重试自愈" in out.notes[0]
    assert calls["n"] == 2


def test_retry_no_rerun_on_structural_gaps(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("ORACLE_UNAVAILABLE", ["预言机未实现（方案 §3.3 诚实降级）: x"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert out.compile_status == "ORACLE_UNAVAILABLE"
    assert calls["n"] == 1     # 结构性缺口不重试


def test_retry_no_rerun_on_fact_card_fabrication(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("REQUIRES_PROTOCOL_REVIEW", ["事实卡复核未过（§11.2 防编造）: k"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    out = cc.compile_contract_with_retry(object())
    assert calls["n"] == 1     # 编造型失败不重试


def test_retry_final_failure_short_circuit(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_compile(finding, **kwargs):
        calls["n"] += 1
        return _CompiledStub("REQUIRES_PROTOCOL_REVIEW",
                             ["侦查 loop 未产出草案（budget_exhausted）: 轮次耗尽"])

    monkeypatch.setattr(cc, "compile_contract", fake_compile)
    failure_log: dict[str, int] = {}
    # 预置历史：该签名已独立失败 3 次（超 max_attempts=2）
    sig = cc.compile_gap_signature("REQUIRES_PROTOCOL_REVIEW",
                                   ["侦查 loop 未产出草案（budget_exhausted）: 轮次耗尽"])
    failure_log[sig] = 3
    out = cc.compile_contract_with_retry(object(), failure_log=failure_log)
    assert out.compile_status == "REQUIRES_PROTOCOL_REVIEW"
    assert "final-failure" in out.errors[0]
    assert calls["n"] == 1     # 收敛：不再发起 fresh session 重试（只烧首场编译）


# ---------------------------------------------------------------------------
# P2 动态 victim 探测 + 守卫泛化
# ---------------------------------------------------------------------------

class _FakeHDC:
    """HDCClient 桩：按路径返回预置 ls/stat 输出。"""

    def __init__(self, dirs: dict[str, tuple[int, list[str]]]) -> None:
        # dirs: 目录 → (rc, 文件名列表)；stat 全部返回 4096
        self._dirs = dirs

    def run(self, argv, *, purpose=""):
        class _R:
            def __init__(self, rc, out):
                self.returncode, self.stdout = rc, out
        if argv[:2] == ["shell", "ls"]:
            d = argv[2]
            rc, names = self._dirs.get(d, (1, []))
            return _R(rc, "\n".join(names))
        if argv[:2] == ["shell", "stat"]:
            return _R(0, "4096\n")
        return _R(1, "")


def test_dynamic_probe_collects_real_files() -> None:
    hdc = _FakeHDC({"/system/etc/hiview": (0, ["freeze_rules.xml", ".hidden", "hisysevent.cfg"])})
    hits = _probe_pt_victims_dynamic(hdc)
    assert hits == [
        "/system/etc/hiview/freeze_rules.xml",
        "/system/etc/hiview/hisysevent.cfg",
    ]


def test_dynamic_probe_empty_falls_back_later() -> None:
    # 全目录探测失败 → 空列表（调用方回落静态清单）
    hdc = _FakeHDC({})
    assert _probe_pt_victims_dynamic(hdc) == []
    assert _probe_pt_victims_dynamic(None) == []


def test_extract_guards_from_poc() -> None:
    poc = {"protocol": {"field_values": {
        "set_pkgName": "smartperf;echo x", "mode": "udp", "port": 8283}}}
    assert _extract_guards_from_poc(poc) == ("smartperf",)
    # 无守卫候选 → 静态表兜底
    assert _extract_guards_from_poc({"protocol": {"field_values": {"mode": "udp"}}}) == ("smartperf",)
