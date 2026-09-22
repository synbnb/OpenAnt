"""扫描中间产物 → 真机动态测试的桥接层。

输入只来自项目扫描的中间产物（不再依赖人工整理的数据集）：

* ``evaluation_dataset/vulnerability/result/N.json`` — 聚合行（sample /
  repository / target_id / location / finding / result_file），finding 限定
  ``vulnerable`` / ``inconclusive``；
* ``result_file`` 指向的 ``stage1_runs_N/outputs/<repo>/results.json`` —
  原始英文键条目（function_analyzed / findings[file,line_start,line_end] /
  attack_scenario / dataflow_summary / attack_vector / preconditions /
  reasoning / unit_id）。

桥接分三步，语义判断全部复用现有适配器/编译器，本模块只做机械转换：

1. ``list_scan_artifacts``：枚举聚合行，按 finding 过滤（机械读文件）；
2. ``bridge_scan_entry``：英文键 → 中文键 Stage1 dict（字段一一映射，
   裸文件名用仓库内唯一命中解析成相对路径，零语义改写）；
3. ``run_dynamic_from_scan``：中文键 → adapt_stage_finding（LLM 语义转换 +
   确定性校验）→ compile_contract（侦查 loop + 硬校验）→ Runner.run（真机）。

入口线索缺口：扫描产物的攻击链常描述 "UDP datagram" 但不带端口，适配器的
严格 hint 形态要求端口。此时依据 repo → 描述符标准端点映射确定性补充
（非编造：端点会由侦查 loop/编译校验在设备上复核），补充依据随桥接产物落盘。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# repo（扫描中间产物的 repository 字段）→ 描述符标准端点。
# 只登记有已注册描述符协议族、且端点在真机上有稳定监听的仓库。
_REPO_UDP_ENDPOINTS: dict[str, str] = {
    # SP_daemon 文本协议 UDP 端口（sp_daemon_text 描述符标准端点）
    "developtools_profiler": "127.0.0.1:8283",
}

# 聚合行 finding → 可动态测试集合（与用户要求一致：inconclusive / vulnerable）
_DYNC_TESTABLE_FINDINGS = {"vulnerable", "inconclusive"}

# P0-1 缺口签名失败计数（进程级缓存）：每次 run spawn 新 Python 进程（Web 模式），
# 该缓存天然按进程隔离；CLI 批量跑多条时同一进程内跨 run 累积。
_COMPILE_FAILURE_LOG: dict[str, int] = {}

# 契约编译的 fresh-session 重试上限。默认比底层库的单元测试默认值稍高，
# 用于吸收 LLM 在 finalize 阶段偶发省略 oracle、帧槽位或源码守卫字面量的
# 非确定性；它不生成任何样本协议，也不绕过 validator。部署时可通过环境变量
# 调低/调高，但始终由 compile_contract_with_retry 做有界收敛。
_DYNAMIC_COMPILE_ATTEMPTS = max(
    1, int(os.environ.get("VULNFOUNDER_DYNAMIC_COMPILE_ATTEMPTS", "5") or "5")
)

# webui 扫描目录名白名单（与 Go 侧 jobIDRe 一致：hex，8-64 位）
_WEBUI_SCAN_ID_RE = re.compile(r"^[a-f0-9]{8,64}$")


class ScanBridgeError(ValueError):
    """扫描产物桥接失败（路径缺失、条目不存在、转换被拒等）。"""


# ---------------------------------------------------------------------------
# webui 扫描目录（~/.openant/webui/<scan_id>/results.json）桥接输入
# ---------------------------------------------------------------------------

def _webui_root(webui_dir: str | Path | None) -> Path:
    if webui_dir is not None:
        root = Path(webui_dir).expanduser().resolve()
    else:
        home = Path.home()
        primary = home / ".vulnfounder" / "webui"
        legacy = home / ".openant" / "webui"
        root = primary if primary.is_dir() else legacy
    if not root.is_dir():
        raise ScanBridgeError(f"webui 扫描目录不存在：{root}")
    return root


def _webui_scan_dir(webui_dir: str | Path | None, scan_id: str) -> Path:
    if not _WEBUI_SCAN_ID_RE.match(scan_id):
        raise ScanBridgeError(f"scan_id 形态非法：{scan_id!r}")
    scan_dir = _webui_root(webui_dir) / scan_id
    if not scan_dir.is_dir():
        raise ScanBridgeError(f"扫描目录不存在：{scan_dir}")
    return scan_dir


def _webui_result_payload(scan_dir: Path) -> dict[str, Any]:
    path = scan_dir / "results.json"
    if not path.is_file():
        raise ScanBridgeError(f"扫描产物缺失：{path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanBridgeError(f"扫描产物不可读：{exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ScanBridgeError(f"扫描产物结构不符（缺 results 列表）：{path}")
    return data


def _webui_entry_lines(entry: dict[str, Any], scan_dir: Path) -> tuple[str, int, int]:
    """条目位置：新扫描取 primary finding 的 file/line；老扫描（无 findings）
    兜底 analyzer_output.json 的 functions[unit_id]（filePath/startLine/endLine）。"""
    findings = entry.get("findings") or []
    primary = next(
        (x for x in findings
         if isinstance(x, dict) and x.get("scope") == "target" and x.get("relation") == "primary"),
        None,
    ) or next((x for x in findings if isinstance(x, dict) and x.get("file")), None)
    if isinstance(primary, dict) and primary.get("file"):
        start = primary.get("line_start") if isinstance(primary.get("line_start"), int) else 1
        end = primary.get("line_end") if isinstance(primary.get("line_end"), int) else start
        return str(primary["file"]), start, end
    unit_id = str(entry.get("unit_id", ""))
    analyzer = scan_dir / "analyzer_output.json"
    if unit_id and analyzer.is_file():
        try:
            fn = (json.loads(analyzer.read_text(encoding="utf-8")).get("functions") or {}).get(unit_id)
            if isinstance(fn, dict) and fn.get("filePath"):
                start = fn.get("startLine") if isinstance(fn.get("startLine"), int) else 1
                end = fn.get("endLine") if isinstance(fn.get("endLine"), int) else start
                return str(fn["filePath"]), start, end
        except (OSError, json.JSONDecodeError):
            pass
    return "", 1, 1


def _candidate_attack_chains_from_entry(entry: dict[str, Any]) -> list[list[str]]:
    """从扫描条目的结构化阶段上下文提取候选入口路径。

    ``results.json`` 当前没有单独的 candidate_attack_chains 顶层字段，
    但 Stage1 已经把候选入口路径保存在
    ``stage_context.stage1.candidate_entry_path_ids`` 中。桥接层把它复制为
    中文键 ``候选攻击链``，再由 FindingInput 以英文标准字段保存。这样不改写
    主攻击链，也不把候选路径误标成已确认路径。
    """
    stage_context = entry.get("stage_context") or {}
    if not isinstance(stage_context, dict):
        stage_context = {}
    stage1 = stage_context.get("stage1") or entry.get("stage1_context") or {}
    if not isinstance(stage1, dict):
        stage1 = {}
    raw = (
        stage1.get("candidate_entry_path_ids")
        or stage1.get("candidate_attack_chains")
        or entry.get("candidate_attack_chains")
        or entry.get("候选攻击链")
        or []
    )
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    paths: list[list[str]] = []
    for path in raw[:8]:
        if isinstance(path, str):
            nodes = [path.strip()[:2000]] if path.strip() else []
        elif isinstance(path, (list, tuple)):
            nodes = [str(node).strip()[:500] for node in path[:32]
                     if str(node).strip()]
        elif isinstance(path, dict):
            values = path.get("path") or path.get("nodes") or []
            if isinstance(values, str):
                nodes = [values.strip()[:2000]] if values.strip() else []
            elif isinstance(values, (list, tuple)):
                nodes = [str(node).strip()[:500] for node in values[:32]
                         if str(node).strip()]
            else:
                nodes = []
        else:
            nodes = []
        if nodes:
            paths.append(nodes)
    return paths


def list_webui_scans(webui_dir: str | Path | None = None) -> list[dict[str, Any]]:
    """列出 webui 下全部扫描（供前端选择表单；新扫描在前）。"""
    root = _webui_root(webui_dir)
    scans: list[dict[str, Any]] = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or not _WEBUI_SCAN_ID_RE.match(path.name):
            continue
        meta_path = path / "meta.json"
        if not (path / "results.json").is_file() or not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        try:
            payload = _webui_result_payload(path)
        except ScanBridgeError:
            continue
        metrics = payload.get("metrics") or {}
        scans.append({
            "scan_id": path.name,
            "started_at": str(meta.get("started_at", "")),
            "platform": str(meta.get("platform", "")),
            "repo": str(meta.get("repo", "")),
            "repo_name": Path(str(meta.get("repo", ""))).name,
            "languages": meta.get("languages") or [],
            "model": str(payload.get("model", "")),
            "provider": str(payload.get("provider", "")),
            "total": metrics.get("total"),
            "vulnerable": metrics.get("vulnerable"),
            "inconclusive": metrics.get("inconclusive"),
            "protected": metrics.get("protected"),
            "safe": metrics.get("safe"),
            "bypassable": metrics.get("bypassable"),
            "errors": metrics.get("errors"),
        })
    scans.sort(key=lambda s: s["started_at"], reverse=True)
    return scans


def list_webui_entries(
    webui_dir: str | Path | None,
    scan_id: str,
    *,
    finding: str | None = None,
) -> list[ScanEntry]:
    """列出一次 webui 扫描中 finding ∈ {vulnerable, inconclusive} 的条目。"""
    scan_dir = _webui_scan_dir(webui_dir, scan_id)
    payload = _webui_result_payload(scan_dir)
    entries: list[ScanEntry] = []
    for row in payload["results"]:
        if not isinstance(row, dict):
            continue
        f = str(row.get("finding", ""))
        if f not in _DYNC_TESTABLE_FINDINGS:
            continue
        if finding and f != finding:
            continue
        file_rel, line_start, line_end = _webui_entry_lines(row, scan_dir)
        location = f"{file_rel}:{line_start}-{line_end}" if file_rel else ""
        entry = ScanEntry(
            round_n=0,
            sample=str(row.get("primary_finding_id") or row.get("unit_id") or ""),
            repository=str(row.get("unit_id", "")),
            target_id=str(row.get("unit_id", "")),
            location=location,
            finding=f,
            confusion_outcome=str(row.get("security_classification", "")),
            confidence=row.get("confidence") if isinstance(row.get("confidence"), (int, float)) else None,
            result_file=str(scan_dir / "results.json"),
            unit_id=str(row.get("unit_id", "")),
            function_analyzed=str(row.get("function_analyzed", "")),
            attack_vector=str(row.get("attack_vector", "")),
            reasoning=str(row.get("reasoning", "")),
        )
        # 前端展示用的附加语义字段（results.json 原始字段透传，零改写）
        entry.extra = {
            "cwe_id": row.get("cwe_id"),
            "cwe_name": row.get("cwe_name", ""),
            "vulnerability_categories": row.get("vulnerability_categories") or [],
            "impact": row.get("impact") or [],
            "attack_scenario": str(row.get("attack_scenario", "")),
            "preconditions": str(row.get("preconditions", "")),
            "dataflow_summary": str(row.get("dataflow_summary", "")),
            "guard_analysis": str(row.get("guard_analysis", "")),
            "evidence": [str(x) for x in (row.get("evidence") or [])],
            "counterevidence": [str(x) for x in (row.get("counterevidence") or [])],
            "missing_evidence": [str(x) for x in (row.get("missing_evidence") or [])],
            "verdict": str(row.get("verdict", "")),
            "code_excerpt": (src_code := (payload.get("code_by_route") or {}).get(str(row.get("route_key", "")), ""))
                            and src_code[:4000] or "",
        }
        entries.append(entry)
    return entries


def bridge_webui_entry(
    webui_dir: str | Path | None,
    *,
    scan_id: str,
    sample: str,
    repo_root: str | Path | None = None,
) -> tuple[dict[str, Any], ScanEntry]:
    """webui results.json 条目 → 中文键 Stage1 dict（机械映射）。"""
    scan_dir = _webui_scan_dir(webui_dir, scan_id)
    payload = _webui_result_payload(scan_dir)
    entry = next(
        (r for r in payload["results"]
         if isinstance(r, dict)
         and (str(r.get("primary_finding_id") or "") == sample or str(r.get("unit_id") or "") == sample)),
        None,
    )
    if entry is None:
        raise ScanBridgeError(f"扫描 {scan_id} 无 sample={sample}")
    f = str(entry.get("finding", ""))
    if f not in _DYNC_TESTABLE_FINDINGS:
        raise ScanBridgeError(
            f"finding={f} 不可动态测试（允许 {'、'.join(sorted(_DYNC_TESTABLE_FINDINGS))}）"
        )
    meta: dict[str, Any] = {}
    meta_path = scan_dir / "meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
    repo_path = str(meta.get("repo", ""))
    if repo_root is not None:
        resolved_root = Path(repo_root).expanduser().resolve()
    elif repo_path and Path(repo_path).is_dir():
        resolved_root = Path(repo_path)
    else:
        raise ScanBridgeError(f"扫描仓库根目录不可用：{repo_path!r}（可用 --repo-root 指定）")

    file_rel, line_start, line_end = _webui_entry_lines(entry, scan_dir)
    findings = entry.get("findings") or []
    primary = next(
        (x for x in findings
         if isinstance(x, dict) and x.get("scope") == "target" and x.get("relation") == "primary"),
        None,
    ) or next((x for x in findings if isinstance(x, dict) and x.get("file")), None) or {}
    primary_reasoning = str(primary.get("reasoning", "")) if isinstance(primary, dict) else ""

    chain_parts = [
        str(entry.get("attack_scenario", "") or ""),
        "Dataflow: " + str(entry.get("dataflow_summary", "")) if entry.get("dataflow_summary") else "",
        "Attack vector: " + str(entry.get("attack_vector", "")) if entry.get("attack_vector") else "",
        "Preconditions: " + str(entry.get("preconditions", "")) if entry.get("preconditions") else "",
    ]
    candidate_attack_chains = _candidate_attack_chains_from_entry(entry)
    bridge = {
        "函数名称": str(entry.get("function_analyzed", "")),
        "起止位置": f"{Path(file_rel).name}:{line_start}-{line_end}" if file_rel else f"unknown:{line_start}-{line_end}",
        "所处文件路径": file_rel,
        "具体漏洞源码与漏洞描述": str(entry.get("reasoning", "")),
        "完整攻击链": "\n\n".join(p for p in chain_parts if p),
        "候选攻击链": candidate_attack_chains,
        "根因分析": primary_reasoning or str(entry.get("reasoning", "")),
        # 入口发现 Agent Loop 需要看到原始证据，而不是只有一段压缩后的
        # reasoning。以下字段仍是 Stage 1 产物的只读副本，不被适配器当作
        # 已验证事实；它们用于指导后续 read_file/grep/hdc 取证。
        "证据": [str(x) for x in (entry.get("evidence") or [])],
        "反证": [str(x) for x in (entry.get("counterevidence") or [])],
        "缺失证据": [str(x) for x in (entry.get("missing_evidence") or [])],
        "防护分析": str(entry.get("guard_analysis", "")),
        "漏洞类别": entry.get("vulnerability_categories") or [],
        "影响": entry.get("impact") or [],
        "目标源码片段": str(entry.get("code_excerpt", "")),
    }

    # 入口线索确定性补充：与 N.json 桥接同一规则（repo → 描述符标准端点）。
    # webui 输入下 repo 来自 meta.repo 路径名；developtools_profiler 系匹配 UDP 映射。
    # 触发条件：攻击链含 UDP/datagram，或（profiler repo 且攻击链描述 socket 接收
    # 路径——SP_daemon 服务本质是 UDP 文本协议端口，socket 词是该协议族的泛称）。
    chain_text = bridge["完整攻击链"]
    has_endpoint = re.search(r"\d+\.\d+\.\d+\.\d+:\d+", chain_text)
    repo_key = next((k for k in _REPO_UDP_ENDPOINTS
                     if k in resolved_root.name or k in repo_path), "")
    is_udp = bool(re.search(r"\bUDP\b|\budp\b|datagram", chain_text))
    is_profiler_socket = (
        repo_key == "developtools_profiler"
        and re.search(r"socket", chain_text, re.IGNORECASE)
        and re.search(r"SP_daemon|sp_daemon|SmartPerf|smartperf|LoadCmd|SPUtils", chain_text)
    )
    endpoint = ""
    source_desc = ""
    if not has_endpoint and (is_udp or is_profiler_socket):
        if repo_key:
            endpoint = _REPO_UDP_ENDPOINTS[repo_key]
            source_desc = f"{repo_key} 对应描述符 sp_daemon_text 标准端点"
        else:
            # 映射表未命中 → repo 源码确定性预扫兜底（P0-3）
            candidates = _scan_repo_endpoints(resolved_root, chain_text)
            if candidates:
                endpoint = candidates[0]
                source_desc = f"{resolved_root.name} 源码确定性预扫（共现 socket 语义的端口常量，候选 {len(candidates)} 个取首个）"
    if endpoint:
        bridge["完整攻击链"] += (
            f"\n\n[bridge] 入口线索（确定性补充，来源：{source_desc}，需设备复核）: hap_udp {endpoint}"
        )

    scan_entry = ScanEntry(
        round_n=0,
        sample=sample,
        repository=str(resolved_root),
        target_id=str(entry.get("unit_id", "")),
        location=bridge["起止位置"],
        finding=f,
        confusion_outcome=str(entry.get("security_classification", "")),
        confidence=entry.get("confidence") if isinstance(entry.get("confidence"), (int, float)) else None,
        result_file=str(scan_dir / "results.json"),
        unit_id=str(entry.get("unit_id", "")),
        function_analyzed=str(entry.get("function_analyzed", "")),
        attack_vector=str(entry.get("attack_vector", "")),
        reasoning=str(entry.get("reasoning", "")),
    )
    return bridge, scan_entry


@dataclass
class ScanEntry:
    """一条可动态测试的扫描中间产物条目。"""

    round_n: int
    sample: str
    repository: str
    target_id: str
    location: str
    finding: str
    confusion_outcome: str
    confidence: float | None
    result_file: str
    unit_id: str = ""
    function_analyzed: str = ""
    attack_vector: str = ""
    reasoning: str = ""
    # 前端展示附加字段（results.json 原始语义字段透传；非 dataclass 字段避免
    # 影响 to_dict 契约，动态挂载后由 __dict__ 一并序列化）
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d.pop("extra", None)
        if self.extra:
            d.update(self.extra)
        return d


def _result_dir(result_dir: str | Path) -> Path:
    root = Path(result_dir).expanduser().resolve()
    if not root.is_dir():
        raise ScanBridgeError(f"扫描结果目录不存在：{root}")
    return root


def _agg_rows(result_root: Path, round_n: int) -> list[dict[str, Any]]:
    path = result_root / f"{round_n}.json"
    if not path.is_file():
        raise ScanBridgeError(f"聚合产物不存在：{path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanBridgeError(f"聚合产物不可读：{exc}") from exc
    rows = data if isinstance(data, list) else data.get("rows", [])
    return [r for r in rows if isinstance(r, dict)]


def list_scan_rounds(result_dir: str | Path) -> list[dict[str, Any]]:
    """列出全部历史扫描轮次及其中可动态测试条目的计数。"""
    root = _result_dir(result_dir)
    rounds: list[dict[str, Any]] = []
    for path in sorted(
        root.glob("[0-9]*.json"),
        key=lambda p: int(p.stem) if p.stem.isdigit() else 10**9,
    ):
        if not path.stem.isdigit():
            continue
        try:
            rows = _agg_rows(root, int(path.stem))
        except ScanBridgeError:
            continue
        findings: dict[str, int] = {}
        for row in rows:
            f = str(row.get("finding", ""))
            if f in _DYNC_TESTABLE_FINDINGS:
                findings[f] = findings.get(f, 0) + 1
        repos = sorted({str(row.get("repository", "")) for row in rows if row.get("repository")})
        rounds.append({
            "round": int(path.stem),
            "total_rows": len(rows),
            "testable_counts": findings,
            "repositories": repos,
        })
    return rounds


def list_scan_entries(
    result_dir: str | Path,
    *,
    round_n: int,
    finding: str | None = None,
    repository: str | None = None,
) -> list[ScanEntry]:
    """列出某一轮扫描中 finding ∈ {vulnerable, inconclusive} 的条目。"""
    root = _result_dir(result_dir)
    rows = _agg_rows(root, round_n)
    entries: list[ScanEntry] = []
    for row in rows:
        f = str(row.get("finding", ""))
        if f not in _DYNC_TESTABLE_FINDINGS:
            continue
        if finding and f != finding:
            continue
        repo = str(row.get("repository", ""))
        if repository and repo != repository:
            continue
        entries.append(ScanEntry(
            round_n=round_n,
            sample=str(row.get("sample", "")),
            repository=repo,
            target_id=str(row.get("target_id", "")),
            location=str(row.get("location", "")),
            finding=f,
            confusion_outcome=str(row.get("confusion_outcome", "")),
            confidence=row.get("confidence") if isinstance(row.get("confidence"), (int, float)) else None,
            result_file=str(row.get("result_file", "")),
        ))
    return entries



# ---------------------------------------------------------------------------
# repo 端点确定性预扫（全自动化收敛 P0-3）：静态扫描产物的攻击链常不带端口，
# 映射表又只登记了少数 repo。此处在 repo 源码内做确定性 rglob 预扫，提取
# socket 端点常量（htons/inetAddress/port 字面量），作为映射表缺位时的
# 兜底入口线索——非编造：补充值随后由 L2 侦查 loop 与 V4/描述符在设备上复核。
# ---------------------------------------------------------------------------

_PORT_CONST_RE = re.compile(r"htons\((\d{2,5})\)|inet_addr\(.*?(\d{2,5})\)|PORT\s*=\s*(\d{2,5})\b|port\s*=\s*(\d{2,5})\b|(\d{2,5})\);\s*//\s*[Uu][Dd][Pp]")
_SOCKET_HINT_RE = re.compile(r"socket\(|bind\(|recvfrom\(|recv\(|udp|UDP")
_MAX_SCAN_FILES = 400          # rglob 上限（防大仓库失控）
_SCANABLE_SUFFIXES = {".cpp", ".c", ".cc", ".h", ".hpp", ".ets", ".ts"}


def _scan_repo_endpoints(repo_root: str | Path, chain_text: str) -> list[str]:
    """确定性预扫 repo 源码，返回候选端点 "ip:port" 列表（去重保序，最多 3 个）。

    触发条件（与映射表补充同一逻辑）：攻击链含 UDP/datagram 且不含 ip:port。
    只提取与 socket 语义共现的端口常量（同文件含 socket/bind/recvfrom/udp
    关键词才收），避免把无关数字常量误报为端点。
    """
    if not re.search(r"\bUDP\b|\budp\b|datagram", chain_text or ""):
        return []
    if re.search(r"\d+\.\d+\.\d+\.\d+:\d+", chain_text or ""):
        return []   # 攻击链已带端点，无需预扫
    root = Path(repo_root)
    if not root.is_dir():
        return []
    ports: list[str] = []
    files = sorted(p for p in root.rglob("*")
                   if p.is_file() and p.suffix in _SCANABLE_SUFFIXES)[:_MAX_SCAN_FILES]
    for path in files:
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _SOCKET_HINT_RE.search(text):
            continue   # 无 socket 语义的文件不提端口
        for m in _PORT_CONST_RE.finditer(text):
            port = next((g for g in m.groups() if g), "")
            if port and 1024 <= int(port) <= 65535 and f"127.0.0.1:{port}" not in ports:
                ports.append(f"127.0.0.1:{port}")
                if len(ports) >= 3:
                    return ports
    return ports


def _resolve_repo_path(repo_root: Path, bare_name: str) -> str:
    """扫描产物的 file 是裸文件名；仓库内唯一命中才解析，否则原样返回。"""
    if not bare_name or "/" in bare_name:
        return bare_name
    hits = [p for p in repo_root.rglob(bare_name) if p.is_file()]
    if len(hits) == 1:
        return hits[0].relative_to(repo_root).as_posix()
    return bare_name


def bridge_scan_entry(
    result_dir: str | Path,
    *,
    round_n: int,
    sample: str,
    repo_root: str | Path | None = None,
) -> tuple[dict[str, Any], ScanEntry]:
    """聚合行 + stage1 原始条目 → 中文键 Stage1 dict（机械映射）。

    返回 (bridge_dict, entry)。bridge_dict 的键与
    ``adapt_stage_finding`` 的要求一致：函数名称 / 起止位置 / 所处文件路径 /
    具体漏洞源码与漏洞描述 / 完整攻击链 / 根因分析。
    """
    root = _result_dir(result_dir)
    rows = _agg_rows(root, round_n)
    row = next((r for r in rows if str(r.get("sample", "")) == sample), None)
    if row is None:
        raise ScanBridgeError(f"第 {round_n} 轮无 sample={sample}")
    f = str(row.get("finding", ""))
    if f not in _DYNC_TESTABLE_FINDINGS:
        raise ScanBridgeError(
            f"finding={f} 不可动态测试（允许 {'、'.join(sorted(_DYNC_TESTABLE_FINDINGS))}）"
        )
    repo = str(row.get("repository", ""))
    target_id = str(row.get("target_id", ""))
    result_file = Path(str(row.get("result_file", "")))
    if not result_file.is_file():
        raise ScanBridgeError(f"result_file 不存在：{result_file}")

    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanBridgeError(f"stage1 产物不可读：{exc}") from exc
    entry = next(
        (r for r in data.get("results", [])
         if isinstance(r, dict) and str(r.get("unit_id", "")) == target_id),
        None,
    )
    if entry is None:
        raise ScanBridgeError(f"{result_file} 无 unit_id={target_id} 的条目")

    findings = entry.get("findings") or []
    primary = next(
        (x for x in findings
         if isinstance(x, dict) and x.get("scope") == "target" and x.get("relation") == "primary"),
        None,
    ) or next((x for x in findings if isinstance(x, dict) and x.get("file")), None) or {}
    line_start = primary.get("line_start") if isinstance(primary.get("line_start"), int) else 1
    line_end = primary.get("line_end") if isinstance(primary.get("line_end"), int) else line_start

    if repo_root is not None:
        resolved_root = Path(repo_root).expanduser().resolve()
    else:
        # 缺省：项目内 socket_scope 仓库（与扫描产物路径约定一致）。
        # 本模块位于 <project>/libs/vulnfounder-core/core/，项目根在 parents[3]。
        resolved_root = (
            Path(__file__).resolve().parents[3]
            / "evaluation_dataset" / "vulnerability" / "service_scopes" / f"{repo}_socket_scope"
        )
    if not resolved_root.is_dir():
        raise ScanBridgeError(f"仓库根目录不存在：{resolved_root}")

    file_rel = _resolve_repo_path(resolved_root, str(primary.get("file", "")))
    chain_parts = [
        str(entry.get("attack_scenario", "") or ""),
        "Dataflow: " + str(entry.get("dataflow_summary", "")) if entry.get("dataflow_summary") else "",
        "Attack vector: " + str(entry.get("attack_vector", "")) if entry.get("attack_vector") else "",
        "Preconditions: " + str(entry.get("preconditions", "")) if entry.get("preconditions") else "",
    ]
    candidate_attack_chains = _candidate_attack_chains_from_entry(entry)
    bridge = {
        "函数名称": str(entry.get("function_analyzed", "")),
        "起止位置": f"{Path(file_rel).name}:{line_start}-{line_end}",
        "所处文件路径": file_rel,
        "具体漏洞源码与漏洞描述": str(entry.get("reasoning", "")),
        "完整攻击链": "\n\n".join(p for p in chain_parts if p),
        "候选攻击链": candidate_attack_chains,
        "根因分析": str(primary.get("reasoning") or entry.get("reasoning", "")),
    }

    # 入口线索确定性补充：攻击链描述 UDP/datagram 但适配器严格形态要求端口。
    # 端点来源两级：① repo → 描述符标准端点映射表；② 映射表未命中时 repo 源码
    # 确定性预扫（htons/bind 共现的端口常量，P0-3 全自动化收敛）。侦查 loop 与
    # 编译校验会在设备上复核，预扫值只是线索不是结论。
    if not re.search(r"\d+\.\d+\.\d+\.\d+:\d+", bridge["完整攻击链"]) and \
            re.search(r"\bUDP\b|\budp\b|datagram", bridge["完整攻击链"]):
        endpoint = _REPO_UDP_ENDPOINTS.get(repo, "")
        source_desc = f"{repo} 对应描述符 sp_daemon_text 标准端点"
        if not endpoint:
            candidates = _scan_repo_endpoints(resolved_root, bridge["完整攻击链"])
            if candidates:
                endpoint = candidates[0]
                source_desc = f"{repo} 源码确定性预扫（共现 socket 语义的端口常量，候选 {len(candidates)} 个取首个）"
        if endpoint:
            bridge["完整攻击链"] += (
                f"\n\n[bridge] 入口线索（确定性补充，来源：{source_desc}，需设备复核）: hap_udp {endpoint}"
            )

    scan_entry = ScanEntry(
        round_n=round_n,
        sample=sample,
        repository=repo,
        target_id=target_id,
        location=str(row.get("location", "")),
        finding=f,
        confusion_outcome=str(row.get("confusion_outcome", "")),
        confidence=row.get("confidence") if isinstance(row.get("confidence"), (int, float)) else None,
        result_file=str(result_file),
        unit_id=str(entry.get("unit_id", "")),
        function_analyzed=str(entry.get("function_analyzed", "")),
        attack_vector=str(entry.get("attack_vector", "")),
        reasoning=str(entry.get("reasoning", "")),
    )
    return bridge, scan_entry


@dataclass
class ScanDynamicResult:
    """一次扫描产物动态测试的完整结果。"""

    entry: ScanEntry
    bridge: dict[str, Any]
    adapter_status: str = ""
    adapter_errors: list[str] = field(default_factory=list)
    adapter_warnings: list[str] = field(default_factory=list)
    vuln_class: str = ""
    sink: str = ""
    entry_hints: list[str] = field(default_factory=list)
    compile_status: str = ""
    compile_errors: list[str] = field(default_factory=list)
    compile_notes: list[str] = field(default_factory=list)
    entry_discovery: dict[str, Any] = field(default_factory=dict)
    descriptor_resolution: dict[str, Any] = field(default_factory=dict)
    protocol_evidence: dict[str, Any] = field(default_factory=dict)
    probe_result: dict[str, Any] = field(default_factory=dict)
    # L0 只读设备/版本/服务前置确认。它与协议编译、漏洞判定分开保存，
    # 避免把设备不存在误读成协议或预言机失败。
    device_fingerprint: dict[str, Any] = field(default_factory=dict)
    run_id: str = ""
    pattern: str = ""
    status: str = ""
    evidence_grade: str = ""
    verdict: dict[str, Any] = field(default_factory=dict)
    record_path: str = ""
    record: dict[str, Any] = field(default_factory=dict)
    contract: dict[str, Any] = field(default_factory=dict)
    deliverables: dict[str, Any] = field(default_factory=dict)
    # 计划要求的每样本标准化产物。即使在契约编译前被阻断，也会生成
    # protocol_contract/probe/payload/oracle/input_influence/dynamic/cleanup
    # 七个状态文件，明确区分 NOT_RUN、BLOCKED、PASSED 和 UNKNOWN，避免
    # 前端只看到一个没有上下文的 error。
    standard_artifacts: dict[str, Any] = field(default_factory=dict)
    clean_room: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry.to_dict(),
            "bridge": self.bridge,
            "adapter_status": self.adapter_status,
            "adapter_errors": self.adapter_errors,
            "adapter_warnings": self.adapter_warnings,
            "vuln_class": self.vuln_class,
            "sink": self.sink,
            "entry_hints": self.entry_hints,
            "compile_status": self.compile_status,
            "compile_errors": self.compile_errors,
            "compile_notes": self.compile_notes,
            "entry_discovery": self.entry_discovery,
            "descriptor_resolution": self.descriptor_resolution,
            "protocol_evidence": self.protocol_evidence,
            "probe_result": self.probe_result,
            "device_fingerprint": self.device_fingerprint,
            "run_id": self.run_id,
            "pattern": self.pattern,
            "status": self.status,
            "evidence_grade": self.evidence_grade,
            "verdict": self.verdict,
            "record_path": self.record_path,
            "record": self.record,
            "contract": self.contract,
            "deliverables": self.deliverables,
            "standard_artifacts": self.standard_artifacts,
            "clean_room": self.clean_room,
            "context_mode": "clean_room" if self.clean_room else "assisted",
            "context_sources": (
                ["current_finding", "current_source_evidence"]
                if self.clean_room else
                ["current_finding", "current_source_evidence", "device_facts", "exemplar"]
            ),
        }


def _progress_emitter(progress_path: str | Path | None):
    """进度事件发射器（--progress-file）：每事件一行 JSONL 追加落盘。

    Go 桥接层为每次 run 建独立目录并轮询该文件做 SSE 实时推送；写失败
    静默忽略（进度展示绝不影响执行本体）。
    """
    if not progress_path:
        return None
    path = Path(progress_path)
    import threading as _threading

    lock = _threading.Lock()

    def emit(event: dict[str, Any]) -> None:
        import time as _time

        row = {"ts": _time.time(), **event}
        try:
            line = json.dumps(row, ensure_ascii=False)
        except (TypeError, ValueError):
            return
        try:
            with lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except OSError:
            pass

    return emit


def _write_run_snapshot(progress_path: str | Path | None, name: str, payload: Any) -> None:
    """把动态测试的关键中间状态写入 Web run 目录。

    这些快照是面向审计和页面展示的只读副本，不参与执行决策。采用同目录
    临时文件再替换，避免前端轮询时读到半个 JSON；写失败也不能影响真机
    测试本身。文件名由调用方固定，Go 侧还会再次按白名单限制读取范围。
    """
    if not progress_path:
        return
    try:
        root = Path(progress_path).expanduser().resolve().parent
        root.mkdir(parents=True, exist_ok=True)
        path = root / name
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        tmp.replace(path)
    except (OSError, TypeError, ValueError):
        # 运行快照是可选的可观测性产物，不能改变测试结论。
        return


def _emit_compile_diagnostics(emit, compile_result) -> None:
    """把契约编译的 notes/errors 写入同一条进度流。

    入口发现、描述符补证和侦查 loop 原本都有逐轮事件，但编译器最后的
    设备自证结果只停留在 ScanDynamicResult.compile_notes 中，前端实时日志
    因而看不到“为什么通过/为什么回退”。统一转成结构化事件，失败时也先
    落盘再抛出 ScanBridgeError，便于前端和后续审计复用。
    """
    if emit is None:
        return
    for note in list(getattr(compile_result, "notes", []) or []):
        try:
            emit({
                "event": "compile_note",
                "detail": str(note),
                "record": {"kind": "compile_note", "status": compile_result.compile_status},
            })
        except Exception:  # noqa: BLE001 — 进度展示不能影响主流程
            pass
    for error in list(getattr(compile_result, "errors", []) or []):
        try:
            emit({
                "event": "compile_error",
                "detail": str(error),
                "record": {"kind": "compile_error", "status": compile_result.compile_status},
            })
        except Exception:  # noqa: BLE001
            pass


def _run_device_preflight(
    *, finding: Any, hdc: Any, repo_root: str | Path | None,
    progress_path: str | Path | None, emit: Any,
    allow_service_start: bool = False,
) -> dict[str, Any]:
    """运行 L0 只读设备确认并落盘快照。

    该阶段不做服务启动或载荷安装；即使某个设备命令失败，也返回带有
    ``UNKNOWN``/错误明细的快照，让后续编译器根据证据决定是否可继续。
    """
    try:
        from openharmony_dynamic.device_preflight import collect_device_fingerprint

        hints = list(getattr(finding, "entry_hints", []) or [])
        context = getattr(finding, "analysis_context", None)
        reference = context.get("device_reference") if isinstance(context, dict) else None
        process_names: list[str] = []
        if isinstance(context, dict):
            raw_processes = context.get("target_processes", context.get("target_process", []))
            if isinstance(raw_processes, str):
                process_names.append(raw_processes)
            elif isinstance(raw_processes, (list, tuple)):
                process_names.extend(str(item) for item in raw_processes if str(item).strip())
        fingerprint = collect_device_fingerprint(
            hdc,
            targets=hints,
            process_names=process_names,
            source_revision=str(context.get("source_revision", "")) if isinstance(context, dict) else "",
            reference=reference if isinstance(reference, dict) else None,
            repo_root=repo_root,
        )
        # 服务启动命令只能来自当前 finding 的结构化设备上下文，并且必须
        # 是参数数组；不接受字符串 shell 命令，也不为任何服务名内置命令。
        start_commands = context.get("service_start_commands", []) if isinstance(context, dict) else []
        valid_start_commands = [
            [str(part) for part in command]
            for command in (start_commands if isinstance(start_commands, list) else [])
            if isinstance(command, (list, tuple)) and command and all(str(part).strip() for part in command)
        ]
        health = dict(fingerprint.service_health or {})
        if health.get("status") == "NOT_READY" and valid_start_commands and allow_service_start:
            attempts: list[dict[str, Any]] = []
            for command in valid_start_commands[:4]:
                rec = hdc.shell(command, purpose="preflight:service-start")
                attempts.append({
                    "argv": list(command), "returncode": getattr(rec, "returncode", -1),
                    "stdout": str(getattr(rec, "stdout", "") or "")[:512],
                    "stderr": str(getattr(rec, "stderr", "") or "")[:512],
                })
            # 启动后必须重新采集两次，不能因启动命令返回 0 就宣称服务就绪。
            import time as _time
            observations = []
            for index in range(2):
                _time.sleep(0.5)
                refreshed = collect_device_fingerprint(
                    hdc, targets=hints, process_names=process_names,
                    source_revision=str(context.get("source_revision", "")) if isinstance(context, dict) else "",
                    reference=reference if isinstance(reference, dict) else None,
                    repo_root=repo_root,
                )
                observations.append({"index": index + 1, "status": refreshed.service_health.get("status"),
                                     "ready": refreshed.service_health.get("ready", False)})
                fingerprint = refreshed
                if refreshed.service_health.get("status") == "READY":
                    break
            fingerprint.service_health = dict(fingerprint.service_health or {})
            fingerprint.service_health.update({
                "start_attempts": attempts,
                "health_checks_after_start": observations,
                "mutation_performed": True,
                "mutation_policy": "explicit_finding_commands_and_user_opt_in",
            })
        elif health.get("status") == "NOT_READY":
            health["start_attempts"] = []
            health["health_checks_after_start"] = []
            health["start_command_available"] = bool(valid_start_commands)
            health["mutation_performed"] = False
            health["mutation_policy"] = (
                "not_authorized" if valid_start_commands and not allow_service_start
                else "no_structured_start_command"
            )
            fingerprint.service_health = health
        payload = fingerprint.to_dict()
    except Exception as exc:  # noqa: BLE001 — 前置诊断失败不应吞掉主错误
        payload = {
            "schema_version": "vf.device_fingerprint.v1",
            "serial": str(getattr(hdc, "serial", "unknown")),
            "observed_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
            "status": "UNKNOWN",
            "status_reasons": [f"前置确认异常：{type(exc).__name__}: {exc}"],
            "command_errors": [{"command": "preflight", "error": str(exc)}],
            "command_count": 0,
        }
    _write_run_snapshot(progress_path, "device_fingerprint.json", payload)
    if emit is not None:
        try:
            emit({
                "event": "device_preflight",
                "detail": f"L0 设备前置确认：{payload.get('status', 'UNKNOWN')}",
                "record": payload,
            })
        except Exception:  # noqa: BLE001 — 进度展示不能影响动态测试
            pass

    return payload


def _standard_artifact_payloads(result: ScanDynamicResult, *, phase: str,
                                 reason: str = "") -> dict[str, dict[str, Any]]:
    """构造计划规定的七个可复查产物。

    这里刻意不把 ``effect_observed`` 推导成 ``input_influence``：文件变化
    只能说明预言机看到变化，不能单独证明指定外部字段控制了危险参数。只有
    Runner/旧动态执行器明确写入输入影响证据时才标记为 proven，其余保持
    unknown/unproven。
    """
    now = __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())
    base = {
        "schema_version": "vf.dynamic_artifact.v1",
        "generated_at": now,
        "phase": phase,
        "sample": result.entry.sample,
        "function_analyzed": result.entry.function_analyzed,
        "target_id": result.entry.target_id,
        "reason": reason,
    }
    compile_status = result.compile_status or "NOT_STARTED"
    contract_ready = bool(result.contract)
    protocol = dict(base)
    protocol.update({
        "status": "READY" if contract_ready else "NOT_READY",
        "compile_status": compile_status,
        "contract": result.contract if contract_ready else None,
        "descriptor_resolution": result.descriptor_resolution,
        "protocol_evidence": result.protocol_evidence,
    })
    notes = [str(item) for item in result.compile_notes]
    probe_status = "NOT_RUN"
    probe_record_status = str((result.probe_result or {}).get("status", ""))
    if probe_record_status == "PASSED" or any("合法报文自证通过" in item for item in notes):
        probe_status = "PASSED"
    elif probe_record_status in {"BLOCKED", "NOT_DELIVERED", "NOT_CONFIRMED", "ERROR"}:
        probe_status = probe_record_status
    elif any("合法探测" in item or "自证" in item for item in notes) or result.descriptor_resolution:
        probe_status = "FAILED" if result.compile_status not in {"ELIGIBLE", ""} else "UNKNOWN"
    probe = dict(base)
    probe.update({
        "status": probe_status,
        "source": "contract_compiler",
        "descriptor_resolution": result.descriptor_resolution,
        "probe_result": result.probe_result,
        "notes": notes,
    })
    observations = list((result.record or {}).get("observations") or [])
    payload = dict(base)
    payload.update({
        "status": "CAPTURED" if observations else "NOT_RUN",
        "source": "run_record.observations",
        "frames": [
            {
                "observation_id": item.get("observation_id", ""),
                "transport": item.get("transport", {}),
                "response_excerpt": item.get("response_excerpt", ""),
            }
            for item in observations if isinstance(item, dict)
        ],
        "contract_id": result.contract.get("contract_id", "") if result.contract else "",
    })
    verdict = result.verdict if isinstance(result.verdict, dict) else {}
    oracle_value = verdict.get("oracle") if isinstance(verdict.get("oracle"), dict) else {}
    oracle = dict(base)
    oracle.update({
        "status": "OBSERVED" if oracle_value.get("effect_observed") is True else (
            "ABSENT" if oracle_value else "NOT_RUN"
        ),
        "kind": oracle_value.get("kind", ""),
        "effect_observed": oracle_value.get("effect_observed"),
        "forms": oracle_value.get("forms", {}),
        "details": oracle_value.get("details", {}),
        "refutation_checks": oracle_value.get("refutation_checks", []),
    })
    influence_value = str(verdict.get("influence", "") or "")
    if influence_value == "SINK_CONTROLLED":
        influence_status = "PROVEN"
    elif influence_value == "SINK_REACHED_UNCONTROLLED":
        influence_status = "UNPROVEN"
    elif influence_value:
        influence_status = "UNKNOWN"
    else:
        influence_status = "NOT_RUN"
    influence = dict(base)
    influence.update({
        "status": influence_status,
        "influence": influence_value,
        "evidence": verdict.get("input_influence_evidence", {})
            if isinstance(verdict, dict) else {},
        "limitations": [
            "设备效果与输入影响分别记录；本文件不因文件差分自动宣称参数可控。"
        ],
    })
    dynamic = dict(base)
    entry_payload = result.entry.to_dict() if hasattr(result.entry, "to_dict") else {
        "sample": result.entry.sample,
        "function_analyzed": result.entry.function_analyzed,
        "target_id": result.entry.target_id,
    }
    dynamic.update({
        "status": result.status or ("BLOCKED" if phase in {"adapter", "compile"} else "NOT_RUN"),
        "compile_status": compile_status,
        "entry": entry_payload,
        "bridge": result.bridge,
        "run_id": result.run_id,
        "pattern": result.pattern,
        "verdict": verdict,
        "device_fingerprint_status": (result.device_fingerprint or {}).get("status", "UNKNOWN"),
    })
    cleanup = dict(base)
    cleanup_record = (result.record or {}).get("cleanup")
    cleanup.update({
        "status": "RECORDED" if cleanup_record is not None else (
            "NOT_RUN" if phase in {"adapter", "compile"} else "UNKNOWN"
        ),
        "details": cleanup_record if cleanup_record is not None else {},
    })
    return {
        "protocol_contract.json": protocol,
        "probe_result.json": probe,
        "payload_manifest.json": payload,
        "input_influence.json": influence,
        "oracle_result.json": oracle,
        "dynamic_result.json": dynamic,
        "cleanup_result.json": cleanup,
    }


def _persist_standard_artifacts(result: ScanDynamicResult, progress_path: str | Path | None,
                                *, phase: str, reason: str = "") -> None:
    """写入七个标准化动态测试产物，并回填可展示的路径状态。"""
    payloads = _standard_artifact_payloads(result, phase=phase, reason=reason)
    result.standard_artifacts = {
        name: {"status": value.get("status", ""), "phase": phase}
        for name, value in payloads.items()
    }
    if not progress_path:
        return
    for name, payload in payloads.items():
        _write_run_snapshot(progress_path, name, payload)


def _maybe_build_deliverables(result: ScanDynamicResult, *, progress_path: str | Path | None,
                              finding: Any, hdc, progress_emit) -> None:
    """CONFIRMED 后打包 PoC+Exp 交付物（runs/<run_id>/deliverables/）。

    run 目录由 progress_path 的父目录推导（Go 端 runs/<run_id>/ 布局，零新增参数）。
    打包失败绝不影响主测试结果：异常折叠进 result.deliverables 的 status 字段。
    """
    if str(result.status) != "CONFIRMED" or not result.contract:
        return
    if progress_path is None:
        return
    try:
        run_dir = Path(progress_path).expanduser().resolve().parent
        if run_dir.name == "deliverables" or not run_dir.is_dir():
            return
        # PoC HAP 路径：Runner 执行时 HapTransport build 的签名产物
        # （record.observations[].transport.hap）。
        poc_hap: Path | None = None
        for o in (result.record or {}).get("observations", []):
            hap = (o.get("transport") or {}).get("hap", "")
            if hap and Path(hap).is_file():
                poc_hap = Path(hap)
                break
        from core.exp_package import build_deliverables  # noqa: PLC0415

        # LLM binding：复用 contract_compiler 的动态测试 phase 绑定（失败即模板默认）
        binding_pair = None
        try:
            from openharmony_dynamic.contract_compiler import _llm_binding  # noqa: PLC0415

            binding_pair = _llm_binding()
        except Exception:  # noqa: BLE001 — LLM 增强是可选路径
            binding_pair = None
        pkg = build_deliverables(
            run_dir=run_dir, poc_contract=result.contract, poc_hap=poc_hap,
            vuln_class=result.vuln_class, finding=finding, hdc=hdc,
            binding_pair=binding_pair, progress_emit=progress_emit,
        )
        result.deliverables = pkg.to_dict()
    except Exception as exc:  # noqa: BLE001 — 打包绝不影响主测试
        try:
            from core.exp_package import ExpPackage  # noqa: PLC0415

            result.deliverables = ExpPackage(status="failed", reason=f"{type(exc).__name__}: {exc}").to_dict()
        except Exception:  # noqa: BLE001
            pass


def run_dynamic_from_scan(
    result_dir: str | Path,
    *,
    round_n: int,
    sample: str,
    serial: str,
    hdc_path: str | None = None,
    repo_root: str | Path | None = None,
    ledger_path: str | Path | None = None,
    unit_id: str | None = None,
    progress_path: str | Path | None = None,
    clean_room: bool = False,
    allow_service_start: bool = False,
) -> ScanDynamicResult:
    """扫描中间产物条目 → 适配 → 编译契约 → 真机执行，全链一气呵成。

    serial 必须显式给出（沿用动态测试约束：绝不隐式选择板卡）。
    """
    # 惰性导入：保持本模块可被只读列表操作独立使用
    import sys as _sys

    core_dir = Path(__file__).resolve().parents[1]
    utilities_dir = core_dir / "utilities"
    for p in (str(core_dir), str(utilities_dir)):
        if p not in _sys.path:
            _sys.path.insert(0, p)

    from openharmony_dynamic.contract_compiler import compile_contract  # noqa: PLC0415
    from openharmony_dynamic.hdc_client import HDCClient  # noqa: PLC0415
    from openharmony_dynamic.runner import Runner  # noqa: PLC0415
    from openharmony_dynamic.stage_finding_adapter import adapt_stage_finding  # noqa: PLC0415

    bridge, entry = bridge_scan_entry(result_dir, round_n=round_n, sample=sample,
                                      repo_root=repo_root)
    result = ScanDynamicResult(entry=entry, bridge=bridge, clean_room=clean_room)
    _write_run_snapshot(progress_path, "bridge.json", {
        "entry": entry.to_dict(),
        "bridge": bridge,
        "source": "scan_artifact_bridge",
    })

    if repo_root is not None:
        resolved_repo_root = str(Path(repo_root).expanduser().resolve())
    else:
        resolved_repo_root = str(
            Path(__file__).resolve().parents[3]
            / "evaluation_dataset" / "vulnerability" / "service_scopes"
            / f"{entry.repository}_socket_scope"
        )
    adapter = adapt_stage_finding(
        bridge,
        finding_id=sample,
        unit_id=unit_id or f"{entry.repository.replace('_', '')}_{sample.lower()}",
        repo_root=resolved_repo_root,
    )
    result.adapter_status = adapter.status
    result.adapter_errors = list(adapter.errors)
    result.adapter_warnings = list(adapter.warnings)
    _write_run_snapshot(progress_path, "finding_adapter.json", adapter.to_dict())
    if adapter.status != "CONVERTED" or adapter.finding is None:
        result.status = "BLOCKED_ADAPTER"
        _persist_standard_artifacts(
            result, progress_path, phase="adapter",
            reason="Stage 1 finding 适配未通过，尚未进入设备协议编译。",
        )
        raise ScanBridgeError(
            f"适配未通过（{adapter.status}）：{'；'.join(adapter.errors) or '未知原因'}"
        )
    finding = adapter.finding
    result.vuln_class = finding.vuln_class
    result.sink = finding.sink
    result.entry_hints = list(finding.entry_hints)
    try:
        from openharmony_dynamic.baseline import baseline_item  # noqa: PLC0415

        _write_run_snapshot(
            progress_path,
            "dynamic_baseline.json",
            baseline_item(finding, clean_room=clean_room),
        )
    except Exception as exc:  # noqa: BLE001 — 审计快照失败不改变主流程
        _write_run_snapshot(progress_path, "dynamic_baseline.json", {
            "schema_version": "vf.dynamic.baseline.v1",
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        })

    emit = _progress_emitter(progress_path)
    cmd_emit = (lambda rec: emit({"event": "device_cmd", "detail": rec.get("purpose", ""),
                                  "record": rec})) if emit else None
    hdc = HDCClient(
        hdc_path=hdc_path or "hdc",
        serial=serial,
        ledger_path=Path(ledger_path) if ledger_path else None,
        on_command=cmd_emit,
    )
    # L0：先确认设备版本、端点和目标进程，再进入协议/PoC 编译。该阶段只读，
    # 不因为未知就伪造匹配，也不自动启动服务。
    result.device_fingerprint = _run_device_preflight(
        finding=finding, hdc=hdc, repo_root=resolved_repo_root,
        progress_path=progress_path, emit=emit,
        allow_service_start=allow_service_start,
    )
    health = result.device_fingerprint.get("service_health", {})
    if health.get("status") == "NOT_READY":
        result.compile_status = "SERVICE_UNAVAILABLE"
        result.status = "BLOCKED_SERVICE_UNAVAILABLE"
        message = "；".join(str(item) for item in health.get("missing", []) or []) or "目标服务未就绪"
        compile_snapshot = {
            "compile_status": result.compile_status,
            "errors": [f"L0 只读前置确认未通过：{message}"],
            "entry_discovery": {}, "descriptor_resolution": {},
            "protocol_evidence": {}, "contract": None,
            "blocked_before_protocol_compile": True,
        }
        _write_run_snapshot(progress_path, "compile_summary.json", compile_snapshot)
        if emit is not None:
            emit({"event": "service_unavailable", "detail": message,
                  "record": result.device_fingerprint})
        _persist_standard_artifacts(result, progress_path, phase="preflight", reason=message)
        raise ScanBridgeError(f"设备目标服务未就绪（SERVICE_UNAVAILABLE）：{message}")
    # P0-1 降级闭环重试：侦查降级 → fresh session 自动重跑一次；同一缺口签名
    # 独立失败超限 → 收敛 final-failure（failure_log 由进程级缓存跨 run 传递）。
    try:
        from openharmony_dynamic.contract_compiler import compile_contract_with_retry  # noqa: PLC0415

        compile_result = compile_contract_with_retry(
            finding, hdc=hdc, on_event=emit, clean_room=clean_room,
            failure_log=_COMPILE_FAILURE_LOG,
            # clean-room 评测必须证明本轮自动描述符链路；内置协议只能作为
            # assisted 模式的显式 library_fallback，不能悄悄进入评测契约。
            require_auto_descriptor=clean_room,
            max_attempts=_DYNAMIC_COMPILE_ATTEMPTS,
        )
    except ImportError:
        compile_result = compile_contract(finding, hdc=hdc, on_event=emit,
                                          clean_room=clean_room,
                                          require_auto_descriptor=clean_room)
    result.compile_status = compile_result.compile_status
    result.compile_errors = list(compile_result.errors)
    result.compile_notes = list(compile_result.notes)
    result.entry_discovery = dict(compile_result.entry_discovery)
    result.descriptor_resolution = dict(compile_result.descriptor_resolution)
    result.protocol_evidence = dict(compile_result.protocol_evidence)
    result.probe_result = dict(getattr(compile_result, "probe_result", {}) or {})
    _write_run_snapshot(progress_path, "entry_discovery.json", result.entry_discovery)
    _write_run_snapshot(progress_path, "protocol_evidence.json", result.protocol_evidence)
    _write_run_snapshot(progress_path, "probe_result.json", result.probe_result)
    _write_run_snapshot(progress_path, "compile_summary.json", compile_result.to_dict())
    _emit_compile_diagnostics(emit, compile_result)
    if compile_result.compile_status != "ELIGIBLE" or compile_result.contract is None:
        result.status = "BLOCKED_PROTOCOL"
        _persist_standard_artifacts(
            result, progress_path, phase="compile",
            reason=("契约编译未达到 ELIGIBLE；协议、设备自证或预言机条件尚未满足，"
                    "该状态不等同于漏洞不存在。"),
        )
        raise ScanBridgeError(
            f"编译未达 ELIGIBLE（{compile_result.compile_status}）："
            f"{'；'.join(compile_result.errors) or '未知原因'}"
        )

    contract = compile_result.contract
    result.contract = contract.to_dict()
    _write_run_snapshot(progress_path, "contract.json", result.contract)
    rec = Runner(hdc, on_event=emit).run(contract)
    result.run_id = rec.run_id
    result.pattern = rec.pattern
    verdict = rec.verdict if isinstance(rec.verdict, dict) else {}
    result.verdict = verdict
    result.status = str(verdict.get("status", ""))
    result.evidence_grade = str(verdict.get("evidence_grade", ""))
    _write_run_snapshot(progress_path, "verdict.json", {
        "run_id": result.run_id,
        "status": result.status,
        "evidence_grade": result.evidence_grade,
        "pattern": result.pattern,
        "verdict": result.verdict,
    })
    # CONFIRMED 契约自动晋升 exemplar（P0-2 全自动化收敛）：该 vuln_class 首个
    # 真机 CONFIRMED 契约沉淀为 L2 few-shot 参考；第一代钉死不可变。失败静默。
    if not clean_room:
        try:
            from openharmony_dynamic.contract_compiler import promote_exemplar_if_absent  # noqa: PLC0415

            promotion = promote_exemplar_if_absent(contract, result.status)
            if promotion != "skipped:非 CONFIRMED":
                result.compile_notes.append(f"exemplar 自动晋升: {promotion}")
        except Exception:  # noqa: BLE001 — 晋升是增强，绝不影响主流程
            pass
    else:
        result.compile_notes.append("clean-room: 跳过 CONFIRMED exemplar 自动晋升")
    # 回填 record（RunRecord 落盘 JSON）路径与内容：前端展示证据细节
    # （transport / 文件系统快照含 marker 内容与 stat / hilog 命中 / 命令计数）。
    # Runner._persist 写 <cwd>/test_records/ohos-dynamic-v2/runs/<run_id>-<contract_id>.json。
    runner_name = f"{rec.run_id}-{rec.contract_id}.json"
    runner_out = next(
        (c for c in (Path("test_records/ohos-dynamic-v2/runs") / runner_name,
                     Path.cwd() / "test_records/ohos-dynamic-v2/runs" / runner_name)
         if c.is_file()),
        None,
    )
    if runner_out is not None:
        result.record_path = str(runner_out)
        try:
            result.record = json.loads(runner_out.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result.record = {}
    if result.record:
        _write_run_snapshot(progress_path, "run_record.json", result.record)
    _maybe_build_deliverables(result, progress_path=progress_path, finding=finding,
                              hdc=hdc, progress_emit=emit)
    _persist_standard_artifacts(result, progress_path, phase="run",
                                reason="设备执行已返回 RunRecord。")
    return result


def run_dynamic_from_webui(
    scan_id: str,
    *,
    sample: str,
    serial: str,
    webui_dir: str | Path | None = None,
    hdc_path: str | None = None,
    repo_root: str | Path | None = None,
    ledger_path: str | Path | None = None,
    unit_id: str | None = None,
    progress_path: str | Path | None = None,
    clean_room: bool = False,
    allow_service_start: bool = False,
) -> ScanDynamicResult:
    """webui 扫描条目（~/.openant/webui/<scan_id>/results.json）→ 适配 →
    编译契约 → 真机执行。serial 必须显式给出（绝不隐式选择板卡）。"""
    bridge, entry = bridge_webui_entry(
        webui_dir, scan_id=scan_id, sample=sample, repo_root=repo_root,
    )

    # 惰性导入：与 run_dynamic_from_scan 相同的复用路径
    import sys as _sys

    core_dir = Path(__file__).resolve().parents[1]
    utilities_dir = core_dir / "utilities"
    for p in (str(core_dir), str(utilities_dir)):
        if p not in _sys.path:
            _sys.path.insert(0, p)

    from openharmony_dynamic.contract_compiler import compile_contract  # noqa: PLC0415
    from openharmony_dynamic.hdc_client import HDCClient  # noqa: PLC0415
    from openharmony_dynamic.runner import Runner  # noqa: PLC0415
    from openharmony_dynamic.stage_finding_adapter import adapt_stage_finding  # noqa: PLC0415

    result = ScanDynamicResult(entry=entry, bridge=bridge, clean_room=clean_room)
    _write_run_snapshot(progress_path, "bridge.json", {
        "entry": entry.to_dict(),
        "bridge": bridge,
        "source": "scan_artifact_bridge",
    })
    # bridge_webui_entry 将 entry.repository 设为扫描 meta.repo（实际存在目录）。
    # 条目 file 是相对该根的路径；若 file 不在该根下（老扫描 file 只有裸文件名，
    # 或 repo 是深层子目录而 file 带仓库内前缀），逐级向上扩展根直到
    # file 在 <root>/<file_rel> 真实存在——适配校验要求 source 相对 repo_root 存在。
    resolved_repo_root = str(entry.repository)
    file_rel = str(bridge["所处文件路径"])
    if file_rel and not (Path(resolved_repo_root) / file_rel).is_file():
        root = Path(resolved_repo_root)
        parts_to_prepend: list[str] = []
        while root.parent != root and len(root.parts) > 2:
            parts_to_prepend.insert(0, root.name)
            root = root.parent
            candidate_rel = "/".join([*parts_to_prepend, file_rel])
            if (root / candidate_rel).is_file():
                resolved_repo_root = str(root)
                bridge["所处文件路径"] = candidate_rel
                break
    adapter = adapt_stage_finding(
        bridge,
        finding_id=sample,
        unit_id=unit_id or f"{entry.target_id.replace('/', '_').replace(':', '_')}_{sample.lower()}",
        repo_root=resolved_repo_root,
    )
    result.adapter_status = adapter.status
    result.adapter_errors = list(adapter.errors)
    result.adapter_warnings = list(adapter.warnings)
    _write_run_snapshot(progress_path, "finding_adapter.json", adapter.to_dict())
    if adapter.status != "CONVERTED" or adapter.finding is None:
        result.status = "BLOCKED_ADAPTER"
        _persist_standard_artifacts(
            result, progress_path, phase="adapter",
            reason="Stage 1 finding 适配未通过，尚未进入设备协议编译。",
        )
        raise ScanBridgeError(
            f"适配未通过（{adapter.status}）：{'；'.join(adapter.errors) or '未知原因'}"
        )
    finding = adapter.finding
    result.vuln_class = finding.vuln_class
    result.sink = finding.sink
    result.entry_hints = list(finding.entry_hints)
    try:
        from openharmony_dynamic.baseline import baseline_item  # noqa: PLC0415

        _write_run_snapshot(
            progress_path,
            "dynamic_baseline.json",
            baseline_item(finding, clean_room=clean_room),
        )
    except Exception as exc:  # noqa: BLE001
        _write_run_snapshot(progress_path, "dynamic_baseline.json", {
            "schema_version": "vf.dynamic.baseline.v1",
            "status": "ERROR",
            "error": f"{type(exc).__name__}: {exc}",
        })

    emit = _progress_emitter(progress_path)
    cmd_emit = (lambda rec: emit({"event": "device_cmd", "detail": rec.get("purpose", ""),
                                  "record": rec})) if emit else None
    hdc = HDCClient(
        hdc_path=hdc_path or "hdc",
        serial=serial,
        ledger_path=Path(ledger_path) if ledger_path else None,
        on_command=cmd_emit,
    )
    # 与目录扫描入口保持同一 L0 前置确认语义，避免 Web 路径和 CLI 路径
    # 因为少了一次设备/版本检查而产生不同结论。
    result.device_fingerprint = _run_device_preflight(
        finding=finding, hdc=hdc, repo_root=resolved_repo_root,
        progress_path=progress_path, emit=emit,
        allow_service_start=allow_service_start,
    )
    health = result.device_fingerprint.get("service_health", {})
    if health.get("status") == "NOT_READY":
        result.compile_status = "SERVICE_UNAVAILABLE"
        result.status = "BLOCKED_SERVICE_UNAVAILABLE"
        message = "；".join(str(item) for item in health.get("missing", []) or []) or "目标服务未就绪"
        compile_snapshot = {
            "compile_status": result.compile_status,
            "errors": [f"L0 只读前置确认未通过：{message}"],
            "entry_discovery": {}, "descriptor_resolution": {},
            "protocol_evidence": {}, "contract": None,
            "blocked_before_protocol_compile": True,
        }
        _write_run_snapshot(progress_path, "compile_summary.json", compile_snapshot)
        if emit is not None:
            emit({"event": "service_unavailable", "detail": message,
                  "record": result.device_fingerprint})
        _persist_standard_artifacts(result, progress_path, phase="preflight", reason=message)
        raise ScanBridgeError(f"设备目标服务未就绪（SERVICE_UNAVAILABLE）：{message}")
    # P0-1 降级闭环重试：侦查降级 → fresh session 自动重跑一次；同一缺口签名
    # 独立失败超限 → 收敛 final-failure（failure_log 由进程级缓存跨 run 传递）。
    try:
        from openharmony_dynamic.contract_compiler import compile_contract_with_retry  # noqa: PLC0415

        compile_result = compile_contract_with_retry(
            finding, hdc=hdc, on_event=emit, clean_room=clean_room,
            failure_log=_COMPILE_FAILURE_LOG,
            require_auto_descriptor=clean_room,
            max_attempts=_DYNAMIC_COMPILE_ATTEMPTS,
        )
    except ImportError:
        compile_result = compile_contract(finding, hdc=hdc, on_event=emit,
                                          clean_room=clean_room,
                                          require_auto_descriptor=clean_room)
    result.compile_status = compile_result.compile_status
    result.compile_errors = list(compile_result.errors)
    result.compile_notes = list(compile_result.notes)
    result.entry_discovery = dict(compile_result.entry_discovery)
    result.descriptor_resolution = dict(compile_result.descriptor_resolution)
    result.protocol_evidence = dict(compile_result.protocol_evidence)
    result.probe_result = dict(getattr(compile_result, "probe_result", {}) or {})
    _write_run_snapshot(progress_path, "entry_discovery.json", result.entry_discovery)
    _write_run_snapshot(progress_path, "protocol_evidence.json", result.protocol_evidence)
    _write_run_snapshot(progress_path, "probe_result.json", result.probe_result)
    _write_run_snapshot(progress_path, "compile_summary.json", compile_result.to_dict())
    _emit_compile_diagnostics(emit, compile_result)
    if compile_result.compile_status != "ELIGIBLE" or compile_result.contract is None:
        result.status = "BLOCKED_PROTOCOL"
        _persist_standard_artifacts(
            result, progress_path, phase="compile",
            reason=("契约编译未达到 ELIGIBLE；协议、设备自证或预言机条件尚未满足，"
                    "该状态不等同于漏洞不存在。"),
        )
        raise ScanBridgeError(
            f"编译未达 ELIGIBLE（{compile_result.compile_status}）："
            f"{'；'.join(compile_result.errors) or '未知原因'}"
        )

    contract = compile_result.contract
    result.contract = contract.to_dict()
    _write_run_snapshot(progress_path, "contract.json", result.contract)
    rec = Runner(hdc, on_event=emit).run(contract)
    result.run_id = rec.run_id
    result.pattern = rec.pattern
    verdict = rec.verdict if isinstance(rec.verdict, dict) else {}
    result.verdict = verdict
    result.status = str(verdict.get("status", ""))
    result.evidence_grade = str(verdict.get("evidence_grade", ""))
    _write_run_snapshot(progress_path, "verdict.json", {
        "run_id": result.run_id,
        "status": result.status,
        "evidence_grade": result.evidence_grade,
        "pattern": result.pattern,
        "verdict": result.verdict,
    })
    # CONFIRMED 契约自动晋升 exemplar（P0-2 全自动化收敛）：该 vuln_class 首个
    # 真机 CONFIRMED 契约沉淀为 L2 few-shot 参考；第一代钉死不可变。失败静默。
    if not clean_room:
        try:
            from openharmony_dynamic.contract_compiler import promote_exemplar_if_absent  # noqa: PLC0415

            promotion = promote_exemplar_if_absent(contract, result.status)
            if promotion != "skipped:非 CONFIRMED":
                result.compile_notes.append(f"exemplar 自动晋升: {promotion}")
        except Exception:  # noqa: BLE001 — 晋升是增强，绝不影响主流程
            pass
    else:
        result.compile_notes.append("clean-room: 跳过 CONFIRMED exemplar 自动晋升")
    # 回填 record（RunRecord 落盘 JSON）路径与内容：前端展示证据细节
    # （transport / 文件系统快照含 marker 内容与 stat / hilog 命中 / 命令计数）。
    # Runner._persist 写 <cwd>/test_records/ohos-dynamic-v2/runs/<run_id>-<contract_id>.json。
    runner_name = f"{rec.run_id}-{rec.contract_id}.json"
    runner_out = next(
        (c for c in (Path("test_records/ohos-dynamic-v2/runs") / runner_name,
                     Path.cwd() / "test_records/ohos-dynamic-v2/runs" / runner_name)
         if c.is_file()),
        None,
    )
    if runner_out is not None:
        result.record_path = str(runner_out)
        try:
            result.record = json.loads(runner_out.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            result.record = {}
    if result.record:
        _write_run_snapshot(progress_path, "run_record.json", result.record)
    _maybe_build_deliverables(result, progress_path=progress_path, finding=finding,
                              hdc=hdc, progress_emit=emit)
    _persist_standard_artifacts(result, progress_path, phase="run",
                                reason="设备执行已返回 RunRecord。")
    return result
