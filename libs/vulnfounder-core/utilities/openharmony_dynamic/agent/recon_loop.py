"""侦查 agent loop（自动化方案 §9 / §11）：LLM ⇄ 确定性工具循环直到 finalize。

LLM 每轮输出一个 JSON 动作 {"tool": ..., "args": {...}}；确定性执行器执行并裁剪
输出回喂；LLM 用 write_note 固化已查明事实（事实卡），用 finalize 提交契约草案。
预算：max_recon_turns（默认 16）；预算耗尽 / LLM 不可用 / 输出非法 → 诚实停。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .device_facts import DeviceFacts
from .recon_tools import ReconTools

if TYPE_CHECKING:
    from ...utilities.llm.registry import PhaseBinding  # noqa: F401

# 清洁上下文不携带历史契约形状，侦查需要额外轮次读取入口、分帧、字段解析
# 和 sink 之间的当前源码证据。增加预算不改变准入规则，只避免模型在完成
# 变异帧核对前被 endgame 截断。
_MAX_TURNS_DEFAULT = 16
_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)

_RECON_SYSTEM_PROMPT = (
    "你是 OpenHarmony 真机动态测试的侦查器。你的任务：在起草契约之前，自主查证"
    "所有需要设备侧/源码侧事实的疑点，然后把查证结论固化为 notes，最后提交契约草案。\n"
    "每轮输出一个 JSON 动作（不要输出其他文字；若输出多个 JSON 只执行最后一个）：\n"
    '  {"tool": "read_file", "args": {"path": "plugins/freeze_detector/freeze_manager.cpp", "offset": 0, "limit": 200}}\n'
    '  {"tool": "grep", "args": {"pattern": "HIVIEW_LOGE", "path": "plugins/freeze_detector"}}\n'
    '  {"tool": "list_dir", "args": {"path": "services"}}\n'
    '  {"tool": "hilog_grep", "args": {"tag": "FreezeDetector", "pattern": "create freezeExt"}}\n'
    '  {"tool": "hdc_shell", "args": {"argv": ["cat", "/system/etc/hiview/freeze_rules.xml"]}}   # 只读白名单\n'
    '  {"tool": "write_note", "args": {"text": "实测：hilog tag 为 C02d01/FreezeDetector（hilog_grep 证据）"}}\n'
    '  {"tool": "read_notes", "args": {}}\n'
    '  {"tool": "finalize", "args": {"draft": {...契约草案 JSON...}, "facts": {"hilog_tag": "..."}}}\n'
    "finalize 的 draft 是契约草案（protocol.field_values / protocol.param_space /"
    " oracle.artifact_forms / oracle.hilog_expectations / fault），facts 是事实卡"
    "（你声称的设备侧实测结论，键值对，会被抽样复核——编造会被打回）。\n"
    "纪律（硬性）：\n"
    "1. 工具返回以「[turn N] …已执行」标注——出现即表示该动作已完成，不要重复同一动作；"
    "重复已执行的动作会浪费预算且不推进侦查。\n"
    "2. 每轮必须推进侦查：要么获取新信息，要么固化 note，要么 finalize。"
    "发现的事实立即 write_note（防上下文滚动丢失）。\n"
    "3. 收敛压力：轮次预算有限，endgame 提示出现后必须尽快 finalize——"
    "把已确认的事实写进草案，未确认的标注推测即可，不允许因完美主义耗尽预算。\n"
    "4. 路径不写死（用 __STACK_FILE__ 等占位符）；不要猜设备事实——去测；"
    "测不了就在 facts 里标注推测。\n"
    "5. field_values / param_space 的每个值必须是**最终发送用的字面量**"
    "（真实字符串/数字），或 runner 支持的占位符——**仅限**："
    "__SRC_FILE__ __STACK_FILE__ __CPU_FILE__ __MARKER__ __MARKER_PATH__ "
    "__RUN_PATTERN__ __RUN_DIR__。禁止发明 __UID__/__PID__/__PACKAGE_NAME__ 等"
    "其他占位符（runner 不支持，校验直接打回）；运行期才知道的值"
    "（PID/包名）用合理字面量（如 PID=1234、包名 com.example.victim），"
    "UID 按源码守卫要求填真实值。"
    "禁止填「推测：…」「需按设备填写」等描述性文字——那不是可执行值，校验会打回。"
    "domain/stringid 这类注册值必须从源码或设备规则文件（如 /system/etc/hiview/ 下规则）"
    "查证出真实值；查不到就输出 {\"tool\": \"finalize\", \"args\": {\"draft\":"
    " {\"insufficient\": \"缺 xxx 真实值\"}}}，不要编。\n"
    "6. 攻击链完整性（finalize 前自查）：从事件字段到 sink 的每一跳都要在源码里核对，"
    "每跳的**守卫条件**（uid 阈值/字段格式/路径限制/拆分规则）write_note 固化，"
    "并把满足守卫所需的具体值填进 field_values。"
    "常见漏项：常量阈值（在源码 constexpr 里）、字段拆分/格式要求（split/正则）、"
    "下游函数对字段值的再校验。只填了入口字段而漏了守卫值 = 链路走不通。\n"
    "6b. 变异载荷与合法探测必须分开：legal_probe 只证明协议能被服务接收，不能作为"
    "漏洞载荷。对于 hap_udp/hap_tcp/unix_dgram/unix_stream 入口，若当前 vuln_class"
    "需要验证输入影响（例如 command_injection、arbitrary_file_write、path_traversal、"
    "permission_bypass、parcel_check_missing），finalize 必须同时提交真实的发送槽位："
    "protocol.frame_sequence 加上 field_values/param_space 中的 frame_first_template、"
    "frame_second、frame_third 或其它源码明确要求的帧值；这些值必须从当前 finding 的"
    "candidate_attack_chains 和本轮 read_file/grep 证据推导，不能只提交 legal_probe、"
    "command 列表或空 frame_sequence。多请求状态链必须按源码顺序列出每一帧。若穷尽"
    "当前源码证据仍无法确定变异帧，才提交 insufficient，并说明缺失的调用点/字段；"
    "frame_sequence 中的 frame_first/frame_second 等是槽位名，不是数组下标；禁止填 0、1、"
    "true 或其它数字索引作为帧值。每个槽位必须在 field_values 或 param_space 中有真实可发送"
    "的字符串（可包含允许的运行期占位符）。如果源码显示必须先设置状态再发送触发命令，"
    "必须把设置帧和触发帧都列出，不能只提交第一个状态帧。"
    "不要先把一个使用常量参数的安全 callsite 当成整个 finding 的结论。\n"
    "6b.1. frame_sequence 的结构示例（仅示范结构，不是任何服务答案）："
    "protocol.frame_sequence=[\"frame_first\",\"frame_second\"]；"
    "protocol.param_space.frame_first_template=\"<源码证据支持的第一条完整线路帧>\"；"
    "protocol.param_space.frame_second=\"<源码证据支持的第二条完整线路帧>\"。"
    "不要把 descriptor.legal_probe 中的 first/second 字段名、\"first\"、\"second\" 或"
    "\"frame_first\" 本身当作要发送的内容，也不要把合法探测和实际变异帧混在同一序列中。\n"
    "6c. 候选攻击链逐条核对：finding 中已有的候选链是检索优先级，不是答案。先读取"
    "链上的入口处理、分派和 sink 函数，区分“外部输入流入参数”的 callsite 与仅使用"
    "常量/内部状态的 callsite；前者需要恢复对应协议帧，后者只能作为已验证的非可控"
    "对照，不能据此 finalize 一个空载荷契约。\n"
    "6d. 如果当前源码已经出现外部字段的分帧前缀、分隔符、字段拆分或状态赋值（例如"
    "接收函数把 prefix + payload 拆分后写入下游状态），这些是构造候选变异帧的有效依据："
    "将源码中真实前缀/分隔符与运行期占位符组合成最终线路字符串，并在 frame_sequence 中"
    "按源码要求的顺序提交；不要因为有效图把分派标成 candidate 就退回只有 legal_probe 的"
    "契约。候选帧仍须在 notes 中记录源码依据，设备未复现时由 oracle 诚实判定"
    "NOT_REPRODUCED。prefix、字段名、帧数量和顺序必须来自本轮当前源码证据，系统不提供"
    "任何服务专用命令。\n"
    "6d.2. token/凭据守卫必须按当前命令分支判断：先读取 Check*Token 的完整分支，"
    "确认 isNeedToken 的默认值以及 set_pkgName/get_version 等命令是否有前缀特判。"
    "如果当前变异链使用的命令被源码明确特判放行，不能仅因为同一接收函数存在通用 token 校验"
    "就申报‘缺少 token’；应提交不带 token 的源码支持帧，并把‘运行时 token 开关未知’作为"
    "事实卡或 oracle 限制交给设备验证。只有当所选命令在所有可行分支上都无条件要求一个"
    "当前源码和设备均无法获得的 token，才允许 finalize insufficient。\n"
    "6d.1. 状态生命周期自检：如果源码显示某条消息会启动 worker/producer、置位"
    "运行标志，另一条消息会清除该标志、停止 worker/producer 或重置共享状态，"
    "不要在触发消息之前发送后者；否则可能在 sink 执行前把链路关闭。最终序列只"
    "保留从入口到 sink 所需的最短顺序（设置状态 → 启动/触发 → 等待观察），"
    "除非源码明确要求，否则不要追加 stop/reset/cleanup 类控制帧。这个判断必须"
    "来自本轮源码中的状态写入、线程启动和分派证据，不得依赖历史 exemplar 或"
    "设备事实库。\n"
    "6e. 若 oracle.artifact_forms 的 create/exfil 设置 content_contains=__RUN_PATTERN__，"
    "则至少一个实际发送帧必须把 __RUN_PATTERN__ 写入由 __MARKER_PATH__/__MARKER__ 指定的"
    "产物（例如源码支持的 echo/printf/tee 重定向）；仅 touch 空文件、仅写固定字符串、"
    "或只在 oracle 中声明 pattern 而未放入线路帧，均不能通过编译校验。不要为了绕过该"
    "约束修改 oracle，应让帧载荷和预言机的可观测内容一致。\n"
    "7. 发送方凭据不需要查证：描述符的 on_send_transforms（如"
    " patch_event_credentials）会在**发送时自动回填** SCM_CREDENTIALS 真实"
    " uid/pid——field_values 里的 UID/PID 字段填合理字面量占位即可，这不是"
    " insufficient 的理由。同样，参考契约里已有的 domain/stringid 组合"
    "（如 GRAPHIC/NO_DRAW）是描述符族已验证的合法注册值，可直接沿用。\n"
    "8. insufficient 的正确使用边界：只有在**源码查证**后确认关键链路字段"
    "（守卫阈值/字段格式/触发条件）在源码与设备上都查不到时才申报；"
    "『发送时自动回填』『参考契约已有合法值』『描述符已声明的缺省端点』"
    "都不构成 insufficient。完美主义申报不足 = 整场测试白跑。"
)


@dataclass
class ReconResult:
    """侦查 loop 结果：finalized 草案 + 事实卡 + 全量审计。"""

    status: str = ""                 # finalized / budget_exhausted / llm_unavailable / invalid_output / tool_error
    draft: dict[str, Any] | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    turns_used: int = 0
    device_commands_used: int = 0
    duplicate_actions: int = 0
    error: str = ""
    audit: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "draft": self.draft,
            "facts": dict(self.facts),
            "notes": list(self.notes),
            "turns_used": self.turns_used,
            "device_commands_used": self.device_commands_used,
            "duplicate_actions": self.duplicate_actions,
            "error": self.error,
            "audit": list(self.audit),
        }


def _llm_binding():
    """LLM 绑定（与 refine_loop / contract_compiler 相同复用路径）。"""
    try:
        import sys

        root = Path(__file__).resolve().parents[4]
        core = str(root / "libs" / "vulnfounder-core")
        if core not in sys.path:
            sys.path.insert(0, core)
        from utilities.llm.helpers import simple_text  # noqa: PLC0415
        from utilities.llm.registry import (  # noqa: PLC0415
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
        )

        cf = load_config_file()
        lc = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, lc)
        return registry.get("dynamic_test"), simple_text
    except Exception:  # noqa: BLE001
        return None


def _balanced_json_objects(text: str) -> list[str]:
    """平衡大括号扫描提取候选 JSON 对象块（处理字符串内的引号/转义/换行）。

    gpt-5.x 有时把两个动作 JSON 连发（中间仅一个换行），贪婪正则
    ``\\{.*\\}`` 会跨块匹配导致 json.loads 必然失败、全部丢弃。
    逐字符扫描配对深度，把每个顶层 ``{...}`` 块切出来。
    """
    blocks: list[str] = []
    depth = 0
    start = -1
    in_str = False
    esc = False
    tail_open = -1  # 未闭合块的起点（输出被 max_tokens 截断时抢救用）
    tail_depth = 0
    tail_in_str = False
    tail_esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
                tail_open = i
                tail_depth = 0
                tail_in_str = False
                tail_esc = False
            depth += 1
            tail_depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                tail_depth -= 1
                if depth == 0 and start >= 0:
                    blocks.append(text[start:i + 1])
                    start = -1
    # 截断抢救：末尾有未闭合块且不在字符串中间——补齐缺失的右括号再解析。
    # （实测 gpt-5.6-luna finalize 长草案 + 推理消耗吃满 max_tokens → JSON 被腰斩，
    # 若直接丢弃，endgame 两轮全 invalid → budget_exhausted 整场白跑。）
    if start >= 0 and not tail_in_str and tail_depth > 0:
        candidate = text[tail_open:] + ("]" if tail_depth == 1 and depth == 0 else "") + "}" * tail_depth
        blocks.append(candidate)
    return blocks


def _parse_action(text: str) -> dict[str, Any] | None:
    """LLM 回复 → {"tool", "args"}；非法输出返回 None。

    模型有时一次输出多个 JSON 动作（实测同轮重复 2~3 次同一动作）：取**最后一个**
    （模型把最终意图放在输出末尾），避免被开头的说明性/过时 JSON 带偏。
    """
    last: dict[str, Any] | None = None
    for block in _balanced_json_objects(text.strip()):
        try:
            action = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(action, dict) and isinstance(action.get("tool"), str):
            last = action
    if last is None:
        return None
    args = last.get("args")
    if not isinstance(args, dict):
        args = {}
    return {"tool": last["tool"], "args": args}


def _route_file_and_function(node: Any) -> tuple[str, str]:
    """从候选攻击链节点提取规范相对路径和函数限定名。"""
    value = str(node or "").strip()
    if ":" not in value:
        return value, ""
    path, symbol = value.split(":", 1)
    return path.strip(), symbol.strip()


def _current_source_evidence(finding: Any, repo_root: Path, *, max_chars: int = 36000) -> list[dict[str, Any]]:
    """构造只来源于当前源码快照的路由证据摘录。

    Stage 1 通常只保留目标函数行号和候选链符号名，侦查器如果完全依赖随机
    ``read_file`` 动作，容易在预算耗尽前漏看共享状态写入点。本函数不推断
    调用关系，也不读取历史 exemplar/设备事实；它只按 finding 已给出的路径、
    行号和候选链函数，从当前仓库截取源码，并补充同目录对这些已见符号的引用。
    这些摘录作为模型的当前源码证据，仍须由侦查器逐条核对后才能写入契约。
    """
    roots: list[Path] = []
    symbols: list[str] = []
    ranges: list[tuple[Path, int, int]] = []
    raw_paths = list(getattr(finding, "source_paths", []) or [])
    chains = list(getattr(finding, "candidate_attack_chains", []) or [])
    for chain in chains:
        for node in chain:
            path_text, symbol = _route_file_and_function(node)
            if path_text:
                raw_paths.append(path_text)
            if symbol:
                symbols.append(symbol)
    for raw in raw_paths:
        text = str(raw).strip()
        if not text:
            continue
        # 证据有时带行号（file.cpp:140-143），文件路径只取前缀。
        path_text = re.sub(r":\d+(?:-\d+)?$", "", text)
        path = (repo_root / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text)
        if path.exists() and path.is_file() and path not in roots:
            roots.append(path)
    for item in list(getattr(finding, "evidence_lines", []) or []):
        try:
            start, end = int(item[0]), int(item[1])
        except (TypeError, ValueError, IndexError):
            continue
        for raw in getattr(finding, "source_paths", []) or []:
            path = (repo_root / str(raw)).resolve()
            if path.exists() and path.is_file():
                ranges.append((path, max(1, start - 24), end + 24))

    # 仅在候选链声明的源码文件及其同目录源码中检索，不做全仓库扫描。
    sibling_files: list[Path] = []
    for root in roots:
        parent = root.parent
        try:
            for path in sorted(parent.iterdir()):
                if path.suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"} and path.is_file():
                    if path not in sibling_files:
                        sibling_files.append(path)
        except OSError:
            continue

    excerpts: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    char_count = 0
    base_budget = max(10000, int(max_chars * 0.60))

    def add_excerpt(path: Path, start: int, end: int, reason: str, *, budget: int = max_chars) -> None:
        nonlocal char_count
        if char_count >= budget or not path.exists():
            return
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        lo, hi = max(1, int(start)), min(len(lines), int(end))
        key = (str(path), lo, hi)
        if key in seen or lo > hi:
            return
        body = "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(lo, hi + 1))
        remaining = min(max_chars - char_count, budget - char_count)
        if len(body) > remaining:
            body = body[:remaining] + "\n/* excerpt truncated */"
        excerpts.append({"path": str(path), "line_range": f"{lo}-{hi}", "reason": reason, "text": body})
        seen.add(key)
        char_count += len(body)

    # 目标 evidence_lines 优先，确保 sink 的精确实现先进入上下文。
    for path, start, end in ranges:
        add_excerpt(path, start, end, "target_evidence", budget=base_budget)

    # 再按候选链中的函数名抓取定义附近的源码。只使用函数短名查找，不把
    # 同名函数直接当成确定调用目标；模型仍须核对限定名与类型。
    short_symbols = []
    for symbol in symbols:
        short = symbol.rsplit("::", 1)[-1].strip()
        short = re.sub(r"<.*>$", "", short)
        if short and short not in short_symbols:
            short_symbols.append(short)
    for path in roots:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for short in short_symbols:
            pattern = re.compile(r"\b" + re.escape(short) + r"\s*\(")
            matches: list[int] = []
            for idx, line in enumerate(lines):
                if not pattern.search(line):
                    continue
                # 优先选择定义而不是调用：定义行本身或后两行通常带 `{`；
                # 若源码风格把 `{` 放得更远，退回第一个匹配供模型核对。
                window = " ".join(lines[idx:min(len(lines), idx + 3)])
                if "{" in window:
                    matches = [idx]
                    break
                matches.append(idx)
            if matches:
                idx = matches[0]
                add_excerpt(path, idx + 1 - 16, idx + 1 + 45,
                            f"candidate_function:{short}", budget=base_budget)

    # 从已截取的源码中提取限定名，再到候选文件同目录查找引用。此步骤专门
    # 补共享全局状态写入/读取（例如 Namespace::field），不把引用自动升级
    # 为调用边。
    qualified: list[str] = []
    for excerpt in excerpts:
        for match in re.findall(r"\b[A-Za-z_]\w*::[A-Za-z_]\w*", excerpt["text"]):
            # 标准库类型会在几乎每个文件的 include/签名中出现；跳过它们，
            # 把有限的引用预算留给业务状态与跨函数对象。
            if match.split("::", 1)[0] in {"std", "stdext", "__gnu_cxx", "OHOS"}:
                continue
            if match not in qualified:
                qualified.append(match)
    # 先补字段/状态名，再补方法名；共享字段通常是跨消息请求把入口值带到
    # sink 的关键证据，而方法引用数量很多且容易耗尽摘录预算。
    qualified.sort(key=lambda item: (item.rsplit("::", 1)[-1][:1].isupper(), len(item)))
    for qualified_name in qualified[:24]:
        token = qualified_name.rsplit("::", 1)[-1]
        if len(token) < 3:
            continue
        pattern = re.compile(r"\b" + re.escape(token) + r"\b")
        for path in sibling_files:
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for idx, line in enumerate(lines):
                if pattern.search(line):
                    add_excerpt(path, idx + 1 - 10, idx + 1 + 16,
                                f"symbol_reference:{qualified_name}", budget=max_chars)
                    break
            if char_count >= max_chars:
                break
        if char_count >= max_chars:
            break
    return excerpts


def _current_route_observations(
    finding: Any, excerpts: list[dict[str, Any]], *, max_items: int = 80,
) -> list[dict[str, str]]:
    """从当前源码摘录构建待模型核对的编号行索引。

    这里只做结构化的行号解析，不根据函数名、危险 API、服务名、协议字段或
    关键词加权/过滤。以前的实现把某个历史样本的词表放进 ``_score``，导致
    其它仓库的源码观察被错误重排。语义筛选和调用关系判断交给 recon LLM；
    这个列表只是从本次 finding 的源码摘录中截取的可审计行索引，不是调用图
    或污点分析结果。
    """
    # 保留参数以兼容现有调用方；finding 本身只在上游生成源码摘录时使用。
    del finding
    observations: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for excerpt in excerpts:
        path = str(excerpt.get("path", ""))
        excerpt_reason = str(excerpt.get("reason", ""))
        for line in str(excerpt.get("text", "")).splitlines():
            if ":" not in line:
                continue
            line_no, _, code = line.partition(":")
            if not line_no.strip().isdigit():
                continue
            code_text = code.strip()
            if not code_text:
                continue
            key = (path, line_no.strip(), code_text)
            if key in seen:
                continue
            seen.add(key)
            observations.append({
                "path": path,
                "line": line_no.strip(),
                "code": code_text,
                "excerpt_reason": excerpt_reason,
                "why": "source-excerpt-line;需模型核对，不是已确认边",
            })
    # 不再按 sink 名称、函数名、协议字段或危险 API 词表打分。此前的
    # ``_score`` 会把某个历史样本的关键词变成全局偏置：即使当前 finding
    # 是另一种语言/协议，也会被错误地把带有这些词的源码行提到前面。
    # 这里保留摘录器产生的稳定顺序：目标证据、候选函数、同目录引用，最后
    # 才是通用语法观察。真正的语义选择交给 recon LLM，并要求它回读完整摘录
    # 逐行核验；这个列表只是有限上下文内的可审计索引，不是规则判定器。
    return observations[:max_items]


def run_recon_loop(
    *,
    finding: Any,
    skeleton: dict[str, Any],
    descriptor_dict: dict[str, Any],
    repo_root: Path,
    hdc=None,
    binding_pair=None,
    device_facts: DeviceFacts | None = None,
    max_turns: int = _MAX_TURNS_DEFAULT,
    oracle_forms: list[dict[str, Any]] | None = None,
    exemplar_contract: dict[str, Any] | None = None,
    on_event=None,
) -> ReconResult:
    """侦查主循环。binding_pair 可注入（测试用 mock LLM）；缺省走真实注册表。

    exemplar_contract：同族手写固件契约（如 HV-05），作为**攻击链形状**的 few-shot
    参考——展示完整链路长什么样（双路径拆分/预埋/守卫值），不是语义答案：
    LLM 仍须自己查证本 finding 的具体值。
    on_event：可选进度回调（前端实时展示），每轮事件
    {"event": "recon_turn", "detail": str, "record": {turn, tool, args 摘要, 结果摘要}}。
    回调异常静默忽略——进度展示绝不影响侦查本体。
    """
    tools = ReconTools(hdc=hdc, repo_root=repo_root)
    if binding_pair is None:
        binding_pair = _llm_binding()
    if binding_pair is None:
        return ReconResult(status="llm_unavailable", notes=list(tools.notes),
                           audit=[a.to_dict() for a in tools.audit],
                           device_commands_used=tools.device_commands_used)
    binding, simple_text = binding_pair

    # 侦查上下文：finding + 确定性骨架 + 描述符 + 已知事实库 + forms 骨架
    current_evidence = _current_source_evidence(finding, repo_root)
    route_observations = _current_route_observations(finding, current_evidence)
    evidence_index = [
        {
            "path": item.get("path", ""),
            "line_range": item.get("line_range", ""),
            "reason": item.get("reason", ""),
        }
        for item in current_evidence
    ]
    context_parts = [
        "finding:", json.dumps(finding.to_dict(), ensure_ascii=False, indent=2),
        "",
        "当前源码路由观察（先读这一节建立待核对的源码行索引；这里不使用服务/漏洞"
        "关键词打分，也不自动判断接收、解析、状态或危险操作。这些行只是索引，绝不等同于已确认调用边。finalize 前必须回到下面的"
        "完整摘录逐行核对。若变异帧没有对应的输入/状态观察，不得将其作为当前"
        "finding 的攻击帧）:",
        json.dumps(route_observations, ensure_ascii=False, indent=2),
        "",
        "当前源码证据摘录（仅来自本次 finding 指定的源码快照；这些摘录不是已确认的调用边，"
        "必须逐条核对后才能写入契约）:",
        json.dumps(current_evidence, ensure_ascii=False, indent=2),
        "当前源码证据索引（先按此索引定位需要复核的函数/共享状态，再决定 finalize；"
        "禁止因候选链标记 possible 就跳过状态写入点）:",
        json.dumps(evidence_index, ensure_ascii=False, indent=2),
        "命中的协议描述符（field_values 只允许这些字段名）:",
        json.dumps(descriptor_dict, ensure_ascii=False, indent=2),
        "",
        "确定性骨架（已填充，禁止改动）:",
        json.dumps(skeleton, ensure_ascii=False, indent=2),
        "",
    ]
    if oracle_forms:
        context_parts.append("vuln_class → oracle forms 骨架（按此实例化路径/内容载体）:")
        context_parts.append(json.dumps(oracle_forms, ensure_ascii=False, indent=2))
        context_parts.append("")
    if exemplar_contract:
        context_parts.append("同 vuln_class 的参考契约（**攻击链结构要完整沿用**：字段怎么组织、"
                             "多路径组合（如逗号分隔双路径）、param_space 的 src_file_dir/preplant/"
                             "effect_window、info_ 的 logPath: 前缀这类格式要求、预埋目录为何必须是"
                             "目标进程可读目录——这些是在真机上验证过的形状，丢掉任何一项 = 链路走不通"
                             "（例如把预埋放 /data/local/tmp 会因 SELinux 阻读而失效）。"
                             "仅具体值（路径随机段/PID/包名）须用占位符与本轮字面量替换：")
        context_parts.append(json.dumps(exemplar_contract, ensure_ascii=False, indent=2))
        context_parts.append("")
    if device_facts is not None and device_facts.keys():
        context_parts.append("设备事实库（此前侦查沉淀；volatile 项需重新验证）:")
        context_parts.extend(device_facts.to_prompt_lines())
        context_parts.append("")
    # compile_contract_with_retry 会把上一场的确定性拒绝原因写回 finding。
    # fresh session 必须能看到这份反馈，否则“重试”只是重复同一个错误草案，
    # 无法修复缺少 oracle、空帧或非法前置路径等结构问题。
    previous_feedback = (getattr(finding, "analysis_context", {}) or {}).get(
        "dynamic_compile_feedback", []
    )
    if previous_feedback:
        context_parts.append("上一场动态契约编译的确定性失败反馈（只用于修正草案，不是源码事实）:")
        context_parts.append(json.dumps(list(previous_feedback)[-3:], ensure_ascii=False, indent=2))
        context_parts.append(
            "请逐项修正上述缺口；修正前重新读取相关源码或设备事实，不能仅复制上一场草案。"
        )
        context_parts.append("")

    result = ReconResult()

    def _emit_turn(turn: int, kind: str, tool: str, args: Any, out: Any = None,
                   note: str = "") -> None:
        """单轮进度事件（recon_turn）：给前端实时展示侦查推进。静默容错。"""
        if on_event is None:
            return
        record: dict[str, Any] = {"turn": turn, "max_turns": max_turns, "kind": kind}
        if tool:
            record["tool"] = tool
        if isinstance(args, dict) and args:
            record["args"] = {k: (str(v)[:120] if not isinstance(v, (int, float, bool)) else v)
                              for k, v in list(args.items())[:4]}
        if isinstance(out, dict):
            record["ok"] = bool(out.get("ok", True))
            output = str(out.get("output", out.get("error", "")))[:300]
            if output:
                record["output"] = output
        if note:
            record["note"] = note[:200]
        try:
            on_event({"event": "recon_turn", "detail": _turn_brief(turn, kind, tool, args, out, note),
                      "record": record})
        except Exception:  # noqa: BLE001 — 进度展示绝不影响侦查本体
            pass

    def _turn_brief(turn: int, kind: str, tool: str, args: Any, out: Any, note: str) -> str:
        if kind == "start":
            return f"侦查第 {turn} 轮开始"
        if kind == "tool":
            arg_brief = ""
            if isinstance(args, dict) and args:
                first = next(iter(args.values()))
                arg_brief = " " + str(first)[:80]
            ok = ""
            if isinstance(out, dict):
                ok = " ✓" if out.get("ok", True) else " ✗ " + str(out.get("error", ""))[:60]
            return f"侦查第 {turn} 轮：{tool}{arg_brief}{ok}"
        if kind == "note":
            return f"侦查第 {turn} 轮：固化事实 — {note[:100]}"
        if kind == "finalize":
            return f"侦查第 {turn} 轮：finalize 提交契约草案"
        if kind == "invalid":
            return f"侦查第 {turn} 轮：LLM 输出非法（{note[:120]}）"
        return f"侦查第 {turn} 轮：{kind}"

    transcript: list[str] = [""]
    # 入口发现 loop 已经会拒绝相同的 tool+args；协议侦查 loop 也必须保持
    # 同一语义，否则模型在源码窗口/grep 结果上来回读取，会消耗有限轮次而
    # 不增加事实。参数完整序列化后去重，不按函数名或服务名猜测“相似动作”。
    action_keys: set[str] = set()
    for turn in range(1, max_turns + 1):
        result.turns_used = turn
        # L1 压缩：上下文 = 静态部分 + 最近 6 轮工具输出 + 全部 notes（§11.1）
        prompt_parts = list(context_parts)
        prompt_parts.append(f"已固化 notes（{len(tools.notes)} 条，事实以此为准）:")
        prompt_parts.extend(f"[{i}] {n}" for i, n in enumerate(tools.notes, 1))
        prompt_parts.append("")
        prompt_parts.append(f"侦查轮次 {turn}/{max_turns}。以下是已执行的动作与真实返回（"
                            "「[turn N]」条目 = 该动作已完成，结果就在 → 后面）：")
        prompt_parts.extend(transcript[-6:])
        prompt_parts.append("")
        if turn >= max_turns - 3:
            prompt_parts.append(f"⚠ endgame：剩余 {max_turns - turn} 轮。"
                                "若关键事实已够，立即 finalize（用当前已确认事实起草，"
                                "未确认项标注推测）；不要再开新的宽泛侦查。")
        prompt_parts.append("下一个动作（JSON，只输出一个）：")
        # LLM 基础设施抖动容忍：连续 2 轮异常才放弃（单轮 5xx/限流/网关抖动
        # 直接放弃 = 整场侦查白跑；content-filter 型 400 换轮重问也常自愈）。
        llm_errors: list[str] = []
        while True:
            try:
                text = simple_text(binding, "\n".join(prompt_parts),
                                   system=_RECON_SYSTEM_PROMPT, max_tokens=16000)
                llm_errors = []
                break
            except Exception as exc:  # noqa: BLE001 — LLM 基础设施抖动
                llm_errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")
                if len(llm_errors) >= 2:
                    return _finish(result, tools, "llm_unavailable", llm_errors[-1])
                transcript.append(f"[turn {turn}] (LLM 调用异常，重试 {len(llm_errors)}/2): "
                                  f"{llm_errors[-1][:200]}")
                _emit_turn(turn, "invalid", "llm_error", None,
                           note=f"LLM 调用异常重试 {len(llm_errors)}/2")

        action = _parse_action(text)
        if action is None:
            transcript.append(f"[turn {turn}] (LLM 输出非法，已忽略): {text[:200]}")
            _emit_turn(turn, "invalid", "", None,
                       note=text.strip()[:160])
            continue
        tool, args = action["tool"], action["args"]
        action_key = json.dumps([tool, args], ensure_ascii=False, sort_keys=True)
        if tool != "finalize" and action_key in action_keys:
            result.duplicate_actions += 1
            transcript.append(
                f"[turn {turn}] 重复动作已执行：{tool}；请改查新证据、固化 note 或 finalize"
            )
            _emit_turn(
                turn, "duplicate", tool, args,
                note="该 tool+args 已在本 session 执行过，动作被抑制",
            )
            continue
        action_keys.add(action_key)
        if tool == "finalize":
            # 【闸门】申报 insufficient（声称"某字段/标识符不可控，无法构造契约"）前，
            # 必须先对涉事标识符做过全仓 grep——否则假否定会循环固化（82fe/979a 实测：
            # 盯着 SET_DUBAI_DB 常量路径申报不足，却漏掉 Network.cpp:153 的真正 sink）。
            # 未 grep 过就申报：动作被拒，注入整改提示让模型先去 grep。
            draft = args.get("draft")
            if isinstance(draft, dict) and "insufficient" in draft:
                if not tools.grep_history:
                    transcript.append(
                        f"[turn {turn}] finalize 申报 insufficient 被拒：本 session 尚未执行过任何"
                        "全仓 grep。申报「字段不可控/证据不足」前必须先 grep 涉事标识符列出全部"
                        "消费者（一次 grep 已执行即可再 finalize）。"
                    )
                    _emit_turn(turn, "note", "gate:insufficient", args,
                               note="申报不足被拒：需先执行全仓 grep")
                    continue
            _emit_turn(turn, "finalize", tool, args)
            draft = args.get("draft")
            if not isinstance(draft, dict):
                transcript.append(f"[turn {turn}] finalize 缺 draft（JSON 对象），动作被拒")
                continue
            facts = args.get("facts")
            result.draft = draft
            result.facts = facts if isinstance(facts, dict) else {}
            return _finish(result, tools, "finalized", "")
        out = tools.call(tool, args)
        if tool == "write_note" and isinstance(out, dict) and out.get("ok"):
            _emit_turn(turn, "note", tool, args, out, note=str(args.get("text", "")))
        else:
            _emit_turn(turn, "tool", tool, args, out)
        transcript.append(f"[turn {turn}] {tool} {json.dumps(args, ensure_ascii=False)[:300]}\n→ "
                          f"{json.dumps(out, ensure_ascii=False)[:2000]}")
    return _finish(result, tools, "budget_exhausted",
                   f"{max_turns} 轮未 finalize")


def _finish(result: ReconResult, tools: ReconTools, status: str, error: str) -> ReconResult:
    result.status = status
    result.error = error
    result.notes = list(tools.notes)
    result.device_commands_used = tools.device_commands_used
    result.audit = [a.to_dict() for a in tools.audit]
    return result
