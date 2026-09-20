"""侦查 agent loop（自动化方案 §9 / §11）：LLM ⇄ 确定性工具循环直到 finalize。

LLM 每轮输出一个 JSON 动作 {"tool": ..., "args": {...}}；确定性执行器执行并裁剪
输出回喂；LLM 用 write_note 固化已查明事实（事实卡），用 finalize 提交契约草案。
预算：max_recon_turns（默认 12）；预算耗尽 / LLM 不可用 / 输出非法 → 诚实停。
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

_MAX_TURNS_DEFAULT = 12
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
    context_parts = [
        "finding:", json.dumps(finding.to_dict(), ensure_ascii=False, indent=2),
        "",
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
