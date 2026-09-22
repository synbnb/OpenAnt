"""Claude Code 旁路协议描述符实验器。

这个模块故意不接入 ``descriptor_synthesizer`` 的默认生产路径。它用于回答一个
可复查的问题：在相同 finding、源码范围和确定性校验器下，Claude Code 是否比当前
动态测试模型更容易补齐协议描述符。

Claude Code 只开放 Read/Grep/Glob；不会获得 shell、HDC、安装、发送、编辑或删除
权限。返回的文本必须再次转换成 ``ProtocolDescriptor``，并复用现有描述符校验器，
因此“模型输出了 JSON”不等于实验通过。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .descriptor_synthesizer import (
    _descriptor_from_draft,
    _validate_legal_probe,
    _validate_protocol_shape_against_source,
    _validate_wire_format_against_source,
    verify_descriptor_evidence,
)


DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_MAX_BUDGET_USD = "1"


CLAUDE_DESCRIPTOR_PROMPT = r"""你负责一个只读的 OpenHarmony 动态测试协议审计任务。

先读取当前 finding 输入文件：{finding_path}
然后读取其中 repo_root 指定的源码；只关注当前 finding 的目标 sink、候选入口、
分帧、字段解析、消息分派和守卫。不要修改文件，不要执行 shell/hdc，不要安装、
启动、停止服务，不要发送网络或设备请求，也不要读取历史 exemplar、设备事实库或
其它样本答案。

请生成一个 ProtocolDescriptor JSON 草案，供程序执行严格证据校验。输出必须是一个
JSON 对象，不要 markdown，不要解释文字。字段必须完整：
{{
  "descriptor_id": "<协议族名或 insufficient>",
  "endianness": "host|ascii|little",
  "framing": "single_message|frame_sequence|stream_tlv",
  "transports": ["unix_dgram|unix_stream|udp|tcp|cli|event_bus"],
  "fields": [{{"name":"<真实字段>","type":"string|int64|u32|u64|double|bool",
                "order":0,"evidence":"file.cpp:line"}}],
  "known_guards": [{{"name":"<检查名>","evidence":"file.cpp:line",
                      "checked_by":"<检查语义>","guard_log_hints":[]}}],
  "on_send_transforms": [],
  "structure_evidence": "<整体布局及证据>",
  "encoder_kind": "raw_text|key_value|json|custom",
  "wire_format": {{"pair_separator":"","record_separator":"","terminator":""}},
  "legal_probe": {{"mode":"udp|tcp|local|cli|event_bus","host":"","port":0,
                    "first":"","second":"","third":"","evidence":"file.cpp:line"}}
}}

硬规则：
1. 每个字段、守卫和 legal_probe 必须引用当前仓库内真实的 file:line；不能编造。
2. 字段名必须逐字出现在当前 route 的源码字段/常量/命令表中；不确定时不要凑字段。
3. legal_probe 只能是无害合法请求，禁止 marker、echo、分号、管道、重定向、反引号、
   shell 控制字符、命令执行词和占位符。
4. 不要按端口大小、候选顺序或服务名称猜入口。若多个端点无法从源码证明与当前 sink
   的绑定关系，descriptor_id 写 insufficient，并在 structure_evidence 说明缺口。
5. 只描述当前 route；不要把同一服务的其它端点、无关命令和其它漏洞样本混入。
6. 即使协议描述符可以生成，也不能声称漏洞已触发；本实验只评估描述符证据闭环。
"""


@dataclass
class ClaudeDescriptorExperimentResult:
    status: str
    claude_bin: str = ""
    command: list[str] = field(default_factory=list)
    finding_path: str = ""
    repo_root: str = ""
    elapsed_seconds: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""
    outer_response: dict[str, Any] = field(default_factory=dict)
    draft: dict[str, Any] | None = None
    descriptor: dict[str, Any] | None = None
    validation: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "provider": "claude_code_sidecar",
            "claude_bin": self.claude_bin,
            "command": list(self.command),
            "finding_path": self.finding_path,
            "repo_root": self.repo_root,
            "elapsed_seconds": self.elapsed_seconds,
            "raw_stdout": self.raw_stdout[-20000:],
            "raw_stderr": self.raw_stderr[-8000:],
            "outer_response": dict(self.outer_response),
            "draft": self.draft,
            "descriptor": self.descriptor,
            "validation": dict(self.validation),
            "error": self.error,
        }


def _extract_json(text: str) -> Any:
    """解析 Claude CLI 的 JSON 外壳以及 result 中的 JSON 字符串。"""

    body = str(text or "").strip()
    candidates = [body]
    # --output-format json 通常只有一个对象，但 CLI 警告可能出现在对象前面。
    start = body.find("{")
    end = body.rfind("}")
    if start >= 0 and end > start:
        candidates.append(body[start : end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("result"), str):
            nested = value["result"].strip()
            try:
                inner = json.loads(nested)
            except json.JSONDecodeError:
                # 允许模型在 result 外围留下少量 markdown，但仍只取一个对象。
                i, j = nested.find("{"), nested.rfind("}")
                if i < 0 or j <= i:
                    return value
                try:
                    inner = json.loads(nested[i : j + 1])
                except json.JSONDecodeError:
                    return value
            value["_descriptor_result"] = inner
        return value
    return None


def _load_finding(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("finding 输入必须是 JSON 对象")
    return value


def _repo_root_from_finding(finding: dict[str, Any]) -> Path:
    root = str(finding.get("repo_root") or "").strip()
    if not root:
        raise ValueError("finding 缺少 repo_root")
    path = Path(root).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"repo_root 不存在或不是目录: {path}")
    return path


def _build_command(
    claude_bin: str,
    *,
    repo_root: Path,
    finding_path: Path,
    model: str = "",
    max_budget_usd: str = DEFAULT_MAX_BUDGET_USD,
) -> list[str]:
    command = [
        claude_bin,
        "-p",
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--permission-prompts",
        "none",
        "--allowed-tools",
        "Read",
        "Grep",
        "Glob",
        "--add-dir",
        str(repo_root),
        "--add-dir",
        str(finding_path.parent),
        "--output-format",
        "json",
    ]
    if model:
        command.extend(["--model", model])
    if max_budget_usd:
        command.extend(["--max-budget-usd", str(max_budget_usd)])
    return command


def _validate_draft(
    draft: dict[str, Any], finding: dict[str, Any], repo_root: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    descriptor = _descriptor_from_draft(draft)
    if descriptor is None:
        return None, {"errors": ["Claude 输出缺少合法 ProtocolDescriptor 结构"]}
    source_paths = [str(x) for x in finding.get("source_paths", []) if str(x).strip()]
    route = finding.get("analysis_context")
    if isinstance(route, dict):
        for raw in route.get("source_evidence", []) or []:
            text = str(raw)
            path = text.split(":", 1)[0]
            if path and path not in source_paths:
                source_paths.append(path)
    evidence = verify_descriptor_evidence(
        descriptor, source_paths, repo_root=str(repo_root),
    )
    errors = list(evidence.get("evidence_failures", []))
    if evidence.get("missing"):
        errors.append("字段未在当前源码证据中核验: " + ", ".join(evidence["missing"]))
    errors.extend(_validate_legal_probe(descriptor.legal_probe))
    errors.extend(_validate_wire_format_against_source(
        descriptor, source_paths, repo_root=str(repo_root),
    ))
    errors.extend(_validate_protocol_shape_against_source(
        descriptor, source_paths, repo_root=str(repo_root),
    ))
    return descriptor.to_dict(), {
        "source_paths": source_paths,
        "evidence": evidence,
        "errors": list(dict.fromkeys(errors)),
    }


def run_claude_descriptor_experiment(
    finding_path: str | Path,
    *,
    output_path: str | Path | None = None,
    claude_bin: str | None = None,
    model: str = "",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_budget_usd: str = DEFAULT_MAX_BUDGET_USD,
) -> ClaudeDescriptorExperimentResult:
    """用 Claude Code 旁路生成并校验一个描述符，不改变生产合成器。"""

    started = time.monotonic()
    finding_file = Path(finding_path).expanduser().resolve()
    result = ClaudeDescriptorExperimentResult(status="not_started", finding_path=str(finding_file))
    try:
        finding = _load_finding(finding_file)
        repo_root = _repo_root_from_finding(finding)
        result.repo_root = str(repo_root)
        executable = claude_bin or os.environ.get("VULNFOUNDER_CLAUDE_BIN") or os.environ.get("OPENANT_CLAUDE_BIN") or shutil.which("claude")
        if not executable:
            raise FileNotFoundError("找不到 Claude Code 可执行文件")
        command = _build_command(
            executable, repo_root=repo_root, finding_path=finding_file,
            model=model, max_budget_usd=max_budget_usd,
        )
        result.claude_bin = executable
        result.command = command
        prompt = CLAUDE_DESCRIPTOR_PROMPT.format(finding_path=str(finding_file))
        completed = subprocess.run(
            [*command, prompt],
            cwd=str(repo_root),
            text=True,
            capture_output=True,
            timeout=max(1, int(timeout_seconds)),
            check=False,
            env=os.environ.copy(),
        )
        result.raw_stdout = completed.stdout or ""
        result.raw_stderr = completed.stderr or ""
        outer = _extract_json(result.raw_stdout)
        if isinstance(outer, dict):
            result.outer_response = outer
        if completed.returncode != 0:
            result.status = "claude_unavailable"
            api_message = ""
            if isinstance(outer, dict):
                api_message = str(outer.get("result") or outer.get("error") or "")
            result.error = api_message or result.raw_stderr[-2000:] or f"Claude Code 退出码 {completed.returncode}"
        else:
            draft = outer.get("_descriptor_result") if isinstance(outer, dict) else outer
            if not isinstance(draft, dict):
                result.status = "invalid_output"
                result.error = "Claude Code 没有返回可解析的 ProtocolDescriptor JSON"
            else:
                result.draft = draft
                descriptor, validation = _validate_draft(draft, finding, repo_root)
                result.descriptor = descriptor
                result.validation = validation
                if descriptor is not None and not validation.get("errors"):
                    result.status = "validated"
                else:
                    result.status = "rejected_by_deterministic_checks"
    except subprocess.TimeoutExpired as exc:
        result.status = "timeout"
        result.error = f"Claude Code 超时（>{timeout_seconds}s）"
        result.raw_stdout = str(exc.stdout or "")
        result.raw_stderr = str(exc.stderr or "")
    except Exception as exc:  # noqa: BLE001 - 实验结果必须显式记录失败原因
        result.status = "experiment_error"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.elapsed_seconds = round(time.monotonic() - started, 3)
        if output_path is not None:
            target = Path(output_path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return result


__all__ = [
    "CLAUDE_DESCRIPTOR_PROMPT",
    "ClaudeDescriptorExperimentResult",
    "run_claude_descriptor_experiment",
]
