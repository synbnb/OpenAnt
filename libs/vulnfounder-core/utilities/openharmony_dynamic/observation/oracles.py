"""预言机层（§9）：artifact_differential 与 hilog_expectation。

artifact_differential 四形态（§9.2）：
- create  执行前不存在 → 执行后存在，内容含本轮唯一图案
- exfil   预埋图案文件 → 其内容出现在声明输出面
- delete  预埋图案文件 → 执行后消失
- attr    执行前后 stat 差异

全部声明项须通过才算 effect 成立；图案必须含本轮随机成分（否证历史文件）。
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ..models import ArtifactForm, OracleResult, OracleSpec
from .snapshot import FileSnapshot

if TYPE_CHECKING:
    from ..hdc_client import HDCClient

_EXFIL_DIR_LS = "ls -l {dir} 2>&1"
_EXFIL_DIR_FILES = "ls {dir} 2>&1"


def _quote(path: str) -> str:
    if "'" in path or any(c in path for c in "\x00\n;|&$`\\"):
        raise ValueError(f"路径不安全: {path!r}")
    return "'" + path + "'"


class OracleError(RuntimeError):
    """预言机配置或执行错误。"""


def _validate_spec(spec: OracleSpec) -> None:
    if spec.kind != "artifact_differential":
        return
    if not spec.artifact_forms:
        raise OracleError("artifact_differential 未声明任何 form")
    for form in spec.artifact_forms:
        if form.form not in ("create", "exfil", "delete", "attr"):
            raise OracleError(f"未知 form: {form.form}")
        if form.form in ("create", "delete", "attr") and not form.path:
            raise OracleError(f"form={form.form} 缺少 path")
        if form.form == "exfil" and (not form.path or not form.output_surface):
            raise OracleError("form=exfil 需要 path（预埋文件）与 output_surface（输出面目录）")
        if form.form == "create" and not form.content_contains:
            raise OracleError("form=create 需要 content_contains（run 唯一图案）")


# ---------------------------------------------------------------------------
# 预埋与清理（exfil/delete/create 的准备阶段）
# ---------------------------------------------------------------------------

def plant_exfil_file(hdc: "HDCClient", form: ArtifactForm, *, purpose: str = "") -> bool:
    """在设备上预埋 exfil 源文件（含图案）。返回是否成功。"""
    if not form.content_contains:
        raise OracleError("exfil 预埋需要 content_contains 图案")
    quoted = _quote(form.path)
    parent = form.path.rsplit("/", 1)[0]
    hdc.shell(["mkdir", "-p", parent], purpose=purpose or f"plant:mkdir:{parent}")
    rec = hdc.shell(
        ["sh", "-c", f"printf %s {form.content_contains!r} > {quoted}"],
        purpose=purpose or f"plant:{form.path}",
    )
    return rec.returncode == 0 and "can't create" not in rec.stdout


def clear_artifacts(hdc: "HDCClient", spec: OracleSpec, *, purpose: str = "",
                    skip_paths: "frozenset[str] | set[str] | None" = None) -> None:
    """执行前精确清理：rm -f 单个声明文件（禁止通配删除）。

    skip_paths：豁免清单（Exp 契约的 param_space.exp_no_plant_paths——victim
    是设备真实系统文件，rm -f 绝不允许、预埋也无意义，只保留快照核对）。
    """
    skip = skip_paths or frozenset()
    for form in spec.artifact_forms:
        if form.path and form.path not in skip:
            hdc.shell(["rm", "-f", form.path], purpose=purpose or f"clear:{form.path}")


# ---------------------------------------------------------------------------
# artifact_differential 判定
# ---------------------------------------------------------------------------

def evaluate_artifact_differential(
    spec: OracleSpec,
    baseline: dict[str, FileSnapshot],
    mutated: dict[str, FileSnapshot],
    *,
    hdc: "HDCClient | None" = None,
    run_pattern: str = "",
) -> OracleResult:
    """对四形态逐一判定；全部通过 → effect_observed=True。

    hdc 仅在 exfil 需要扫描输出面目录时使用。
    """
    _validate_spec(spec)
    forms: dict[str, bool] = {}
    details: dict[str, Any] = {"forms": {}}
    for form in spec.artifact_forms:
        before = baseline.get(form.path)
        after = mutated.get(form.path)
        if before is None or after is None:
            forms[form.form] = False
            details["forms"][form.form] = {"error": "missing snapshot", "path": form.path}
            continue
        if form.form == "create":
            # 期望内容：优先契约声明的 content_contains（注入载体的字面输出如 canary 文本），
            # 未声明时回退 run_pattern（run 唯一图案绑定）
            needle = form.content_contains or run_pattern
            ok = (not before.exists) and after.exists and bool(needle and needle in after.content)
            details["forms"][form.form] = {
                "path": form.path,
                "before_exists": before.exists,
                "after_exists": after.exists,
                "pattern_found": needle in after.content if after.exists else False,
                "needle_source": "contract" if form.content_contains else "run_pattern",
            }
        elif form.form == "delete":
            ok = before.exists and (not after.exists)
            details["forms"][form.form] = {
                "path": form.path,
                "before_exists": before.exists,
                "after_exists": after.exists,
            }
        elif form.form == "attr":
            changed = (
                before.exists and after.exists
                and (before.size != after.size or before.stat_text != after.stat_text)
            )
            ok = changed
            details["forms"][form.form] = {
                "path": form.path,
                "before_size": before.size,
                "after_size": after.size,
                "stat_changed": before.stat_text != after.stat_text,
            }
        else:  # exfil
            found, surface_files = _exfil_surface_scan(hdc, form, run_pattern)
            # 源文件在执行后被消费删除是常见副作用（HV-05 实证），只要求执行前存在
            ok = before.exists and found
            details["forms"][form.form] = {
                "path": form.path,
                "before_exists": before.exists,
                "pattern_in_surface": found,
                "surface_files": surface_files,
            }
        forms[form.form] = bool(ok)

    effect_observed = all(forms.values()) if forms else False
    result = OracleResult(kind="artifact_differential", effect_observed=effect_observed, forms=forms, details=details)
    # 否证记录：若效果成立但图案缺失（不应发生），标注
    if effect_observed and run_pattern:
        result.refutation_checks.append({"check": "run_pattern_bound", "passed": True, "pattern": run_pattern})
    elif not effect_observed:
        result.refutation_checks.append({"check": "all_forms_passed", "passed": False, "forms": forms})
    return result


def evaluate_declared_oracle(
    spec: OracleSpec,
    baseline: dict[str, FileSnapshot],
    mutated: dict[str, FileSnapshot],
    *,
    hdc: "HDCClient | None" = None,
    run_pattern: str = "",
    hilog_hits: list[dict[str, Any]] | None = None,
    process_before: dict[str, Any] | None = None,
    process_after: dict[str, Any] | None = None,
    response_before: str = "",
    response_after: str = "",
    state_before: dict[str, Any] | None = None,
    state_after: dict[str, Any] | None = None,
) -> OracleResult:
    """按契约声明分派通用预言机。

    旧实现把所有漏洞类型压成 ``artifact_differential``，导致资源、崩溃、
    权限和状态样本在契约编译阶段直接 ``ORACLE_UNAVAILABLE``。这里保留
    文件差分的既有实现，并为其余类型提供同一套 before/during/after/
    refutation 结构。没有足够观测值时返回未通过且明确写出缺口，不伪造
    effect；调用方仍会据此产生 INCONCLUSIVE/UNPROVEN，而不是误报 CONFIRMED。
    """
    kind = str(spec.kind or "artifact_differential")
    if kind == "artifact_differential":
        result = evaluate_artifact_differential(
            spec, baseline, mutated, hdc=hdc, run_pattern=run_pattern,
        )
    elif kind in {"hilog_expectation", "log_signal"}:
        hits = list(hilog_hits or [])
        required = [item for item in spec.hilog_expectations if isinstance(item, dict) and item.get("required") is not False]
        minimum = max([int(item.get("min_count", 1)) for item in required] or [1])
        passed = len(hits) >= minimum
        result = OracleResult(
            kind=kind, effect_observed=passed,
            forms={"log_signal": passed},
            details={"hits": hits, "required_count": len(required), "minimum": minimum},
        )
    elif kind in {"readback_differential", "response_match"}:
        needle = str(spec.config.get("content_contains") or run_pattern or "")
        passed = bool(needle and needle in str(response_after or "") and needle not in str(response_before or ""))
        result = OracleResult(
            kind=kind, effect_observed=passed,
            forms={"response": passed},
            details={
                "needle_source": "config" if spec.config.get("content_contains") else "run_pattern",
                "before_contains": bool(needle and needle in str(response_before or "")),
                "after_contains": bool(needle and needle in str(response_after or "")),
            },
        )
    elif kind in {"process_liveness", "crash_correlated"}:
        before_alive = bool((process_before or {}).get("alive", (process_before or {}).get("pids")))
        after_alive = bool((process_after or {}).get("alive", (process_after or {}).get("pids")))
        crashed = before_alive and not after_alive
        before_faultlog = str((process_before or {}).get("faultlog_tail", ""))
        after_faultlog = str((process_after or {}).get("faultlog_tail", ""))
        faultlog = bool((process_after or {}).get("faultlog_match")) or bool(
            after_faultlog and after_faultlog != before_faultlog
        )
        passed = crashed and (kind == "process_liveness" or faultlog or bool(spec.config.get("allow_unattributed_crash")))
        result = OracleResult(
            kind=kind, effect_observed=passed,
            forms={"process_exit": passed},
            details={
                "before_alive": before_alive,
                "after_alive": after_alive,
                "faultlog_match": faultlog,
                "faultlog_changed": bool(after_faultlog and after_faultlog != before_faultlog),
            },
        )
    elif kind in {"resource_delta", "fd_delta", "memory_delta"}:
        before = process_before or {}
        after = process_after or {}
        metric = str(spec.config.get("metric") or "fd_count")
        try:
            before_value = float(before.get(metric, 0))
            after_value = float(after.get(metric, 0))
            threshold = float(spec.config.get("min_delta", 1))
        except (TypeError, ValueError):
            before_value = after_value = 0.0
            threshold = 1.0
        delta = after_value - before_value
        passed = bool((before or after) and delta >= threshold)
        result = OracleResult(
            kind=kind, effect_observed=passed,
            forms={"resource_growth": passed},
            details={"metric": metric, "before": before_value, "after": after_value, "delta": delta, "threshold": threshold},
        )
    elif kind in {"permission_differential", "identity_differential"}:
        before = str((state_before or {}).get("outcome", ""))
        after = str((state_after or {}).get("outcome", ""))
        expected = str(spec.config.get("expected_after") or "allowed")
        denied = str(spec.config.get("expected_before") or "denied")
        passed = bool(after == expected and (not before or before == denied))
        result = OracleResult(
            kind=kind, effect_observed=passed,
            forms={"permission_change": passed},
            details={"before_outcome": before, "after_outcome": after, "expected_before": denied, "expected_after": expected},
        )
    elif kind in {"state_differential", "race_differential"}:
        before = state_before or {}
        after = state_after or {}
        keys = list(spec.config.get("keys") or sorted(set(before) | set(after)))
        changes = {key: {"before": before.get(key), "after": after.get(key)} for key in keys if before.get(key) != after.get(key)}
        passed = bool(changes)
        result = OracleResult(kind=kind, effect_observed=passed, forms={"state_changed": passed}, details={"changes": changes})
    else:
        result = OracleResult(kind=kind, effect_observed=False, forms={}, details={"error": f"unsupported oracle kind: {kind}"})

    # 所有通用 oracle 都带有可审计的反事实说明；这不是把失败升级成成功，
    # 只是记录哪些否证条件已经被检查。
    if result.effect_observed:
        result.refutation_checks.append({"check": "run_pattern_bound", "passed": bool(run_pattern)})
    else:
        result.refutation_checks.append({"check": "oracle_signal_present", "passed": False})
    return result


def _exfil_surface_scan(
    hdc: "HDCClient | None",
    form: ArtifactForm,
    run_pattern: str,
) -> tuple[bool, list[dict[str, Any]]]:
    """扫描 exfil 输出面（目录），查找包含图案的文件并回读其内容。

    needle 优先取契约显式 content_contains（Exp 契约回填的 victim 实测指纹），
    未声明时回退 run_pattern。PoC 契约的 __RUN_PATTERN__ 占位符在 runner
    _substitute 展开后与本轮 run_pattern 相同，两源等价，行为不变。
    """
    if hdc is None:
        return False, []
    needle = form.content_contains or run_pattern
    if not needle:
        return False, []
    ls = hdc.shell(["sh", "-c", _EXFIL_DIR_FILES.format(dir=_quote(form.output_surface))],
                   purpose="exfil:ls-surface")
    files = [f.strip() for f in ls.stdout.splitlines() if f.strip() and "No such file" not in f]
    hits: list[dict[str, Any]] = []
    found = False
    for name in files[:64]:  # 上限防失控
        full = form.output_surface.rstrip("/") + "/" + name
        rec = hdc.shell(["cat", full], purpose="exfil:read")
        if needle in rec.stdout:
            found = True
            hits.append({"path": full, "contains_pattern": True})
    return found, hits
