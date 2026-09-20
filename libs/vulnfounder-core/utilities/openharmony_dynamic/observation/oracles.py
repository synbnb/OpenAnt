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
