"""
Verification wrapper (Stage 2 attacker simulation).

Wraps FindingVerifier to run Stage 2 verification on Stage 1 results.
Verifies vulnerable/bypassable findings and, when enabled, Stage-1
inconclusive findings so the tool-assisted verifier can recover missing
downstream evidence.

Checkpoints are always enabled. Per-finding results are saved to
``{output_dir}/verify_checkpoints/`` so interrupted runs can resume.
On successful completion the checkpoint dir is removed.
"""

import json
import os
import sys
from pathlib import Path

from core.schemas import VerifyResult, UsageInfo
from core.observability import print_chinese_log
from core import tracking
from core.checkpoint import StepCheckpoint
from core.progress import ProgressReporter

from utilities.llm_client import TokenTracker, get_global_tracker
from utilities.llm import (
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    resolve_llm_config,
)
from utilities.file_io import normalize_results, read_json, write_json
from utilities.finding_verifier import FindingVerifier
from utilities.agentic_enhancer.repository_index import load_index_from_file

# Import application context (optional)
try:
    from context.application_context import ApplicationContext, load_context
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    load_context = None


def _result_finding(result: dict) -> str:
    """Return a normalized Stage-1 finding from a model result."""
    if not isinstance(result, dict):
        return ""
    return str(result.get("finding") or result.get("verdict") or "").strip().lower()


def select_stage2_candidates(
    results: list,
    *,
    include_inconclusive: bool = True,
) -> list:
    """Select results that benefit from tool-assisted Stage 2 review.

    Stage 2 is intentionally not a second pass over every safe/protected unit.
    In addition to actionable Stage-1 findings, an inconclusive result is a
    bounded evidence-recovery candidate: FindingVerifier can search definitions,
    usages, and downstream implementations before deciding whether the finding
    should be promoted, resolved, or kept inconclusive.
    """
    candidates = []
    for result in results:
        finding = _result_finding(result)
        if finding in ("vulnerable", "bypassable"):
            candidates.append(result)
        elif include_inconclusive and finding == "inconclusive":
            candidates.append(result)
    return candidates


def _count_final_findings(results: list) -> dict:
    """Count final findings from a merged result list."""
    counts = {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }
    for result in results:
        # An adapter/tool failure is not a final security verdict.  The
        # verifier keeps the Stage-1 finding on the result for auditability,
        # so error state must take precedence here or a failed vulnerable /
        # inconclusive item would be counted as a real final finding.
        if result.get("error"):
            counts["errors"] += 1
            continue
        finding = _result_finding(result) or "error"
        if finding in counts:
            counts[finding] += 1
        elif str(result.get("verdict", "")).upper() == "ERROR":
            counts["errors"] += 1
    return counts


def run_verification(
    results_path: str,
    output_dir: str,
    analyzer_output_path: str,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    workers: int = 8,
    checkpoint_path: str | None = None,
    backoff_seconds: int = 30,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
    include_inconclusive: bool = True,
) -> VerifyResult:
    """Run Stage 2 attacker-simulation verification on Stage 1 results.

    Findings with verdict ``vulnerable`` or ``bypassable`` are always verified.
    When ``include_inconclusive`` is true (the standard scanner default),
    Stage-1 ``inconclusive`` findings are also sent to the tool-assisted
    verifier as evidence-recovery candidates.  Safe/protected results remain
    out of scope. Results are written to ``results_verified.json``.

    Checkpoints are always enabled. Per-finding verification results are
    saved to ``{output_dir}/verify_checkpoints/`` so interrupted runs
    resume automatically.

    Args:
        results_path: Path to ``results.json`` from the analyze step.
        output_dir: Directory to write ``results_verified.json``.
        analyzer_output_path: Path to ``analyzer_output.json`` (required for
            repository index / tool use).
        app_context_path: Optional path to ``application_context.json``.
        repo_path: Optional path to the repository root (passed to index).
        checkpoint_path: Path to checkpoint directory. If None, auto-derived
            from output_dir.
        workers: Number of parallel workers (default: 8).
        backoff_seconds: Seconds to wait on rate limit before retry (default: 30).
        include_inconclusive: Whether to send Stage-1 inconclusive findings to
            Stage 2 for downstream evidence recovery (default: True).

    Returns:
        VerifyResult with paths, counts, and usage info.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Configure global rate limiter
    from utilities.rate_limiter import configure_rate_limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    # Set up checkpoint
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "verify_checkpoints")
    checkpoint = StepCheckpoint("Verify", output_dir)
    checkpoint.dir = checkpoint_path

    # Load Stage 1 results
    print(f"[Verify] Loading results: {results_path}", file=sys.stderr)
    print_chinese_log(
        f"结果验证输入：读取第一阶段结果 {results_path}，"
        "先规范化模型返回结构，避免恶意或损坏条目中断验证。",
        category="验证决策",
    )
    experiment = read_json(results_path)
    # fa17 TRUST BOUNDARY: `results` is model-supplied; drop non-dict elements
    # once here so the vulnerable_results filter below (and every downstream
    # r.get()) is safe. Verify runs BEFORE report, so this is the first place a
    # poisoned result would crash — normalizing per-loop missed it (fa15/fa16).
    normalize_results(experiment)
    all_results = experiment.get("results", [])
    code_by_route = experiment.get("code_by_route", {})

    # Stage 2 verifies actionable findings and, by default, unresolved
    # Stage-1 results.  The latter is deliberately a separate input class so
    # logs and metrics can show whether the verifier recovered evidence rather
    # than silently treating it as an ordinary vulnerability confirmation.
    vulnerable_results = select_stage2_candidates(
        all_results,
        include_inconclusive=include_inconclusive,
    )
    inconclusive_input = sum(
        1 for r in vulnerable_results if _result_finding(r) == "inconclusive"
    )

    findings_input = len(vulnerable_results)
    print(f"[Verify] {findings_input} findings to verify "
          f"({inconclusive_input} inconclusive evidence-recovery candidates; "
          f"out of {len(all_results)} total)", file=sys.stderr)
    print_chinese_log(
        f"验证筛选：从 {len(all_results)} 个第一阶段结果中选择 {findings_input} 个；"
        f"其中漏洞/可绕过={findings_input - inconclusive_input}，"
        f"待定补证={inconclusive_input}。安全和受保护条目不进入攻击者模拟。",
        category="验证决策",
    )

    if findings_input == 0:
        # Nothing to verify — write empty verified results
        verified_path = os.path.join(output_dir, "results_verified.json")
        _write_verified_results(verified_path, experiment, all_results, [])
        print_chinese_log(
            f"验证阶段自动跳过：没有可验证候选，已写入空增量结果 {verified_path}，"
            "不会为零候选调用模型。",
            category="验证决策",
        )
        return VerifyResult(
            verified_results_path=verified_path,
            findings_input=0,
            findings_verified=0,
            agreed=0,
            disagreed=0,
            confirmed_vulnerabilities=0,
            inconclusive_input=0,
            inconclusive_promoted=0,
            inconclusive_resolved=0,
            inconclusive_remaining=0,
            final_counts=_count_final_findings(all_results),
            usage=tracking.get_usage(),
        )

    # Build repository index
    if not analyzer_output_path or not os.path.exists(analyzer_output_path):
        raise FileNotFoundError(
            f"analyzer_output.json is required for Stage 2 verification: "
            f"{analyzer_output_path}"
        )

    print(f"[Verify] Loading repository index...", file=sys.stderr)
    print_chinese_log(
        f"验证上下文：加载函数索引 {analyzer_output_path}，"
        "用于把候选条目定位到源码、调用者和下游调用者。",
        category="验证决策",
    )
    index = load_index_from_file(analyzer_output_path, repo_path)
    print(f"  Index loaded: {len(index.functions)} functions", file=sys.stderr)
    print_chinese_log(
        f"验证上下文：函数索引包含 {len(index.functions)} 个函数，"
        "模型可据此检查调用路径而不是只看单个函数片段。",
        category="验证决策",
    )

    # Load application context if provided
    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        print(f"[Verify] App context: {app_context.application_type}", file=sys.stderr)
        print_chinese_log(
            f"验证上下文：已加载 {app_context.application_type} 应用上下文，"
            "攻击者模拟会受到同一信任边界约束。",
            category="验证决策",
        )

    # If no code_by_route in experiment file, build from results
    if not code_by_route:
        code_by_route = _build_code_by_route(all_results)

    # Resolve the verify-phase binding from the registry.
    # Standalone-invocation path validates upfront; scanner-driven
    # calls trust the scanner's probe.
    if registry is None:
        from utilities.llm import probe_registry_or_raise

        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        probe_registry_or_raise(registry)
    verify_binding = registry.get("verify")
    print(f"[Verify] Provider: {verify_binding.provider_name}, Model: {verify_binding.model}", file=sys.stderr)
    print_chinese_log(
        f"验证模型：{verify_binding.provider_name}/{verify_binding.model}；"
        "验证检查点与模型和第一阶段指纹绑定，换模型不会复用旧结论。",
        category="验证决策",
    )

    # I2 adopt gate. Runs AFTER the checkpoint.dir override above (line ~88 sets
    # ``verify_checkpoints``, not the StepCheckpoint default) and BEFORE
    # verify_batch's checkpoint.load(), so a backend swap archives the stale
    # verify checkpoints aside instead of adopting them. The static verify
    # system prompt is rendered with app_context=None. The producing analyze
    # run's fingerprint is folded into verify's KEY: a verify checkpoint written
    # against analyze run A is NOT adopted once results.json carries analyze run
    # B (a model swap). This closes the finding where verify adopts a stale
    # checkpoint and ``finding_verifier.py`` ``r["finding"] = cp_data["finding"]``
    # overwrites the fresh Stage-1 verdict.
    from core.backend_identity import fingerprint_for_binding, render_template_texts
    from prompts.verification_prompts import get_verification_system_prompt
    _verify_texts = render_template_texts(
        [lambda: get_verification_system_prompt(None)])
    checkpoint.sync_identity(fingerprint_for_binding(
        verify_binding, _verify_texts,
        extra_key={"analyze_fingerprint": experiment.get("analyze_fingerprint")}))

    # Run Stage 2 verification via verify_batch
    tracker = get_global_tracker()
    verifier = FindingVerifier(
        index=index,
        binding=verify_binding,
        tracker=tracker,
        verbose=False,
        app_context=app_context,
    )

    print(f"[Verify] Running Stage 2 attacker simulation on {findings_input} findings...",
          file=sys.stderr)
    print_chinese_log(
        f"开始攻击者模拟：并行验证 {findings_input} 个候选，"
        f"工作线程={workers}；每个结果完成后立即写入检查点以支持中断恢复。",
        category="验证进度",
    )

    # Set up progress reporter
    progress = ProgressReporter("Verify", findings_input, tracker=tracker)

    def _on_finding_done(unit_id: str, detail: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=detail,
            unit_elapsed=unit_elapsed,
        )

    def _on_restored(count: int):
        progress.completed = count

    try:
        verified_results = verifier.verify_batch(
            vulnerable_results, code_by_route,
            progress_callback=_on_finding_done,
            workers=workers,
            checkpoint=checkpoint,
            restored_callback=_on_restored,
        )
    except Exception as e:
        print(f"[Verify] ERROR during batch verification: {e}", file=sys.stderr)
        raise

    progress.finish()

    # Count outcomes (see _count_verification_outcomes for the bucketing rules).
    _counts = _count_verification_outcomes(verified_results)
    agreed = _counts["agreed"]
    disagreed = _counts["disagreed"]
    confirmed_vulnerabilities = _counts["confirmed_vulnerabilities"]
    needs_review = _counts["needs_review"]
    error_count = _counts["error_count"]
    inconclusive_promoted = _counts["inconclusive_promoted"]
    inconclusive_resolved = _counts["inconclusive_resolved"]
    inconclusive_remaining = _counts["inconclusive_remaining"]

    print(f"\n[Verify] Results: {agreed} agreed, {disagreed} disagreed, "
          f"{needs_review} need manual review, "
          f"{confirmed_vulnerabilities} confirmed vulnerabilities", file=sys.stderr)
    print_chinese_log(
        f"攻击者模拟结果：同意={agreed}，完成后改变结论={disagreed}，"
        f"需人工审阅={needs_review}，确认漏洞={confirmed_vulnerabilities}，错误={error_count}；"
        f"待定补证升级为漏洞={inconclusive_promoted}，"
        f"待定补证已解决={inconclusive_resolved}，仍待定={inconclusive_remaining}。",
        category="验证结果",
    )
    if error_count:
        print(f"[Verify] Errors: {error_count}", file=sys.stderr)

    # Checkpoints are preserved as a permanent artifact alongside results
    # (final summary with phase="done" is written inside verify_batch).

    tracking.log_usage("Stage 2")

    # Merge verified results back into the full result set
    verified_ids = {r.get("unit_id") or r.get("route_key") for r in verified_results}
    merged_results = []
    verified_lookup = {
        (r.get("unit_id") or r.get("route_key")): r for r in verified_results
    }

    for r in all_results:
        key = r.get("unit_id") or r.get("route_key")
        if key in verified_lookup:
            merged_results.append(verified_lookup[key])
        else:
            merged_results.append(r)

    # Write results_verified.json
    verified_path = os.path.join(output_dir, "results_verified.json")
    _write_verified_results(verified_path, experiment, merged_results, verified_results)
    final_counts = _count_final_findings(merged_results)

    print(f"[Verify] Verified results written to {verified_path}", file=sys.stderr)
    print_chinese_log(
        f"验证产物：合并后的 results_verified.json 已写入 {verified_path}，"
        "后续汇总和报告以该文件为准。",
        category="验证结果",
    )

    return VerifyResult(
        verified_results_path=verified_path,
        findings_input=findings_input,
        findings_verified=len(verified_results),
        agreed=agreed,
        disagreed=disagreed,
        confirmed_vulnerabilities=confirmed_vulnerabilities,
        needs_review=needs_review,
        error_count=error_count,
        inconclusive_input=inconclusive_input,
        inconclusive_promoted=inconclusive_promoted,
        inconclusive_resolved=inconclusive_resolved,
        inconclusive_remaining=inconclusive_remaining,
        final_counts=final_counts,
        usage=tracking.get_usage(),
    )


def _count_verification_outcomes(verified_results: list) -> dict:
    """Bucket verified results into agreed / disagreed / needs_review / error.

    PR #69 F5/L4 — the four buckets are mutually exclusive and, crucially,
    keep "incomplete" and "errored" findings OUT of the path that the scanner
    later folds into ``safe`` (``safe += disagreed``):

      * ``error``        — ``result["error"]`` is set (adapter raised; L4). The
                           verification could not run; never read as safe.
      * ``needs_review`` — verification ran but could NOT COMPLETE, or an
                           inconclusive input still has no determined final
                           verdict. Such results await manual triage.
      * ``agreed``       — Stage 2 completed and agreed; if the final finding is
                           vulnerable/bypassable it is a confirmed vulnerability.
      * ``disagreed``    — Stage 2 completed and actively disagreed (e.g.
                           downgraded the verdict). ONLY this bucket is safe to
                           fold into ``safe`` downstream.
    """
    counts = {
        "agreed": 0,
        "disagreed": 0,
        "needs_review": 0,
        "confirmed_vulnerabilities": 0,
        "error_count": 0,
        "inconclusive_input": 0,
        "inconclusive_promoted": 0,
        "inconclusive_resolved": 0,
        "inconclusive_remaining": 0,
    }
    for r in verified_results:
        verification = r.get("verification", {})
        original_finding = str(
            verification.get("stage1_finding")
            or r.get("stage1_finding")
            or r.get("finding")
            or r.get("verdict", "")
        ).strip().lower()
        if original_finding == "inconclusive":
            counts["inconclusive_input"] += 1
        if r.get("error"):
            counts["error_count"] += 1
            if original_finding == "inconclusive":
                counts["inconclusive_remaining"] += 1
            continue
        if verification.get("incomplete"):
            # Could not complete — needs manual review, NOT a disagreement.
            counts["needs_review"] += 1
            if original_finding == "inconclusive":
                counts["inconclusive_remaining"] += 1
            continue
        final_finding = _result_finding(r) or str(
            verification.get("correct_finding", "")
        ).strip().lower()
        if original_finding == "inconclusive":
            if final_finding in ("vulnerable", "bypassable"):
                counts["inconclusive_promoted"] += 1
            elif final_finding in ("safe", "protected"):
                counts["inconclusive_resolved"] += 1
            else:
                counts["inconclusive_remaining"] += 1
                counts["needs_review"] += 1
        if verification.get("agree", False):
            counts["agreed"] += 1
            # Canonical read (matches :99 input filter): fall back to `verdict`
            # so a verdict-only VULNERABLE result is not silently dropped.
            finding = final_finding
            if finding in ("vulnerable", "bypassable"):
                counts["confirmed_vulnerabilities"] += 1
        else:
            # Stage 2 disagreed. finding_verifier has already written the
            # corrected verdict onto ``r["finding"]`` (= correct_finding). A
            # disagreement only folds into ``safe`` (``safe += disagreed``) when
            # that corrected verdict is itself non-vulnerable. If the verifier
            # disagreed but the finding is STILL vulnerable/bypassable (e.g.
            # vulnerable -> bypassable), it is a confirmed vulnerability, NOT
            # safe — counting it as ``disagreed`` would under-report the vuln.
            # Canonical read (matches :99 input filter): fall back to `verdict`
            # so a verdict-only VULNERABLE disagreement is not silently dropped.
            finding = final_finding
            if finding in ("vulnerable", "bypassable"):
                counts["confirmed_vulnerabilities"] += 1
            else:
                counts["disagreed"] += 1
    return counts


def _write_verified_results(
    path: str,
    experiment: dict,
    merged_results: list,
    verified_only: list,
) -> None:
    """Write the verified results file."""
    output = {
        "dataset": experiment.get("dataset", ""),
        "model": experiment.get("model", ""),
        "timestamp": experiment.get("timestamp", ""),
        "verify": True,
        "metrics": experiment.get("metrics", {}),
        "results": merged_results,
        # Preserve the source snippets assembled during Stage 1.  Report
        # generation deliberately renders this map without asking the LLM to
        # reproduce source code; dropping it here made every verified
        # disclosure lose its deterministic ``Vulnerable Code`` section.
        "code_by_route": (
            dict(experiment.get("code_by_route"))
            if isinstance(experiment.get("code_by_route"), dict)
            else _build_code_by_route(merged_results)
        ),
        # Filter on the FINAL verdict (already updated by Stage 2 when it
        # disagrees), not the `agree` flag. Stage 2 may disagree on the
        # reason/CWE but still confirm the finding is vulnerable — those
        # must not be dropped.
        "confirmed_findings": [
            r for r in verified_only
            # Canonical read (matches :99 input filter): fall back to `verdict`.
            if str(r.get("finding") or r.get("verdict", "")).lower()
            in ("vulnerable", "bypassable")
        ],
    }

    # Recount metrics after verification from the merged final verdicts.  This
    # is authoritative for the scanner: an inconclusive result promoted or
    # resolved by Stage 2 must move buckets exactly once.
    output["metrics"] = {
        "total": len(merged_results),
        **_count_final_findings(merged_results),
    }

    write_json(path, output, ensure_ascii=False)
def _build_code_by_route(results: list) -> dict:
    """Build code_by_route from result entries (fallback)."""
    code_by_route = {}
    for r in results:
        route_key = r.get("route_key") or r.get("unit_id", "")
        code = r.get("code", "")
        if isinstance(code, dict):
            code = code.get("primary_code", "")
        if route_key and code:
            code_by_route[route_key] = code
    return code_by_route
