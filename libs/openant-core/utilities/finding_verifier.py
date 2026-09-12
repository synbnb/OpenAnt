"""
Stage 2 Finding Verifier (Enhanced)

Stage 2 of the two-stage vulnerability analysis pipeline.
Uses Opus with tool access to validate Stage 1 assessments by exploring
the codebase - searching function usages, reading definitions, and
tracing call paths.

Key Improvements:
    1. Explicit vulnerability definitions (exploitable NOW vs dangerous design)
    2. Required exploit path tracing (entry point -> sink)
    3. Consistency cross-check for similar code patterns
    4. Structured output with exploit_path field
    5. Batch verification with consistency validation

The verifier asks: "Can an attacker exploit this NOW in the current codebase?"
It validates by tracing the complete exploit path from attacker input to sink.

Available Tools:
    - search_usages: Find where a function is called
    - search_definitions: Find where a function is defined
    - read_function: Get full function code by ID
    - list_functions: List all functions in a file
    - read_file_section: Read bounded registration/dispatch context by line range
    - get_static_dependencies: Return parser-resolved callers/callees for the current target route
    - finish: Complete verification with verdict and exploit path

Classes:
    VerificationResult: Dataclass containing verdict, exploit path, explanation
    FindingVerifier: Main verifier class with verify_result() and verify_batch() methods
"""

import json
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from .llm_client import TokenTracker, get_global_tracker
from .llm import (
    LLMRateLimitError,
    Message,
    PhaseBinding,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
    lookup_pricing,
)

# Null logger that discards all messages (used when no logger provided)
_null_logger = logging.getLogger("null_verifier")
_null_logger.addHandler(logging.NullHandler())
from .agentic_enhancer.repository_index import RepositoryIndex
from .agentic_enhancer.tools import ToolExecutor
from prompts.verification_prompts import (
    VERIFICATION_SYSTEM_PROMPT,
    get_verification_prompt,
    get_verification_system_prompt,
    get_consistency_check_prompt
)
from core.verdict_taxonomy import DISCLOSURE_DROPPED, FINDING_VERDICT_ORDER
from core.finding_records import ensure_primary_record, normalize_findings

# Import application context type for type hints
try:
    from context.application_context import ApplicationContext
except ImportError:
    ApplicationContext = None


MAX_ITERATIONS = 20
MAX_TOKENS_PER_RESPONSE = 4096


# Expected JSON shape of a verifier `finish` response — handed to JSONCorrector
# so a malformed-but-recoverable verifier reply is repaired into THIS shape (no
# verdict) rather than the default vuln schema, and its success is gated on the
# verifier's own required keys instead of a nonexistent ``verdict`` field.
_VERIFY_JSON_SCHEMA = """{
    "agree": true,
    "correct_finding": "safe | protected | bypassable | vulnerable | inconclusive",
    "assessment": {
        "defect_status": "confirmed | suspected | none | unknown",
        "reachability_status": "confirmed | conditional | unknown | none",
        "impact_status": "confirmed | plausible | unknown | none",
        "evidence_completeness": "complete | partial | missing",
        "parameter_dataflow_status": "confirmed | partial | missing | blocked | not_evaluated",
        "boundary_type": "binder | system_ability | idl | socket | unix_socket | tcp | udp | tcp_udp_socket | napi | hdf_hdi | ioctl | file | callback | queue | cli | other",
        "direction": "inbound | outbound | bidirectional | unknown",
        "source_evidence_status": "confirmed | partial | missing | unknown",
        "registration_evidence": [],
        "endpoint": null,
        "input_relation": "confirmed | partial | missing | blocked | unknown",
        "missing_evidence": []
    },
    "exploit_path": {"entry_point": null, "data_flow": [], "sink_reached": false, "attacker_control_at_sink": "none", "path_broken_at": null},
    "findings": [
        {
            "finding_id": "stable issue id",
            "scope": "target | context",
            "relation": "primary | secondary | context_risk",
            "target_match": true,
            "finding": "safe | protected | bypassable | vulnerable | inconclusive",
            "function_analyzed": "function containing the issue",
            "file": "source file",
            "line_start": 0,
            "line_end": 0,
            "vulnerability_categories": [],
            "impact": [],
            "reasoning": "independent issue explanation",
            "evidence": [],
            "missing_evidence": []
        }
    ],
    "explanation": "Detailed explanation of your analysis",
    "security_weakness": null
}"""


# Enhanced finish tool with exploit_path structure
VERIFICATION_TOOLS = [
    {
        "name": "search_usages",
        "description": "Search for all places where a function is called/used in the codebase. Use this to trace how attacker input flows through the code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find usages of"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "search_definitions",
        "description": "Search for where a function is defined. Use this to understand what a function does.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to find definition of"
                }
            },
            "required": ["function_name"]
        }
    },
    {
        "name": "read_function",
        "description": "Read the full source code of a function by its ID. Use this to analyze function behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_id": {
                    "type": "string",
                    "description": "Function identifier in format 'file/path.ts:functionName'"
                }
            },
            "required": ["function_id"]
        }
    },
    {
        "name": "list_functions",
        "description": "List all functions defined in a specific file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to repository root"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "read_file_section",
        "description": "Read a bounded source section by file and line numbers when a registration, socket receiver, guard, or sink is outside a function body.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1}
            },
            "required": ["file_path", "start_line", "end_line"]
        }
    },
    {
        "name": "get_static_dependencies",
        "description": "Return parser-resolved callers and callees for the target route. Use this as a starting map, then read the relevant function bodies; graph edges are evidence, not proof of attacker control.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "finish",
        "description": "Complete the verification with your verdict and exploit path analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agree": {
                    "type": "boolean",
                    "description": "Whether you agree with Stage 1's assessment"
                },
                "correct_finding": {
                    "type": "string",
                    "enum": ["safe", "protected", "bypassable", "vulnerable", "inconclusive"],
                    "description": "The correct finding based on exploit path analysis"
                },
                "assessment": {
                    "type": "object",
                    "description": "Independent assessment of defect, route, impact, and evidence completeness.",
                    "properties": {
                        "defect_status": {
                            "type": "string",
                            "enum": ["confirmed", "suspected", "none", "unknown"]
                        },
                        "reachability_status": {
                            "type": "string",
                            "enum": ["confirmed", "conditional", "unknown", "none"]
                        },
                        "impact_status": {
                            "type": "string",
                            "enum": ["confirmed", "plausible", "unknown", "none"]
                        },
                        "evidence_completeness": {
                            "type": "string",
                            "enum": ["complete", "partial", "missing"]
                        },
                        "parameter_dataflow_status": {
                            "type": "string",
                            "enum": ["confirmed", "partial", "missing", "blocked", "not_evaluated"]
                        },
                        "boundary_type": {"type": "string"},
                        "direction": {
                            "type": "string",
                            "enum": ["inbound", "outbound", "bidirectional", "unknown"]
                        },
                        "source_evidence_status": {
                            "type": "string",
                            "enum": ["confirmed", "partial", "missing", "unknown"]
                        },
                        "registration_evidence": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 8
                        },
                        "endpoint": {"type": ["string", "null"]},
                        "input_relation": {
                            "type": "string",
                            "enum": ["confirmed", "partial", "missing", "blocked", "unknown"]
                        },
                        "missing_evidence": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                },
                "exploit_path": {
                    "type": "object",
                    "description": "Analysis of the exploit path from attacker input to sink",
                    "properties": {
                        "entry_point": {
                            "type": ["string", "null"],
                            "description": "Where attacker input enters (null if none found)"
                        },
                        "data_flow": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Steps showing how data flows from entry to sink"
                        },
                        "sink_reached": {
                            "type": "boolean",
                            "description": "Whether attacker-controlled data reaches the vulnerable operation"
                        },
                        "attacker_control_at_sink": {
                            "type": "string",
                            "enum": ["full", "partial", "none"],
                            "description": "Level of attacker control at the dangerous operation"
                        },
                        "path_broken_at": {
                            "type": ["string", "null"],
                            "description": "Where/why the exploit path breaks (null if complete)"
                        }
                    }
                },
                "findings": {
                    "type": "array",
                    "description": "Independent target and context findings. Keep context risks separate from the target verdict.",
                    "maxItems": 16,
                    "items": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "string"},
                            "scope": {"type": "string", "enum": ["target", "context"]},
                            "relation": {"type": "string", "enum": ["primary", "secondary", "context_risk", "related"]},
                            "target_match": {"type": ["boolean", "null"]},
                            "finding": {"type": "string", "enum": ["safe", "protected", "bypassable", "vulnerable", "inconclusive"]},
                            "function_analyzed": {"type": "string"},
                            "file": {"type": "string"},
                            "line_start": {"type": "integer", "minimum": 0},
                            "line_end": {"type": "integer", "minimum": 0},
                            "vulnerability_categories": {"type": "array", "items": {"type": "string"}},
                            "impact": {"type": "array", "items": {"type": "string"}},
                            "reasoning": {"type": "string"},
                            "evidence": {"type": "array", "items": {"type": "string"}},
                            "missing_evidence": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["finding", "scope", "target_match"]
                    }
                },
                "explanation": {
                    "type": "string",
                    "description": "Detailed explanation of your analysis"
                },
                "security_weakness": {
                    "type": ["string", "null"],
                    "description": "Any dangerous patterns that exist but aren't currently exploitable (optional)"
                }
            },
            "required": ["agree", "correct_finding", "explanation"]
        }
    }
]


def _resolve_stage1_finding(result: dict) -> str:
    """Resolve a Stage-1 result's classification for verification.

    A verdict-only result (``{"verdict": "vulnerable"}`` with no ``finding``
    key) must fall back to its raw ``verdict`` before the ``inconclusive``
    default — otherwise a real VULNERABLE is silently downgraded to
    ``inconclusive`` and dropped from the report.
    """
    return str(result.get("finding") or result.get("verdict") or "inconclusive").lower()


def _more_severe(a: str, b: str) -> str:
    """Return the more-severe of two verdicts per FINDING_VERDICT_ORDER
    (index 0 = most severe). An unknown verdict ranks least-severe. Used to pick
    the surfacing verdict on a self-contradictory finish so a vuln on EITHER side
    is not dropped (FAM-REPORT-2)."""
    def _rank(v: str) -> int:
        v = str(v or "").strip().lower()
        return FINDING_VERDICT_ORDER.index(v) if v in FINDING_VERDICT_ORDER else len(FINDING_VERDICT_ORDER)
    return a if _rank(a) <= _rank(b) else b


# Stage 2 receives model-produced labels from several providers.  Keep the
# route vocabulary small and stable so that ``Unix Domain Socket``, ``UDS``
# and ``unix socket`` do not become three different boundary classes in the
# report.  This is deliberately a normalization layer, not a trust decision:
# it never promotes a finding or proves that a route is attacker controlled.
_BOUNDARY_ALIASES = {
    "binder": "binder",
    "binder_ipc": "binder",
    "binder ipc": "binder",
    "system ability": "system_ability",
    "system_ability": "system_ability",
    "sa": "system_ability",
    "idl": "idl",
    "unix": "unix_socket",
    "unix socket": "unix_socket",
    "unix domain socket": "unix_socket",
    "unix_domain_socket": "unix_socket",
    "uds": "unix_socket",
    "uds socket": "unix_socket",
    "tcp": "tcp",
    "tcp socket": "tcp",
    "udp": "udp",
    "udp socket": "udp",
    "socket": "socket",
    "napi": "napi",
    "hdf": "hdf_hdi",
    "hdi": "hdf_hdi",
    "hdf/hdi": "hdf_hdi",
    "hdf_hdi": "hdf_hdi",
    "ioctl": "ioctl",
    "file": "file",
    "file/config": "file",
    "callback": "callback",
    "event": "callback",
    "event callback": "callback",
    "event_callback": "callback",
    "event/callback": "callback",
    "queue": "queue",
    "message queue": "queue",
    "async queue": "queue",
    "cli": "cli",
    "command line": "cli",
    "command-line": "cli",
    "argv": "cli",
    "argc/argv": "cli",
    "other": "other",
}

_DIRECTION_ALIASES = {
    "inbound": "inbound",
    "in": "inbound",
    "receive": "inbound",
    "recv": "inbound",
    "read": "inbound",
    "listen": "inbound",
    "accept": "inbound",
    "outbound": "outbound",
    "out": "outbound",
    "send": "outbound",
    "write": "outbound",
    "connect": "outbound",
    "bidirectional": "bidirectional",
    "both": "bidirectional",
    "unknown": "unknown",
}

_ROUTE_EVIDENCE_ALIASES = {
    "confirmed": "confirmed",
    "verified": "confirmed",
    "source-backed": "confirmed",
    "source backed": "confirmed",
    "source_backed": "confirmed",
    "evidenced": "confirmed",
    "partial": "partial",
    "conditional": "partial",
    "incomplete": "partial",
    "missing": "missing",
    "unknown": "unknown",
}

_INPUT_RELATION_ALIASES = {
    "confirmed": "confirmed",
    "verified": "confirmed",
    "partial": "partial",
    "possible": "partial",
    "missing": "missing",
    "blocked": "blocked",
    "unknown": "unknown",
}


def _canonical_route_value(value, aliases: dict[str, str], *, limit: int = 128) -> str | None:
    """Return a bounded canonical label for model-supplied route metadata."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = " ".join(value.strip().lower().replace("-", " ").split())
    lookup = text.replace(" / ", "/")
    direct = aliases.get(lookup)
    if direct:
        return direct
    # Boundary descriptions are often composite prose rather than enum-like
    # labels (for example ``local Unix SOCK_SEQPACKET service socket`` or
    # ``tcp/udp loopback socket``).  Recognize only transport/boundary words;
    # do not infer inbound reachability or an attacker identity here.
    if aliases is _BOUNDARY_ALIASES:
        has_socket = "socket" in text or "sock_" in text
        if "tcp" in text and "udp" in text:
            return "tcp_udp_socket"
        if has_socket and "unix" in text:
            return "unix_socket"
        if has_socket and "tcp" in text:
            return "tcp"
        if has_socket and "udp" in text:
            return "udp"
        if "callback" in text or ("event" in text and "ingestion" in text):
            return "callback"
        if "argc" in text or "argv" in text or "command line" in text:
            return "cli"
        if has_socket:
            return "socket"
    return aliases.get(lookup, text.replace(" ", "_")[:limit])


@dataclass
class ExploitPath:
    """Structured exploit path analysis."""
    entry_point: Optional[str] = None
    data_flow: list = field(default_factory=list)
    sink_reached: bool = False
    attacker_control_at_sink: str = "none"  # "full", "partial", "none"
    path_broken_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "entry_point": self.entry_point,
            "data_flow": self.data_flow,
            "sink_reached": self.sink_reached,
            "attacker_control_at_sink": self.attacker_control_at_sink,
            "path_broken_at": self.path_broken_at
        }

    def is_complete(self) -> bool:
        """Check if exploit path is complete (exploitable)."""
        return (
            self.entry_point is not None and
            self.sink_reached and
            self.attacker_control_at_sink in ["full", "partial"] and
            self.path_broken_at is None
        )


@dataclass
class VerificationResult:
    """Result from Stage 2 verification."""
    agree: bool
    correct_finding: str
    explanation: str
    iterations: int
    total_tokens: int
    exploit_path: Optional[ExploitPath] = None
    security_weakness: Optional[str] = None
    # Additive inventory of independent target/context issues.  The legacy
    # correct_finding/exploit_path fields remain the primary target verdict.
    findings: list = field(default_factory=list)
    # Orthogonal evidence assessment.  ``correct_finding`` remains the
    # backwards-compatible Stage-2 verdict; this additive object prevents a
    # missing route from erasing a well-supported target defect and gives the
    # report/UI a way to explain conditional reachability.
    assessment: dict = field(default_factory=dict)
    # First-class "incomplete verification" state (PR #69 F4/F5). True on the
    # four degenerate fail-safe paths (unparseable text, no tool calls, max
    # iterations, finish-without-agree) where Stage 2 could NOT COMPLETE a
    # verdict. Distinct from a genuine disagreement: those paths keep
    # ``agree=False`` + ``correct_finding=finding`` (the Stage-1 verdict is
    # preserved, the finding stays surfaced), but downstream consumers must
    # NOT read ``agree=False`` here as "Stage 2 actively rejected". This flag
    # lets the reporter render "unverified" (not "rejected") and lets the
    # metrics bucket it as needs-review (not "safe").
    incomplete: bool = False

    def to_dict(self) -> dict:
        result = {
            "agree": self.agree,
            "correct_finding": self.correct_finding,
            "explanation": self.explanation,
            "iterations": self.iterations,
            "total_tokens": self.total_tokens
        }
        if self.exploit_path:
            result["exploit_path"] = self.exploit_path.to_dict()
        if self.security_weakness:
            result["security_weakness"] = self.security_weakness
        # Always preserve the inventory.  Incomplete/no-tool-call exits do not
        # pass through _parse_finish_result, so also synthesize the historical
        # target verdict there; this keeps a context-only/empty inventory from
        # being mistaken for the target result disappearing.
        result["findings"] = ensure_primary_record(
            list(self.findings or []), self.correct_finding
        )
        if self.assessment:
            result["assessment"] = self.assessment
        # Always serialize the incomplete flag so downstream consumers
        # (core/reporter.py, core/verifier.py) can branch on it explicitly.
        result["incomplete"] = self.incomplete
        return result


@dataclass
class ConsistencyCheckResult:
    """Result from consistency cross-check."""
    pattern_identified: str
    consistent_verdict: str
    findings_updated: list
    explanation: str

    def to_dict(self) -> dict:
        return {
            "pattern_identified": self.pattern_identified,
            "consistent_verdict": self.consistent_verdict,
            "findings_updated": self.findings_updated,
            "explanation": self.explanation
        }


class FindingVerifier:
    """Validates Stage 1 assessments using Opus with tool access."""

    def __init__(
        self,
        index: RepositoryIndex,
        binding: PhaseBinding,
        tracker: TokenTracker = None,
        verbose: bool = False,
        app_context: "ApplicationContext" = None,
        logger: logging.Logger = None,
    ):
        if not binding.adapter.supports_tools:
            raise ValueError(
                f"Stage 2 verification requires a tool-supporting adapter, "
                f"but the binding for phase {binding.phase!r} uses adapter "
                f"type {binding.adapter.name!r} which does not support tools."
            )
        self.index = index
        self.binding = binding
        self.tracker = tracker or get_global_tracker()
        self.verbose = verbose
        self.app_context = app_context
        self.tool_executor = ToolExecutor(index)
        # ``verify_batch`` runs findings in parallel.  ToolExecutor keeps the
        # current unit's static callers/callees, so sharing one mutable
        # instance would mix graph context between workers.  Keep a per-thread
        # executor while retaining ``tool_executor`` as a backwards-compatible
        # fallback for direct/single-unit callers and tests.
        self._tool_local = threading.local()
        self.logger = logger or _null_logger
        self._use_logger = logger is not None

        # Build typed tool defs once per verifier instance.
        self._tool_defs: list[ToolDef] = [
            ToolDef(
                name=td["name"],
                description=td["description"],
                input_schema=td["input_schema"],
            )
            for td in VERIFICATION_TOOLS
        ]

    def _log(self, level: str, msg: str, **extras):
        """Log a message, using logger if available, otherwise print if verbose."""
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        elif self.verbose:
            # Fallback to print for CLI usage
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"    {msg} {suffix}" if suffix else f"    {msg}")

    def _platform_context_for_route(self, route_key: str):
        """Return static platform metadata for one indexed function.

        Analyzer output historically used camelCase (``platformContext``),
        while dataset units use snake_case.  Accept both forms so Stage 2 can
        read current and migrated analyzer outputs without changing the
        repository index contract.  The prompt renderer performs the actual
        allow-listing and bounds checks.
        """
        if not isinstance(route_key, str) or not route_key:
            return None
        function = self.index.get_function(route_key)
        if not isinstance(function, dict):
            return None
        context = function.get("platformContext")
        if context is None:
            context = function.get("platform_context")
        return context

    def _set_tool_context_for_route(self, route_key: str) -> None:
        """Expose parser-resolved graph neighbors to the Stage-2 tools."""
        graph_key = route_key
        normalize = getattr(self.index, "_normalize_graph_id", None)
        if callable(normalize):
            graph_key = normalize(route_key) or route_key
        deps = getattr(self.index, "call_graph", {}).get(graph_key, [])
        callers = getattr(self.index, "reverse_call_graph", {}).get(graph_key, [])
        executor = ToolExecutor(self.index)
        executor.set_unit_context(
            deps if isinstance(deps, list) else [],
            callers if isinstance(callers, list) else [],
            route_key=route_key,
        )
        self._tool_local.executor = executor

    def verify_result(
        self,
        code: str,
        finding: str,
        attack_vector: str,
        reasoning: str,
        files_included: list = None,
        platform_context: dict | None = None,
        route: str | None = None,
        stage1_context: dict | None = None,
        stage1_findings: list | None = None,
    ) -> VerificationResult:
        """
        Validate a Stage 1 assessment with exploit path tracing.

        Args:
            code: The code that was assessed
            finding: Stage 1's finding
            attack_vector: Stage 1's attack vector
            reasoning: Stage 1's reasoning
            files_included: Optional list of files in context
            platform_context: Optional bounded OpenHarmony unit metadata
            route: Optional source/function route key for route-aware review
            stage1_context: Optional phase-separated structural context and
                pending Stage-2 data-flow gaps from the analyze result.
            stage1_findings: Optional additive inventory of independent
                Stage-1 target/context findings.

        Returns:
            VerificationResult with verdict, exploit path, and explanation
        """
        user_prompt = get_verification_prompt(
            code=code,
            finding=finding,
            attack_vector=attack_vector,
            reasoning=reasoning,
            files_included=files_included,
            app_context=self.app_context,
            platform_context=platform_context,
            route=route,
            stage1_context=stage1_context,
            stage1_findings=stage1_findings,
        )

        # Direct callers (including legacy experiment.py integrations) do not
        # pass through ``_verify_one``. Install route-specific graph context
        # here too. Reinstalling for every explicit route is intentional: a
        # thread may verify several units sequentially and a stale executor
        # would expose the previous unit's callers/callees.
        if route:
            self._set_tool_context_for_route(route)
        tool_executor = getattr(self._tool_local, "executor", self.tool_executor)

        # Get system prompt with app context if available
        system_prompt = get_verification_system_prompt(self.app_context)

        messages: list[Message] = [
            Message(role="user", content=[TextBlock(user_prompt)])
        ]
        iterations = 0
        total_input_tokens = 0
        total_output_tokens = 0

        while iterations < MAX_ITERATIONS:
            iterations += 1

            self._log("debug", f"Iteration {iterations}", iterations=iterations)

            # Adapter handles the rate-limiter wait/report dance internally.
            response = self.binding.adapter.complete(
                model=self.binding.model,
                max_tokens=MAX_TOKENS_PER_RESPONSE,
                system=system_prompt,
                tools=self._tool_defs,
                messages=messages,
            )

            total_input_tokens += response.input_tokens
            total_output_tokens += response.output_tokens

            assistant_content = response.content
            stop_reason = response.stop_reason

            # If model finished without calling finish tool, try to parse response
            if stop_reason == "end_turn":
                result = self._try_parse_text_response(
                    assistant_content, finding, iterations,
                    total_input_tokens, total_output_tokens
                )
                if result:
                    return result

                # Fail-safe (R4-7): a degenerate path must NOT auto-agree with
                # Stage 1 (that reads downstream as "Verification agreed" — a
                # silent rubber-stamp for a security verifier). Mark agree=False
                # so it never reads as agreed/clean, but PRESERVE the Stage-1
                # verdict in correct_finding so the finding stays surfaced:
                # the agree=False consumer (:644-651, experiment.py:775-778)
                # sets result["finding"] = correct_finding, and the report
                # filters on that field — using "inconclusive" here would drop
                # a Stage-1 "vulnerable" from the report entirely.
                # C(a): record spend on this degenerate exit too — the three sibling
                # degenerate paths (finish, no-tool-calls, max-iterations) all record,
                # this one alone did not, undercounting the unit's tokens/cost.
                self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                )
                return VerificationResult(
                    agree=False,
                    correct_finding=finding,
                    explanation="Verification incomplete",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    incomplete=True,
                )

            # Process tool calls
            tool_results: list[ToolResultBlock] = []
            finish_result = None

            for block in assistant_content:
                if isinstance(block, ToolUseBlock):
                    tool_name = block.name
                    tool_input = block.input
                    tool_use_id = block.id

                    self._log("debug", f"Tool call: {tool_name}")

                    if tool_name == "finish":
                        finish_result = tool_input
                        tool_results.append(
                            ToolResultBlock(
                                tool_use_id=tool_use_id,
                                name=tool_name,
                                content=json.dumps({"status": "complete"}),
                            )
                        )
                        break
                    else:
                        outcome = tool_executor.execute(tool_name, tool_input)
                        tool_results.append(
                            ToolResultBlock(
                                tool_use_id=tool_use_id,
                                name=tool_name,
                                content=json.dumps(outcome),
                            )
                        )

            # A finish call on a turn the model TRUNCATED (stop_reason == "max_tokens")
            # is not a trustworthy completed verdict: a well-formed
            # finish(agree=False, "safe") from a cut-off turn would silently downgrade a
            # Stage-1 vulnerable. Treat it as verification-incomplete (preserve the
            # Stage-1 verdict for triage) — honoring the adapter's truncation signal
            # (the responses/chat paths relabel abnormal terminations to "max_tokens")
            # rather than reading a truncated reply as a clean verdict.
            if finish_result and stop_reason == "max_tokens":
                self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                )
                return VerificationResult(
                    agree=False,
                    correct_finding=finding,
                    explanation="Verification incomplete (finish call truncated at max_tokens)",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    incomplete=True,
                )

            if finish_result:
                self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                )
                return self._parse_finish_result(
                    finish_result, finding, iterations,
                    total_input_tokens + total_output_tokens
                )

            # Echo only the block kinds the loop consumes (Text + ToolUse);
            # a future 4th block kind would otherwise throw when the next
            # turn re-serializes the assistant history.
            echoed = [b for b in assistant_content if isinstance(b, (TextBlock, ToolUseBlock))]
            messages.append(Message(role="assistant", content=echoed))
            # Mirror the enhancer's guard: an empty tool_results turn (the
            # model truncated at max_tokens / stop_sequence before any tool
            # call) would send an empty-content user message, which the next
            # complete() rejects. Treat it as verification-incomplete.
            if not tool_results:
                self.tracker.record_call(
                    model=self.binding.model,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    pricing=lookup_pricing(self.binding),
                )
                # Fail-safe (R4-7): see the :380 path above. Don't auto-agree;
                # keep the Stage-1 verdict surfaced for human triage.
                return VerificationResult(
                    agree=False,
                    correct_finding=finding,
                    explanation="Verification incomplete (no tool calls)",
                    iterations=iterations,
                    total_tokens=total_input_tokens + total_output_tokens,
                    incomplete=True,
                )
            messages.append(Message(role="user", content=list(tool_results)))

        # Max iterations reached
        self.tracker.record_call(
            model=self.binding.model,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            pricing=lookup_pricing(self.binding),
        )
        # Fail-safe (R4-7): exhausting the iteration budget is not agreement.
        # Don't auto-agree; keep the Stage-1 verdict surfaced for human triage.
        return VerificationResult(
            agree=False,
            correct_finding=finding,
            explanation="Max iterations reached",
            iterations=iterations,
            total_tokens=total_input_tokens + total_output_tokens,
            incomplete=True,
        )

    def verify_batch(
        self,
        results: list,
        code_by_route: dict,
        progress_callback: Optional[Callable] = None,
        workers: int = 10,
        checkpoint=None,
        restored_callback: Optional[Callable] = None,
    ) -> list:
        """
        Verify a batch of results with consistency cross-check.

        Uses ThreadPoolExecutor for parallel verification when workers > 1.
        Supports checkpoint/resume via the checkpoint parameter.

        Args:
            results: List of Stage 1 results to verify
            code_by_route: Dict mapping route_key to code
            progress_callback: Optional callback(unit_id, detail, unit_elapsed)
                called after each finding is verified.
            workers: Number of parallel workers (default: 10).
            checkpoint: Optional StepCheckpoint instance for resume support.
            restored_callback: Optional callback(count) called after checkpoint
                loading with the number of restored units.

        Returns:
            Updated results with verification and consistency check
        """
        total = len(results)

        # Load checkpoint state
        checkpointed = {}
        if checkpoint is not None:
            checkpointed = checkpoint.load()

        def _cp_is_error(cp_data):
            """A verify checkpoint is errored if verification is missing/empty
            or correct_finding == 'error'."""
            if not cp_data:
                return True
            v = cp_data.get("verification", {})
            if not isinstance(v, dict) or not v:
                return True
            return v.get("correct_finding") == "error"

        # Separate already-done (successful) from to-do (new + errored)
        results_to_verify = []
        _restored_ok = 0
        for r in results:
            key = r.get("unit_id") or r.get("route_key", "unknown")
            cp_data = checkpointed.get(key)
            if cp_data and not _cp_is_error(cp_data):
                # Restore verification data from checkpoint
                if "verification" in cp_data:
                    r["verification"] = cp_data["verification"]
                if "finding" in cp_data:
                    r["finding"] = cp_data["finding"]
                if "verification_note" in cp_data:
                    r["verification_note"] = cp_data["verification_note"]
                _restored_ok += 1
            else:
                # Either no checkpoint, or an errored one — re-verify
                results_to_verify.append(r)

        if _restored_ok:
            print(f"[Verify] Restored {_restored_ok} findings from checkpoints",
                  file=sys.stderr, flush=True)
            if restored_callback:
                restored_callback(_restored_ok)
        errored_retries = len(checkpointed) - _restored_ok
        if errored_retries:
            print(f"[Verify] Retrying {errored_retries} previously errored findings",
                  file=sys.stderr, flush=True)

        # Initialize summary tracking for _summary.json
        _summary_completed = _restored_ok
        _summary_errors = 0
        _summary_error_breakdown = {}
        _summary_input_tokens = 0
        _summary_output_tokens = 0
        _summary_cost_usd = 0.0

        # Sum usage from ALL existing checkpoints (including errored ones
        # — their cost was already spent in a prior run)
        for _key, _cp in checkpointed.items():
            _cp_usage = _cp.get("usage", {})
            _summary_input_tokens += _cp_usage.get("input_tokens", 0)
            _summary_output_tokens += _cp_usage.get("output_tokens", 0)
            _summary_cost_usd += _cp_usage.get("cost_usd", 0.0)

        def _usage_dict():
            return {"input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6)}

        # Inject prior usage into tracker so step_report captures the total
        if _summary_input_tokens or _summary_output_tokens:
            self.tracker.add_prior_usage(
                _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)

        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="in_progress",
                                     usage=_usage_dict())

        def _summary_callback(detail, usage=None):
            """Update summary counters after each unit. Called from main thread."""
            nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
            nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
            if detail == "error":
                _summary_errors += 1
                _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
            else:
                _summary_completed += 1
            if usage:
                _summary_input_tokens += usage.get("input_tokens", 0)
                _summary_output_tokens += usage.get("output_tokens", 0)
                _summary_cost_usd += usage.get("cost_usd", 0.0)
            if checkpoint is not None:
                checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                         _summary_error_breakdown, phase="in_progress",
                                         usage=_usage_dict())

        remaining = len(results_to_verify)
        mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
        print(f"[Verify] Mode: {mode}, {remaining} findings to verify "
              f"({len(checkpointed)} already done)", file=sys.stderr, flush=True)

        if workers <= 1:
            self._verify_batch_sequential(
                results_to_verify, code_by_route, progress_callback, checkpoint,
                summary_callback=_summary_callback)
        else:
            self._verify_batch_parallel(
                results_to_verify, code_by_route, progress_callback, workers, checkpoint,
                summary_callback=_summary_callback)

        # Write final summary with phase="done"
        if checkpoint is not None:
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="done",
                                     usage=_usage_dict())

        # Step 2: Consistency cross-check (barrier — needs all results)
        results = self._check_consistency(results, code_by_route)

        return results

    def _verify_one(self, result, code_by_route):
        """Verify a single result. Returns (route_key, detail, elapsed, worker, usage).

        Mutates the result dict in-place (each result is unique, no contention).
        """
        route_key = result.get("route_key", "unknown")
        stage1_finding = _resolve_stage1_finding(result)
        worker = threading.current_thread().name

        self.tracker.start_unit_tracking()
        unit_start = time.monotonic()
        detail = ""
        try:
            self._set_tool_context_for_route(route_key)
            code = code_by_route.get(route_key, "")
            # Prefer static analyzer metadata over result fields, because the
            # result itself contains model-controlled values.  Both values are
            # still normalized by PlatformPromptContext before rendering.
            platform_context = self._platform_context_for_route(route_key)
            if platform_context is None:
                platform_context = result.get("platformContext")
            if platform_context is None:
                platform_context = result.get("platform_context")
            verification = self.verify_result(
                code=code,
                finding=stage1_finding,
                attack_vector=result.get("attack_vector"),
                reasoning=result.get("reasoning", ""),
                files_included=result.get("files_included", []),
                platform_context=platform_context,
                route=route_key,
                stage1_context=result.get("stage_context") or {
                    "stage1": result.get("stage1_context", {}),
                    "stage2": result.get("stage2_context", {}),
                },
                stage1_findings=result.get("findings"),
            )

            result["verification"] = verification.to_dict()
            # Preserve the pre-verification verdict so Stage 2 can distinguish
            # an inconclusive result that was promoted/resolved from an ordinary
            # vulnerable/bypassable disagreement.  This is also persisted in
            # checkpoints and keeps outcome metrics auditable after write-back.
            result["verification"]["stage1_finding"] = stage1_finding

            if verification.agree:
                detail = f"agreed:{verification.correct_finding}"
                self._log("info", f"Verification agreed: {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)
            else:
                detail = f"disagreed:{stage1_finding}->{verification.correct_finding}"
                result["finding"] = verification.correct_finding
                result["verification_note"] = f"Changed from {stage1_finding} to {verification.correct_finding}"
                self._log("info", f"Verification disagreed: {stage1_finding} -> {verification.correct_finding}",
                          unit_id=route_key, total_tokens=verification.total_tokens,
                          iterations=verification.iterations)

        except Exception as e:
            detail = "error"
            # L4 (PR #69 round-5): record the error ON the result dict, not just
            # in the local ``detail``. The downstream counter (core/verifier.py)
            # buckets on ``r.get("error")``; without this the errored finding
            # falls through to "disagreed" and is folded into the ``safe`` count.
            # Fail-safe: an adapter raise (e.g. R4-1/R4-2 empty/refusal) must
            # NEVER read as safe — it is unverified and needs manual review.
            err_msg = f"{type(e).__name__}: {e}"
            result["error"] = err_msg
            # Surface a minimal verification dict marked incomplete so any
            # consumer that branches on ``verification.incomplete`` also treats
            # it as needs-review rather than a clean verdict.
            result.setdefault("verification", {})
            result["verification"]["incomplete"] = True
            result["verification"]["stage1_finding"] = stage1_finding
            result["verification_note"] = f"Verification errored: {err_msg}"
            print(f"[Verify] ERROR {route_key}: {err_msg}", file=sys.stderr, flush=True)

        unit_elapsed = time.monotonic() - unit_start
        usage = self.tracker.get_unit_usage()
        return route_key, detail, unit_elapsed, worker, usage

    def _verify_batch_sequential(self, results, code_by_route, progress_callback,
                                 checkpoint=None, summary_callback=None):
        """Verify all results sequentially."""
        try:
            for i, result in enumerate(results):
                route_key = result.get("route_key", "unknown")
                stage1_finding = _resolve_stage1_finding(result)
                self._log("info", f"Verifying finding {i+1}/{len(results)}",
                          unit_id=route_key, classification=stage1_finding)

                route_key, detail, unit_elapsed, _worker, usage = self._verify_one(result, code_by_route)
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, detail, unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — progress saved to checkpoints",
                  file=sys.stderr, flush=True)

    def _verify_batch_parallel(self, results, code_by_route, progress_callback, workers,
                                checkpoint=None, summary_callback=None):
        """Verify all results in parallel using ThreadPoolExecutor."""
        executor = ThreadPoolExecutor(max_workers=workers)
        future_to_result = {}
        for result in results:
            future = executor.submit(self._verify_one, result, code_by_route)
            future_to_result[future] = result

        try:
            for future in as_completed(future_to_result):
                result = future_to_result[future]
                route_key, detail, unit_elapsed, worker, usage = future.result()
                if checkpoint is not None:
                    key = result.get("unit_id") or route_key
                    cp_data = {
                        "verification": result.get("verification", {}),
                        "finding": result.get("finding", ""),
                        "verification_note": result.get("verification_note", ""),
                    }
                    if usage:
                        cp_data["usage"] = usage
                    checkpoint.save(key, cp_data)
                if summary_callback:
                    summary_callback(detail, usage=usage)
                if progress_callback:
                    progress_callback(route_key, f"{detail}  [{worker}]", unit_elapsed)
        except KeyboardInterrupt:
            print("[Verify] Interrupted — cancelling pending work...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            print("[Verify] Progress saved to checkpoints",
                  file=sys.stderr, flush=True)
            return
        executor.shutdown(wait=False)

    def _check_consistency(
        self,
        results: list,
        code_by_route: dict
    ) -> list:
        """
        Check for inconsistent verdicts among similar code patterns.

        Groups findings by code pattern similarity and ensures consistent verdicts.

        IMPORTANT: Does NOT override findings that have conclusive exploit path analysis
        showing the path is broken (sink_reached=false, attacker_control=none, or path_broken_at set).
        """
        # Group by vulnerability pattern (simplified: by file and function type)
        pattern_groups = self._group_by_pattern(results)

        inconsistent_groups = []
        for pattern, group in pattern_groups.items():
            if len(group) < 2:
                continue

            verdicts = set(r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group)
            if len(verdicts) > 1:
                inconsistent_groups.append((pattern, group))

        if not inconsistent_groups:
            self._log("info", "Consistency check: All similar patterns have consistent verdicts")
            return results

        # Fix inconsistencies
        for pattern, group in inconsistent_groups:
            verdicts = [r.get("verification", {}).get("correct_finding") or r.get("finding") for r in group]
            self._log("warning", f"Inconsistency detected in pattern: {pattern}",
                      details={"findings": [r.get('route_key') for r in group], "verdicts": verdicts})

            # Run consistency check
            consistency_result = self._resolve_inconsistency(group, code_by_route)

            if consistency_result:
                # Apply consistent verdict, but respect exploit path analysis
                for finding_update in consistency_result.findings_updated:
                    route_key = finding_update.get("route_key")
                    new_verdict = finding_update.get("should_be")

                    for result in results:
                        if result.get("route_key") == route_key:
                            # Check if this result has conclusive exploit path analysis
                            if self._has_conclusive_exploit_path(result):
                                self._log("debug", f"Skipping {route_key}: has conclusive exploit path analysis",
                                          unit_id=route_key)
                                continue

                            # F-KB-1b: a conclusively-exploitable finding must not be
                            # silently downgraded to ANY disclosure-dropping verdict by
                            # pattern matching (mirror of the conclusive-broken guard
                            # above). The block-set MUST reference
                            # core.verdict_taxonomy.DISCLOSURE_DROPPED directly rather
                            # than a hardcoded {safe, protected}: the original guard
                            # covered only {safe, protected} while DISCLOSURE_DROPPED also
                            # contains {inconclusive, rejected}, so a downgrade to
                            # inconclusive/rejected silently dropped the finding from
                            # disclosure (an identical security false-negative) while
                            # bypassing the guard. Referencing the canonical set keeps the
                            # two from drifting apart again — that drift WAS the bug.
                            if (self._has_conclusive_exploitable_path(result)
                                    and str(new_verdict or "").strip().lower() in DISCLOSURE_DROPPED):
                                self._log("warning",
                                          f"Blocked consistency downgrade of conclusively-exploitable {route_key} -> {new_verdict}",
                                          unit_id=route_key)
                                result["consistency_downgrade_blocked"] = {
                                    "proposed": new_verdict,
                                    "reason": finding_update.get("reason"),
                                    "pattern": consistency_result.pattern_identified,
                                }
                                continue

                            old_verdict = result.get("verification", {}).get("correct_finding") or result.get("finding")
                            if old_verdict != new_verdict:
                                result["finding"] = new_verdict
                                if "verification" not in result:
                                    result["verification"] = {}
                                result["verification"]["correct_finding"] = new_verdict
                                result["consistency_update"] = {
                                    "from": old_verdict,
                                    "to": new_verdict,
                                    "reason": finding_update.get("reason"),
                                    "pattern": consistency_result.pattern_identified
                                }
                                self._log("info", f"Consistency update: {old_verdict} -> {new_verdict}",
                                          unit_id=route_key)

        return results

    def _has_conclusive_exploit_path(self, result: dict) -> bool:
        """
        Check if a result has conclusive exploit path analysis that should not be overridden.

        A conclusive exploit path analysis is one where:
        1. The exploit path was analyzed (not just max iterations reached)
        2. The path shows either:
           - sink_reached = false (attacker data doesn't reach the sink)
           - attacker_control_at_sink = "none" (no control at sink)
           - path_broken_at is set (explicit explanation of where path breaks)

        These findings are based on detailed code analysis and should not be
        overridden by superficial pattern matching.
        """
        verification = result.get("verification", {})

        # If max iterations was reached, the analysis is not conclusive
        if verification.get("explanation") == "Max iterations reached":
            return False

        # Check for exploit path analysis. A model may emit ``exploit_path``
        # as a truthy non-dict (e.g. the bare string "reached"); the ``.get``
        # calls below would then raise AttributeError. Treat any non-dict as
        # not-conclusive, matching a missing exploit_path.
        exploit_path = verification.get("exploit_path")
        if not isinstance(exploit_path, dict):
            return False

        # Check if the exploit path analysis shows the path is broken
        sink_reached = exploit_path.get("sink_reached", True)
        attacker_control = exploit_path.get("attacker_control_at_sink", "unknown")
        path_broken_at = exploit_path.get("path_broken_at")

        # Conclusive if: path is broken OR sink not reached OR no attacker control
        if not sink_reached:
            return True
        if attacker_control == "none":
            return True
        if path_broken_at:
            return True

        return False

    def _has_conclusive_exploitable_path(self, result: dict) -> bool:
        """Mirror of _has_conclusive_exploit_path: True when analysis conclusively
        shows the path IS reachable, attacker-controlled, and unbroken. Defaults
        require proof — a missing field must NOT read as exploitable."""
        verification = result.get("verification", {})
        if verification.get("explanation") == "Max iterations reached":
            return False
        exploit_path = verification.get("exploit_path")
        if not isinstance(exploit_path, dict):
            return False
        sink_reached = exploit_path.get("sink_reached", False)
        attacker_control = exploit_path.get("attacker_control_at_sink", "none")
        path_broken_at = exploit_path.get("path_broken_at")
        return bool(sink_reached) and attacker_control in ("full", "partial") and not path_broken_at

    def _group_by_pattern(self, results: list) -> dict:
        """Group results by code pattern for consistency checking."""
        groups = {}

        for result in results:
            # Extract pattern key from route_key
            route_key = result.get("route_key", "")

            # Group by file and function signature pattern
            # e.g., "pkg/logger/console.go:*Msg.json" groups all json methods
            if ":" in route_key:
                file_part, func_part = route_key.rsplit(":", 1)

                # Normalize function name to find similar patterns
                # e.g., "errorMsg.json" and "infoMsg.json" -> "*Msg.json"
                normalized_func = re.sub(r'^[a-z]+Msg', '*Msg', func_part)
                pattern_key = f"{file_part}:{normalized_func}"
            else:
                pattern_key = route_key

            if pattern_key not in groups:
                groups[pattern_key] = []
            groups[pattern_key].append(result)

        return groups

    def _resolve_inconsistency(
        self,
        group: list,
        code_by_route: dict
    ) -> Optional[ConsistencyCheckResult]:
        """
        Use LLM to resolve inconsistent verdicts for similar code patterns.
        """
        prompt = get_consistency_check_prompt(group, code_by_route)

        try:
            # Adapter handles rate-limit coordination internally.
            from .llm import simple_text

            text = simple_text(
                self.binding,
                prompt,
                system="You are checking verdict consistency across similar code patterns.",
                max_tokens=MAX_TOKENS_PER_RESPONSE,
                tracker=self.tracker,
            )
            result = self._parse_json_from_text(text)

            if result:
                return ConsistencyCheckResult(
                    pattern_identified=result.get("pattern_identified", "unknown"),
                    consistent_verdict=result.get("consistent_verdict", "inconclusive"),
                    findings_updated=result.get("findings_to_update", []),
                    explanation=result.get("explanation", "")
                )

        except LLMRateLimitError as e:
            # Adapter already reported the 429; just log it locally.
            self._log("error", f"Consistency resolution rate limited", error=str(e))
        except Exception as e:
            self._log("error", f"Consistency resolution failed", error=str(e))

        return None

    def _parse_finish_result(
        self,
        finish_result: dict,
        original_finding: str,
        iterations: int,
        total_tokens: int
    ) -> VerificationResult:
        """Parse the finish tool result into VerificationResult."""
        if not isinstance(finish_result, dict):
            # Non-Anthropic adapters can hand back a scalar/list as tool
            # arguments. Treat it as an incomplete finish instead of raising
            # while parsing and losing the audit record entirely.
            finish_result = {}
        # Parse the orthogonal assessment if present.  Older models do not
        # emit it, so missing/invalid values are simply omitted and the legacy
        # ``correct_finding`` path remains authoritative.  Values are bounded
        # and allow-listed because finish arguments are model supplied.
        raw_assessment = finish_result.get("assessment")
        # A few providers flatten optional tool fields despite the nested
        # schema. Accept those fields as a compatibility fallback while
        # keeping the same allow-list/bounds in ``_parse_assessment``.
        if not isinstance(raw_assessment, dict):
            flattened = {
                key: finish_result.get(key)
                for key in (
                    "defect_status", "reachability_status", "impact_status",
                    "evidence_completeness", "boundary_type",
                    "direction", "source_evidence_status",
                    "registration_evidence", "endpoint", "input_relation",
                    "missing_evidence", "confidence",
                )
                if key in finish_result
            }
            raw_assessment = flattened
        assessment = self._parse_assessment(raw_assessment)

        # Parse exploit path if present
        exploit_path = None
        # FAM-ROBUST: finish_result is raw model tool-args; only treat
        # exploit_path as structured when it is actually a dict. A non-dict
        # (str/list/int from a non-Anthropic model) has no path fields — skip
        # it (normalized to None) instead of crashing on ep.get(...).
        ep = finish_result.get("exploit_path")
        if isinstance(ep, dict) and ep:
            entry_point = ep.get("entry_point")
            if not isinstance(entry_point, str):
                entry_point = None
            raw_flow = ep.get("data_flow", [])
            if isinstance(raw_flow, str):
                raw_flow = [raw_flow]
            data_flow = (
                [item.strip()[:2_000] for item in raw_flow
                 if isinstance(item, str) and item.strip()][:24]
                if isinstance(raw_flow, (list, tuple)) else []
            )
            sink_reached = ep.get("sink_reached", False)
            if isinstance(sink_reached, str):
                sink_reached = sink_reached.strip().lower() == "true"
            else:
                sink_reached = bool(sink_reached) if isinstance(sink_reached, bool) else False
            control = ep.get("attacker_control_at_sink", "none")
            if control not in ("full", "partial", "none"):
                control = "none"
            broken = ep.get("path_broken_at")
            if not isinstance(broken, str) or not broken.strip():
                broken = None
            else:
                broken = broken.strip()[:2_000]
            exploit_path = ExploitPath(
                entry_point=entry_point,
                data_flow=data_flow,
                sink_reached=sink_reached,
                attacker_control_at_sink=control,
                path_broken_at=broken,
            )

        # Fail-safe (R4-7): a `finish` call that omits `agree` must NOT
        # default to agreement — an absent field is not a confirmed verdict.
        # Default to False so it can never silently read as "Verification
        # agreed"; correct_finding still falls back to the Stage-1 verdict,
        # keeping the finding surfaced.
        #
        # F4/F5: an absent `agree` is the fourth degenerate path — the model
        # finished without asserting a verdict, so the verification did NOT
        # COMPLETE. Mark it incomplete so downstream reads "unverified" /
        # needs-review rather than "rejected" / "safe". A finish call that DOES
        # carry `agree` (True or False) is a real, completed verdict and stays
        # incomplete=False.
        agree_missing = "agree" not in finish_result
        raw_agree = finish_result.get("agree", False)
        if isinstance(raw_agree, bool):
            agree = raw_agree
        elif isinstance(raw_agree, str) and raw_agree.strip().lower() in ("true", "false"):
            agree = raw_agree.strip().lower() == "true"
        else:
            # A malformed agreement must never be interpreted as truthy. Mark
            # it incomplete so it remains visible for review rather than
            # silently becoming an active rejection/agreement.
            agree = False
            agree_missing = True
        valid_findings = {"safe", "protected", "bypassable", "vulnerable", "inconclusive"}
        raw_correct_finding = finish_result.get("correct_finding", original_finding)
        correct_finding = (
            raw_correct_finding.strip().lower()
            if isinstance(raw_correct_finding, str)
            else str(original_finding or "inconclusive").strip().lower()
        )
        if correct_finding not in valid_findings:
            correct_finding = str(original_finding or "inconclusive").strip().lower()
            if correct_finding not in valid_findings:
                correct_finding = "inconclusive"
            agree = False
            agree_missing = True
        incomplete = agree_missing

        # FAM-REPORT-2: a self-contradictory finish — `agree=True` (claims to
        # agree with Stage-1) while `correct_finding` diverges from the Stage-1
        # verdict — is NOT a clean agreement. The `finish` schema declares the
        # two fields independently (no cross-field constraint), so a model can
        # emit it. Reading it as agreed leaves result["finding"] at the Stage-1
        # verdict (the write-back consumers only propagate correct_finding on the
        # disagree branch), so an UPGRADE contradiction (stage1=safe,
        # correct_finding=vulnerable) silently DROPS the vuln at the reporter's
        # disclosure filter. Surface it: treat as a disagreement toward the
        # MORE-SEVERE verdict (so a vuln on either side is never dropped, and a
        # downgrade cannot silence a real Stage-1 vuln) and flag incomplete so
        # the reporter renders "unverified" (needs manual review), not "agreed".
        # Mirrors this file's R4-7 fail-safe philosophy (abnormal signal ->
        # surface, don't silently resolve).
        if agree and str(correct_finding or "").strip().lower() != str(original_finding or "").strip().lower():
            correct_finding = _more_severe(original_finding, correct_finding)
            agree = False
            incomplete = True

        explanation = finish_result.get("explanation", "")
        if not isinstance(explanation, str):
            explanation = str(explanation)[:8_000]
        weakness = finish_result.get("security_weakness")
        if not isinstance(weakness, str):
            weakness = None
        elif weakness:
            weakness = weakness[:8_000]

        # Preserve every independently described issue.  Older verifier
        # responses do not contain ``findings``; synthesize a target-primary
        # record so the new consumer can adopt the additive field without
        # invalidating historical checkpoints.  Context records are never
        # promoted to the legacy ``correct_finding`` verdict here.
        independent_findings = normalize_findings(
            finish_result.get("findings"),
            primary_finding=correct_finding,
            synthesize_primary=True,
        )
        independent_findings = ensure_primary_record(
            independent_findings, correct_finding
        )

        return VerificationResult(
            agree=agree,
            correct_finding=correct_finding,
            explanation=explanation,
            iterations=iterations,
            total_tokens=total_tokens,
            exploit_path=exploit_path,
            security_weakness=weakness,
            findings=independent_findings,
            assessment=assessment,
            incomplete=incomplete,
        )

    @staticmethod
    def _parse_assessment(value) -> dict:
        """Normalize optional defect, route, and impact evidence fields.

        ``assessment`` is model supplied metadata.  The parser canonicalizes
        aliases for reporting and downstream grouping, but deliberately does
        not infer a route from a function name or upgrade a verdict.  A route
        remains usable only when the verifier supplied source evidence and an
        explicit inbound/conditional assessment.
        """
        if not isinstance(value, dict):
            return {}
        allowed = {
            "defect_status": {"confirmed", "suspected", "none", "unknown"},
            "reachability_status": {"confirmed", "conditional", "unknown", "none"},
            "impact_status": {"confirmed", "plausible", "unknown", "none"},
            "evidence_completeness": {"complete", "partial", "missing"},
            "parameter_dataflow_status": {
                "confirmed", "partial", "missing", "blocked", "not_evaluated"
            },
        }
        result = {}
        for key, values in allowed.items():
            item = value.get(key)
            if isinstance(item, str) and item.strip().lower() in values:
                result[key] = item.strip().lower()
        boundary = value.get("boundary_type")
        if isinstance(boundary, str) and boundary.strip():
            result["boundary_type"] = _canonical_route_value(
                boundary, _BOUNDARY_ALIASES
            )
        direction = _canonical_route_value(value.get("direction"), _DIRECTION_ALIASES)
        if direction:
            result["direction"] = direction
        source_status = _canonical_route_value(
            value.get("source_evidence_status"), _ROUTE_EVIDENCE_ALIASES
        )
        if source_status in {"confirmed", "partial", "missing", "unknown"}:
            result["source_evidence_status"] = source_status
        input_relation = _canonical_route_value(
            value.get("input_relation"), _INPUT_RELATION_ALIASES
        )
        if input_relation in {"confirmed", "partial", "missing", "blocked", "unknown"}:
            result["input_relation"] = input_relation
        registration = value.get("registration_evidence")
        if registration is None:
            # Providers occasionally call this field listener_evidence or
            # route_evidence.  Accept those aliases without treating them as
            # proof; keeping the evidence text is useful for audit output.
            registration = value.get("listener_evidence")
        if isinstance(registration, str):
            registration = [registration]
        if isinstance(registration, (list, tuple)):
            result["registration_evidence"] = [
                item.strip()[:1_000]
                for item in registration[:8]
                if isinstance(item, str) and item.strip()
            ]
        endpoint = value.get("endpoint")
        if isinstance(endpoint, str) and endpoint.strip():
            result["endpoint"] = endpoint.strip()[:512]
        missing = value.get("missing_evidence")
        if isinstance(missing, (list, tuple)):
            result["missing_evidence"] = [
                item.strip()[:500]
                for item in missing[:12]
                if isinstance(item, str) and item.strip()
            ]
        confidence = value.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            if 0.0 <= float(confidence) <= 1.0:
                result["confidence"] = float(confidence)
        return result

    def _try_parse_text_response(
        self,
        assistant_content: list,
        original_finding: str,
        iterations: int,
        total_input_tokens: int,
        total_output_tokens: int
    ) -> Optional[VerificationResult]:
        """Try to parse a text response as JSON."""
        for block in assistant_content:
            if isinstance(block, TextBlock):
                result = self._parse_json_from_text(block.text)
                if result:
                    self.tracker.record_call(
                        model=self.binding.model,
                        input_tokens=total_input_tokens,
                        output_tokens=total_output_tokens,
                        pricing=lookup_pricing(self.binding),
                    )
                    return self._parse_finish_result(
                        result, original_finding, iterations,
                        total_input_tokens + total_output_tokens
                    )
        return None

    def _parse_json_from_text(self, text: str) -> Optional[dict]:
        """Extract JSON object from text, with LLM correction fallback."""
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

        # Fallback: use LLM to correct malformed JSON. Pass the verifier's
        # `finish` schema so the corrector recovers verifier shape (no verdict)
        # instead of rewriting it into the vuln verdict schema — otherwise a
        # perfectly-extractable verification is rejected by the verdict-only
        # success gate and the finding is silently dropped.
        if text.strip():
            try:
                from utilities.json_corrector import JSONCorrector
                corrector = JSONCorrector(self.binding)
                corrected = corrector.attempt_correction(
                    text,
                    schema=_VERIFY_JSON_SCHEMA,
                    required_keys=["agree", "correct_finding", "explanation"],
                )
                if corrected.get("verdict") != "ERROR":
                    corrected["json_corrected"] = True
                    return corrected
            except Exception:
                pass
        return None
