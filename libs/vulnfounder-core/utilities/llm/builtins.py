"""The frozen ``vulnfounder-default`` llm-config.

Properties (per plan §7):

* **Source-defined, not on disk.** ``vulnfounder-default`` is the
  baked-in baseline that always resolves, even on a fresh install
  with no config.json.
* **Immutable.** ``parse_config()`` rejects any user attempt to
  redefine it. Users customise by copying it under a different name
  (``vulnfounder llm-config copy vulnfounder-default my-config``).
* **References provider name "anthropic".** The provider entry IS
  user-editable; this lets ``vulnfounder set-api-key`` write the key to
  ``llm_providers["anthropic"].api_key`` and have ``vulnfounder-default``
  pick it up automatically.

If Anthropic deprecates a model ID listed here, this file is the
single place we update — every other module reads through the
registry.
"""

from __future__ import annotations

from ..model_config import CLAUDE_OPUS, CLAUDE_SONNET
from .config import LLMConfig, PhaseRef


# Provider name referenced by every phase. Synthesised from the
# legacy ``api_key`` field by the migrator, or set via
# ``vulnfounder set-api-key``.
_ANTHROPIC_PROVIDER = "anthropic"


# Per-phase Claude defaults — preserves today's behavior on upgrade.
# When this file changes, the CHANGELOG must say so, because every
# existing user without a custom llm-config picks up the new IDs on
# the next ``vulnfounder scan``.
VULNFOUNDER_DEFAULT = LLMConfig(
    name="vulnfounder-default",
    phases={
        # Stage 1 detection. Opus by historical default.
        "analyze": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Context enhancement (agentic + single-shot). Sonnet for cost.
        "enhance": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
        # Stage 2 attacker simulation. Opus, uses tool calling.
        "verify": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Disclosure + summary + remediation HTML generation. Opus —
        # matches master's report/generator.py report-generator default.
        # The refactor briefly moved this to Sonnet; restored so the
        # report output (incl. the HTML-remediation sub-call) stays on
        # Opus on a fresh, config-less install.
        "report": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Docker exploit-test generation. Sonnet.
        "dynamic_test": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
        # LLM-driven reachability review (opt-in stage). Opus.
        "llm_reach": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_OPUS),
        # Application-context classification (web_app / cli_tool / etc).
        # Single-shot, runs once per scan during ``vulnfounder scan``. Sonnet.
        "app_context": PhaseRef(provider=_ANTHROPIC_PROVIDER, model=CLAUDE_SONNET),
    },
)


# Public, callable accessor so callers don't accidentally mutate the
# module-level dict. The dataclass is frozen so the dict-mutation
# foot-gun is mostly hypothetical, but this gives us a single hook
# if we ever want to load the default from disk for testing.
def get_builtin_default() -> LLMConfig:
    return VULNFOUNDER_DEFAULT


# Source compatibility for extensions importing the old constant. Its value is
# the new builtin, so no second divergent default configuration can emerge.
OPENANT_DEFAULT = VULNFOUNDER_DEFAULT
