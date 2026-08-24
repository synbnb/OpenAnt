"""Operator-owned OpenHarmony application security baseline.

The repository may describe additional business context, but a scanned
repository is not allowed to remove the minimum attacker and input assumptions
that follow from an OpenHarmony boundary.  This module keeps that policy in a
small, deterministic layer between platform-profile detection and the existing
``ApplicationContext`` consumers.

OH-16A-1 intentionally does not add a CLI trust-tier switch or finding-level
suppression accounting.  It establishes the safer default: when OpenHarmony is
selected, the platform baseline is merged monotonically and its provenance is
written into the context and scan artifacts.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from context.application_context import ApplicationContext


OPENHARMONY_BASELINE_ID = "openharmony-minimum"
OPENHARMONY_BASELINE_VERSION = 1

_IPC_BOUNDARIES = frozenset({"binder_ipc", "system_ability", "idl", "ipc"})
_HDF_BOUNDARIES = frozenset({"hdf", "hdi", "device_data"})
_REMOTE_BOUNDARY_TOKENS = frozenset(
    {"network", "wifi", "bluetooth", "ble", "socket", "remote", "nearby"}
)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            converted = to_dict()
        except (OSError, TypeError, ValueError):
            return {}
        return dict(converted) if isinstance(converted, Mapping) else {}
    return {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    values: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            normalized = item.strip()
            if normalized not in values:
                values.append(normalized)
    return values


def _stable_union(*values: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        for item in _string_list(value):
            if item not in result:
                result.append(item)
    return result


def _profile_boundaries(profile: Mapping[str, Any]) -> list[str]:
    """Extract conservative, normalized boundary labels from a profile."""
    boundaries = _stable_union(profile.get("boundaries"))
    detection = _as_dict(profile.get("detection"))
    signals = _as_dict(detection.get("signals"))
    for signal_name in ("binder_ipc", "system_ability", "idl", "hdf"):
        if signals.get(signal_name) and signal_name not in boundaries:
            boundaries.append(signal_name)

    # A selected OpenHarmony platform with an incomplete profile must not turn
    # into a silent local-IPC blind spot.  The caller can still report the
    # profile's missing metadata through its normal coverage fields.
    if not boundaries:
        boundaries.append("binder_ipc")
    return boundaries


def _has_boundary(boundaries: list[str], candidates: frozenset[str]) -> bool:
    for boundary in boundaries:
        normalized = boundary.lower().replace("-", "_").replace(" ", "_")
        if normalized in candidates:
            return True
    return False


def _has_remote_boundary(boundaries: list[str]) -> bool:
    return any(
        token in boundary.lower()
        for boundary in boundaries
        for token in _REMOTE_BOUNDARY_TOKENS
    )


def _profile_evidence(profile: Mapping[str, Any], boundaries: list[str]) -> list[str]:
    detection = _as_dict(profile.get("detection"))
    evidence = _stable_union(detection.get("evidence"))
    signals = _as_dict(detection.get("signals"))
    for boundary in boundaries:
        for path in _string_list(signals.get(boundary)):
            marker = f"{boundary}:{path}"
            if marker not in evidence:
                evidence.append(marker)
    if not evidence:
        evidence.append("explicit platform selection: openharmony")
    return evidence


def _build_baseline_sections(
    boundaries: list[str],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]], list[str]]:
    attackers: list[dict[str, Any]] = []
    inputs: dict[str, dict[str, str]] = {}
    criteria: list[str] = []

    if _has_boundary(boundaries, _IPC_BOUNDARIES):
        attackers.extend(
            [
                {
                    "id": "openharmony_local_ipc_caller",
                    "position": "local_user",
                    "description": (
                        "An unprivileged local application that can reach an "
                        "exposed Binder/System Ability endpoint."
                    ),
                    "capabilities": [
                        "send Binder/SA transactions",
                        "control MessageParcel field values, lengths, and request frequency",
                    ],
                    "cannot": [
                        "assume shell, root, or host-file access",
                        "bypass a valid permission check without exploiting a defect",
                    ],
                    "entry_via": ["Binder IPC", "System Ability transaction"],
                    "impact": "Gain an unauthorized capability or corrupt service state.",
                },
                {
                    "id": "openharmony_restricted_system_app",
                    "position": "local_user",
                    "description": (
                        "A system application with limited permissions that can "
                        "call the service and exercise cross-SA paths."
                    ),
                    "capabilities": [
                        "invoke IPC methods available to the application's granted permissions",
                        "supply repeated or malformed transaction fields",
                    ],
                    "cannot": [
                        "assume unrestricted system or root privileges",
                    ],
                    "entry_via": ["System Ability transaction"],
                    "impact": "Cross a service authorization or data-validation boundary.",
                },
            ]
        )
        inputs.update(
            {
                "openharmony_binder_parcel": {
                    "trust": "untrusted",
                    "description": "Caller-controlled MessageParcel fields and transaction payloads.",
                },
                "openharmony_calling_identity": {
                    "trust": "semi_trusted",
                    "description": "Caller UID/token metadata used by service authorization guards.",
                },
            }
        )
        criteria.extend(
            [
                "Validate interface tokens, read return values, field types, widths, and ordering before use.",
                "Bound Parcel-derived lengths, counts, indexes, and callback registrations before allocation or iteration.",
                "Require caller identity and permission checks to dominate sensitive IPC operations.",
            ]
        )

    if _has_boundary(boundaries, _HDF_BOUNDARIES):
        attackers.append(
            {
                "id": "openharmony_device_data_source",
                "position": "adjacent",
                "description": "An abnormal or malicious device-facing data source reaching an HDF/HDI component.",
                "capabilities": [
                    "provide malformed device data through the driver-facing boundary",
                    "trigger repeated bind, dispatch, and release paths",
                ],
                "cannot": ["assume user-space shell access to the host"],
                "entry_via": ["HDF/HDI device data"],
                "impact": "Trigger memory-safety, ownership, or availability failures in the component.",
            }
        )
        inputs["openharmony_device_data"] = {
            "trust": "untrusted",
            "description": "Device-facing HDF/HDI data and buffers.",
        }
        criteria.extend(
            [
                "Validate HdfSBuf/HDI device values and lengths before pointer, index, or allocation use.",
                "Keep HDF/HDI Bind, Init, Dispatch, and Release ownership paths consistent on failure.",
            ]
        )

    if _has_remote_boundary(boundaries):
        attackers.append(
            {
                "id": "openharmony_remote_or_adjacent_input",
                "position": "remote",
                "description": "A remote or nearby peer that can reach the component's declared network boundary.",
                "capabilities": ["send malformed protocol or connection data"],
                "cannot": ["assume local filesystem or administrative access"],
                "entry_via": ["declared network/Wi-Fi/Bluetooth boundary"],
                "impact": "Reach an unsafe parser, state transition, or privileged operation.",
            }
        )
        inputs["openharmony_remote_input"] = {
            "trust": "untrusted",
            "description": "Network, Wi-Fi, Bluetooth, or other remote/nearby input.",
        }
        criteria.append(
            "Treat remote or nearby protocol fields as untrusted until type, size, state, and authorization checks pass."
        )

    return attackers, inputs, _stable_union(criteria)


def build_openharmony_baseline_context(
    profile: Mapping[str, Any] | Any | None,
    *,
    force: bool = False,
) -> ApplicationContext | None:
    """Build the built-in baseline from an OpenHarmony profile.

    ``force`` is used only when the operator explicitly selected
    ``--platform openharmony`` and profile detection was incomplete.  In that
    case the conservative Binder baseline is still applied rather than silently
    suppressing local IPC analysis.
    """
    profile_data = _as_dict(profile)
    if not force and profile_data.get("platform") != "openharmony":
        return None

    boundaries = _profile_boundaries(profile_data)
    attackers, inputs, criteria = _build_baseline_sections(boundaries)
    evidence = _profile_evidence(profile_data, boundaries)
    detection = _as_dict(profile_data.get("detection"))
    confidence = detection.get("confidence", 1.0 if force else 0.0)
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 0.0

    baseline = {
        "id": OPENHARMONY_BASELINE_ID,
        "version": OPENHARMONY_BASELINE_VERSION,
        "platform": "openharmony",
        "source": "openant_builtin",
        "boundaries": list(boundaries),
        "attacker_profiles": deepcopy(attackers),
        "input_sources": deepcopy(inputs),
        "vulnerability_criteria": list(criteria),
        "evidence": list(evidence),
    }
    provenance = {
        "context_source": "openharmony_baseline",
        "repository_model_applied": False,
        "repository_model_sha256": None,
        "platform_baseline": {
            "id": OPENHARMONY_BASELINE_ID,
            "version": OPENHARMONY_BASELINE_VERSION,
            "applied": True,
            "boundaries": list(boundaries),
            "attacker_profile_ids": [item["id"] for item in attackers],
            "input_source_names": list(inputs),
            "criteria_count": len(criteria),
            "evidence": list(evidence),
        },
        "merge_conflicts": [],
    }
    return ApplicationContext(
        application_type="openharmony_component",
        purpose=(
            "An OpenHarmony component whose platform boundaries require analysis "
            "of local IPC, device, and explicitly detected remote inputs."
        ),
        intended_behaviors=[
            "Expose platform component functionality through declared OpenHarmony boundaries."
        ],
        trust_boundaries={name: spec["trust"] for name, spec in inputs.items()},
        security_model=(
            "OpenHarmony platform minimum: caller-controlled boundary data and "
            "identity require explicit validation, bounds, and authorization."
        ),
        not_a_vulnerability=[],
        requires_remote_trigger=_has_remote_boundary(boundaries),
        confidence=confidence,
        evidence=evidence,
        source="openharmony_baseline",
        attacker_profiles=deepcopy(attackers),
        input_sources=deepcopy(inputs),
        vulnerability_criteria=list(criteria),
        platform_baseline=baseline,
        context_provenance=provenance,
    )


def _merge_dict_records(
    baseline_records: list[dict[str, Any]],
    repository_records: Any,
    *,
    key: str,
    conflicts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge records with baseline-first precedence and stable ordering."""
    merged = deepcopy(baseline_records)
    by_key = {
        item.get(key): item
        for item in merged
        if isinstance(item, dict) and isinstance(item.get(key), str)
    }
    if not isinstance(repository_records, list):
        return merged
    for item in repository_records:
        if not isinstance(item, dict):
            continue
        record_key = item.get(key)
        if not isinstance(record_key, str) or not record_key.strip():
            continue
        if record_key in by_key:
            if item != by_key[record_key]:
                conflicts.append(
                    {
                        "kind": f"repository_{key}_cannot_override_baseline",
                        "id": record_key,
                    }
                )
            continue
        merged.append(deepcopy(item))
        by_key[record_key] = item
    return merged


def merge_openharmony_context(
    context: ApplicationContext,
    profile: Mapping[str, Any] | Any | None,
    *,
    force: bool = False,
) -> ApplicationContext:
    """Monotonically merge the OpenHarmony baseline into an app context."""
    if not isinstance(context, ApplicationContext):
        raise TypeError("context must be an ApplicationContext")
    baseline_context = build_openharmony_baseline_context(profile, force=force)
    if baseline_context is None:
        return context
    if context.has_openharmony_baseline():
        # Idempotence matters when a caller resumes a partially completed scan
        # or applies the adapter at more than one orchestration boundary.
        return context

    conflicts: list[dict[str, Any]] = []
    baseline = baseline_context.platform_baseline
    attackers = _merge_dict_records(
        baseline_context.attacker_profiles,
        context.attacker_profiles,
        key="id",
        conflicts=conflicts,
    )

    baseline_inputs = deepcopy(baseline_context.input_sources)
    repository_inputs = context.input_sources if isinstance(context.input_sources, dict) else {}
    inputs = deepcopy(baseline_inputs)
    for name, spec in repository_inputs.items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            continue
        if name in inputs:
            if spec != inputs[name]:
                conflicts.append(
                    {
                        "kind": "repository_input_source_cannot_override_baseline",
                        "name": name,
                        "baseline_trust": inputs[name].get("trust"),
                        "repository_trust": spec.get("trust"),
                    }
                )
            continue
        inputs[name] = deepcopy(spec)

    repository_exclusions = list(context.repository_advisory_exclusions or context.not_a_vulnerability or [])
    if repository_exclusions:
        conflicts.extend(
            {
                "kind": "repository_exclusion_is_advisory",
                "item": item,
            }
            for item in repository_exclusions
            if isinstance(item, str) and item.strip()
        )
    if not context.attacker_profiles:
        conflicts.append(
            {
                "kind": "repository_declares_no_attacker_profiles",
                "retained": "openharmony_platform_baseline",
            }
        )

    repository_source = context.source
    repository_model_applied = context.has_threat_model() or repository_source in {
        "manual",
        "threat_model",
    }
    merged_provenance = deepcopy(baseline_context.context_provenance)
    merged_provenance.update(
        {
            "context_source": "merged",
            "repository_model_applied": repository_model_applied,
            "repository_model_source": repository_source,
            "repository_model_sha256": context.source_sha256,
            "merge_conflicts": deepcopy(conflicts),
        }
    )
    merged_provenance["platform_baseline"] = deepcopy(
        baseline_context.context_provenance["platform_baseline"]
    )
    merged_provenance["platform_baseline"]["applied"] = True

    purpose = context.purpose or baseline_context.purpose
    security_model = baseline_context.security_model
    if context.security_model:
        security_model = f"{security_model} Repository model: {context.security_model}"

    return ApplicationContext(
        application_type="openharmony_component",
        purpose=purpose,
        intended_behaviors=_stable_union(
            baseline_context.intended_behaviors, context.intended_behaviors
        ),
        trust_boundaries={name: spec.get("trust", "") for name, spec in inputs.items()},
        security_model=security_model,
        not_a_vulnerability=list(context.not_a_vulnerability or []),
        requires_remote_trigger=(
            baseline_context.requires_remote_trigger or context.requires_remote_trigger
        ),
        confidence=max(baseline_context.confidence, context.confidence),
        evidence=_stable_union(baseline_context.evidence, context.evidence),
        source="merged",
        source_sha256=context.source_sha256,
        permissive_warnings=list(context.permissive_warnings or []),
        threat_model_version=context.threat_model_version,
        classification=context.classification,
        components=deepcopy(context.components),
        attacker_profiles=attackers,
        input_sources=inputs,
        vulnerability_criteria=_stable_union(
            baseline_context.vulnerability_criteria, context.vulnerability_criteria
        ),
        impact_statement=context.impact_statement,
        platform_baseline=deepcopy(baseline),
        platform_baseline_conflicts=deepcopy(conflicts),
        repository_advisory_exclusions=repository_exclusions,
        context_provenance=merged_provenance,
    )

