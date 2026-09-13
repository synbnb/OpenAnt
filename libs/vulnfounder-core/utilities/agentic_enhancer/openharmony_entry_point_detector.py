"""OpenHarmony-specific native entry-point detection.

The generic entry-point detector intentionally knows about web, CLI and
language-level program roots only.  OpenHarmony adds externally reachable
execution hooks whose names are stable across generated and handwritten C/C++
code.  This module classifies only those hooks; it does not infer call-graph
edges or treat an individual parcel read as an entry point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


_SA_CONTEXT_RE = re.compile(
    r"\b(?:SystemAbility|REGISTER_SYSTEM_ABILITY|DECLARE_SYSTEM_ABILITY|"
    r"Publish|publish)\b|(?:service|ability|sa)",
    re.IGNORECASE,
)
# ``OnStart``/``OnStop`` are also common lifecycle methods on ordinary
# components.  Keep a stricter context expression for those two names: a
# generic ``Ability`` token is not enough because application/extension
# Ability classes are not System Abilities, and an unbounded ``sa`` match
# produces accidental matches in unrelated words.
_SA_LIFECYCLE_CONTEXT_RE = re.compile(
    r"\b(?:SystemAbility|ISystemAbility|SystemAbilityManager|"
    r"REGISTER_SYSTEM_ABILITY(?:_BY_ID)?|DECLARE_SYSTEM_ABILITY|"
    r"GetSystemAbility|AddSystemAbility|RemoveSystemAbility|Publish)\b"
    r"|(?:^|::)[A-Za-z_]\w*Service(?:Stub|Proxy|Impl)?\b"
    r"|(?:^|/)(?:sa|system_ability|systemability|systemabilitymgr|"
    r"service|services)(?:/|$)"
    r"|(?:^|/)[^/]+_sa\.(?:c|cc|cpp|cxx)$",
    re.IGNORECASE,
)
_HDF_SIGNATURE_RE = re.compile(
    r"\b(?:HdfDeviceIoClient|HdfSBuf|HdfRemoteService|IDeviceIoService|"
    r"SbufToParcel|HdfSbufRead\w*)\b",
    re.IGNORECASE,
)
_HDF_INIT_RE = re.compile(
    r"(?m)^\s*HDF_INIT\s*\(\s*(?P<entry>[A-Za-z_]\w*)\s*\)\s*;?\s*$"
)
_HDF_ENTRY_RE = re.compile(
    r"\b(?:static\s+)?(?:const\s+)?struct\s+HdfDriverEntry\s+"
    r"(?P<entry>[A-Za-z_]\w*)\s*=\s*\{(?P<body>.*?)\};",
    re.IGNORECASE | re.DOTALL,
)
_HDF_CALLBACK_RE = re.compile(
    r"\.\s*(?P<field>Bind|Init|Release)\s*=\s*"
    r"(?P<callback>[A-Za-z_]\w*)\b"
)
# Strong native receive primitives.  ``read()`` is deliberately excluded: in
# OpenHarmony it is also widely used for files, pipes, and device nodes, so
# treating every read as a socket boundary would create a large false-positive
# seed set.  The regex is applied after comments and literals are masked.
_SOCKET_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<primitive>accept4?|recv(?:from|msg)?|recvmmsg)\s*\("
)
_CPP_NON_CODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|"
    r"'(?:\\.|[^'\\])*'",
    re.DOTALL,
)
_SOCKET_KERNEL_CONTEXT_RE = re.compile(
    r"\b(?:AF_NETLINK|NETLINK_[A-Z0-9_]+|sockaddr_nl|KOBJECT_UEVENT|"
    r"uevent|netlink)\b",
    re.IGNORECASE,
)
_SOCKET_LOCAL_CONTEXT_RE = re.compile(
    r"\b(?:AF_UNIX|AF_LOCAL|sockaddr_un|SO_PEERCRED|socketpair|"
    r"unix[_ ]socket|local[_ ]socket)\b",
    re.IGNORECASE,
)
_SOCKET_NETWORK_CONTEXT_RE = re.compile(
    r"\b(?:AF_INET6?|sockaddr_in6?|IPPROTO_(?:TCP|UDP)|"
    r"(?:tcp|udp)[_ ]socket|inet[_ ]socket)\b",
    re.IGNORECASE,
)
_ABILITY_CONTEXT_RE = re.compile(
    r"\b(?:AAFwk::)?Want(?:Params)?\b|\bSessionInfo\b|"
    r"\bAbilityTransactionCallbackInfo\b|\b(?:Ability|Extension)::On(?:Start|Stop|"
    r"Foreground|Background|NewWant|Connect|Disconnect|Command|Continue|"
    r"SaveData|RestoreData)\b",
    re.IGNORECASE,
)
_ABILITY_OWNER_RE = re.compile(
    r"(?:Ability|Extension)(?:Base(?:Impl)?|Impl|Object)?$|"
    r"Ability(?:Lifecycle|Connect)(?:Callback|Observer)(?:Impl)?$",
    re.IGNORECASE,
)
_ABILITY_PATH_RE = re.compile(
    r"(?:^|/)(?:ability|ability_runtime|ability_lifecycle|application_context|"
    r"agent_extension_ability|ui_extension_ability|auto_fill_extension_ability|"
    r"form_extension_ability|service_extension_ability|"
    r"app_service_extension_ability)(?:/|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OpenHarmonyEntryPointMatch:
    """One deterministic OpenHarmony entry-point match."""

    category: str
    matched: str
    confidence: str
    evidence: str
    reason: str
    details: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "matched": self.matched,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reason": self.reason,
        }
        if self.details:
            result.update(self.details)
        return result


class OpenHarmonyEntryPointDetector:
    """Detect native OpenHarmony execution hooks from function metadata.

    The detector is deliberately conservative about generic names.  Binder
    and SA hooks use exact method names, while a HDF dispatch requires both a
    dispatch-shaped function name and an HDF/HDI signature or path signal.
    """

    _SA_LIFECYCLE_METHODS = frozenset(
        {
            "OnStart",
            "OnStop",
            "OnDump",
            "OnAddSystemAbility",
            "OnRemoveSystemAbility",
        }
    )
    _ABILITY_LIFECYCLE_METHODS = frozenset(
        {
            "OnStart",
            "OnStop",
            "OnForeground",
            "OnBackground",
            "OnNewWant",
            "OnConnect",
            "OnDisconnect",
            "OnCommand",
            "OnContinue",
            "OnSaveData",
            "OnRestoreData",
        }
    )

    def detect(
        self,
        func_data: Mapping[str, Any],
        file_evidence: Iterable[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, str]]:
        """Return platform matches for one extracted function."""
        name = self._text(func_data, "name")
        leaf = self._qualified_leaf(name)
        code = self._text(func_data, "code")
        file_path = self._text(func_data, "file_path", "filePath")

        matches: list[OpenHarmonyEntryPointMatch] = []

        if leaf == "OnRemoteRequest":
            matches.append(
                self._match(
                    category="binder_ipc",
                    matched=leaf,
                    confidence="high",
                    evidence=f"function_name:{leaf}",
                )
            )

        socket_match = self._detect_socket_input(name, code, file_path, func_data)
        if socket_match is not None:
            matches.append(socket_match)

        if leaf in self._SA_LIFECYCLE_METHODS:
            # OnStart/OnStop are common in ordinary components, so require a
            # strong SA/service context for them.  OnDump keeps the historical
            # broader context check, while the System Ability listener hooks
            # remain exact framework callbacks regardless of surrounding text.
            has_context = (
                self._has_sa_lifecycle_context(name, code, file_path)
                if leaf in {"OnStart", "OnStop"}
                else self._has_sa_context(name, code, file_path)
            )
            requires_context = leaf in {"OnStart", "OnStop", "OnDump"}
            if not requires_context or has_context:
                confidence = "high" if leaf in {"OnStart", "OnStop"} else "medium"
                matches.append(
                    self._match(
                        category="system_ability_lifecycle",
                        matched=leaf,
                        confidence=confidence,
                        evidence=f"function_name:{leaf}",
                    )
                )

        if (
            leaf in self._ABILITY_LIFECYCLE_METHODS
            and self._has_ability_context(name, code, file_path)
            and not self._has_sa_lifecycle_context(name, code, file_path)
        ):
            matches.append(
                self._match(
                    category="ability_lifecycle",
                    matched=leaf,
                    confidence="high",
                    evidence=f"function_name:{leaf};ability_context",
                )
            )

        if self._is_hdf_dispatch(leaf, code, file_path):
            matches.append(
                self._match(
                    category="hdf_dispatch",
                    matched=leaf,
                    confidence="high",
                    evidence=f"function_name:{leaf};hdf_signature",
                )
            )

        for evidence in file_evidence or ():
            if self._is_hdf_registration_callback(name, leaf, evidence):
                entry = str(evidence.get("entry", ""))
                callbacks = ",".join(evidence.get("callbacks", ()))
                line = int(evidence.get("line", 0) or 0)
                matches.append(
                    self._match(
                        category="hdf_registration",
                        matched=leaf,
                        confidence="high",
                        evidence=(
                            f"HDF_INIT({entry});HdfDriverEntry;"
                            f"callback:{leaf};callbacks:{callbacks};"
                            f"registration_line:{line}"
                        ),
                    )
                )

        return [match.to_dict() for match in matches]

    @staticmethod
    def _detect_socket_input(
        name: str,
        code: str,
        file_path: str,
        func_data: Mapping[str, Any],
    ) -> OpenHarmonyEntryPointMatch | None:
        """Classify a function that directly receives bytes from a socket.

        This is intentionally a seed detector, not a data-flow proof.  A
        direct receive is enough to retain the function and its callees for
        later security analysis; the trust classification remains explicit so
        the LLM can distinguish Internet, local IPC-like, and kernel-originated
        data.  Comments and string/character literals are masked to avoid
        turning logging text or documentation into entry points.
        """
        if not code:
            return None
        masked = _CPP_NON_CODE_RE.sub(
            lambda match: "".join("\n" if char == "\n" else " " for char in match.group(0)),
            code,
        )
        calls = list(_SOCKET_CALL_RE.finditer(masked))
        if not calls:
            return None

        context = f"{name}\n{file_path}\n{masked}"
        if _SOCKET_KERNEL_CONTEXT_RE.search(context):
            socket_kind, trust = "kernel_socket", "semi_trusted"
        elif _SOCKET_LOCAL_CONTEXT_RE.search(context):
            socket_kind, trust = "local_socket", "semi_trusted"
        elif _SOCKET_NETWORK_CONTEXT_RE.search(context):
            socket_kind, trust = "network_socket", "untrusted"
        else:
            # A direct receive is still an external-data boundary even when
            # the address family is hidden behind a helper or build macro.
            socket_kind, trust = "unknown_socket", "untrusted"

        start_line = func_data.get("start_line", func_data.get("startLine", 1))
        if not isinstance(start_line, int) or start_line < 1:
            start_line = 1
        socket_calls = []
        for call in calls:
            primitive = call.group("primitive")
            line = start_line + masked.count("\n", 0, call.start())
            socket_calls.append({"primitive": primitive, "line": line})
        primitive_names = list(dict.fromkeys(item["primitive"] for item in socket_calls))
        call_evidence = ",".join(
            f"{item['primitive']}@{item['line']}" for item in socket_calls
        )
        return OpenHarmonyEntryPointMatch(
            category="native_socket",
            matched=",".join(primitive_names),
            confidence="high",
            evidence=(
                f"socket_call:{call_evidence};socket_kind:{socket_kind};trust:{trust}"
            ),
            reason="platform:openharmony:native_socket",
            details={
                "socket_primitives": primitive_names,
                "socket_calls": socket_calls,
                "socket_kind": socket_kind,
                "trust": trust,
            },
        )

    @staticmethod
    def _text(func_data: Mapping[str, Any], *keys: str) -> str:
        for key in keys:
            value = func_data.get(key)
            if value is not None:
                return str(value)
        return ""

    @staticmethod
    def _qualified_leaf(name: str) -> str:
        return name.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()

    @staticmethod
    def _has_sa_context(name: str, code: str, file_path: str) -> bool:
        return any(
            _SA_CONTEXT_RE.search(value)
            for value in (name, code, file_path)
            if value
        )

    @staticmethod
    def _has_sa_lifecycle_context(name: str, code: str, file_path: str) -> bool:
        """Return whether an ``OnStart``/``OnStop`` has strong SA evidence.

        The check intentionally accepts class/path conventions used by real
        OpenHarmony services, but rejects a plain ``Ability`` class or an
        arbitrary component's ``Start``/``Stop`` implementation.  This is a
        context gate, not a claim that every matched method receives attacker
        controlled bytes directly.
        """
        return any(
            _SA_LIFECYCLE_CONTEXT_RE.search(value)
            for value in (name, code, file_path)
            if value
        )

    @staticmethod
    def _has_ability_context(name: str, code: str, file_path: str) -> bool:
        owner = name.rsplit("::", 1)[-2] if "::" in name else ""
        owner_leaf = owner.rsplit("::", 1)[-1]
        normalized_path = file_path.replace("\\", "/")
        return bool(
            _ABILITY_OWNER_RE.search(owner_leaf)
            or _ABILITY_CONTEXT_RE.search(name)
            or _ABILITY_CONTEXT_RE.search(code)
            or _ABILITY_PATH_RE.search(normalized_path)
        )

    @staticmethod
    def _is_hdf_registration_callback(
        name: str, leaf: str, evidence: Mapping[str, Any]
    ) -> bool:
        if evidence.get("category") != "hdf_registration":
            return False
        callbacks = {
            str(callback)
            for callback in evidence.get("callbacks", ())
            if callback
        }
        return bool(callbacks and (leaf in callbacks or name in callbacks))

    @staticmethod
    def _is_hdf_dispatch(leaf: str, code: str, file_path: str) -> bool:
        if not leaf or not leaf.lower().endswith("dispatch"):
            return False
        if _HDF_SIGNATURE_RE.search(code):
            return True
        normalized_path = file_path.replace("\\", "/").lower()
        return bool(re.search(r"(?:^|/)(?:hdi|hdf|driver|drivers?)(?:/|$)", normalized_path))

    @staticmethod
    def _match(
        *, category: str, matched: str, confidence: str, evidence: str
    ) -> OpenHarmonyEntryPointMatch:
        return OpenHarmonyEntryPointMatch(
            category=category,
            matched=matched,
            confidence=confidence,
            evidence=evidence,
            reason=f"platform:openharmony:{category}",
        )


__all__ = ["OpenHarmonyEntryPointDetector", "OpenHarmonyEntryPointMatch"]


def collect_hdf_registration_evidence(
    repository_root: str | Path,
    file_paths: Iterable[str],
) -> dict[str, list[dict[str, Any]]]:
    """Collect bounded HDF registration evidence keyed by relative file path.

    HDF registration is a file-level macro, so it is not represented in a
    function's tree-sitter body.  This helper resolves only the callbacks
    explicitly referenced by ``HDF_INIT`` and ``HdfDriverEntry``; it never
    treats every function in the file as an entry point.
    """
    root = Path(repository_root).resolve()
    result: dict[str, list[dict[str, Any]]] = {}
    for relative in sorted({str(path).replace("\\", "/") for path in file_paths}):
        source_path = (root / relative).resolve()
        try:
            source_path.relative_to(root)
            if not source_path.is_file() or source_path.stat().st_size > 1024 * 1024:
                continue
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue

        registrations = []
        definitions = {
            match.group("entry"): match.group("body")
            for match in _HDF_ENTRY_RE.finditer(source)
        }
        for init_match in _HDF_INIT_RE.finditer(source):
            entry = init_match.group("entry")
            body = definitions.get(entry, "")
            callbacks = sorted(
                {
                    match.group("callback")
                    for match in _HDF_CALLBACK_RE.finditer(body)
                    if match.group("callback") not in {"NULL", "nullptr"}
                }
            )
            registrations.append(
                {
                    "category": "hdf_registration",
                    "entry": entry,
                    "callbacks": callbacks,
                    "line": source.count("\n", 0, init_match.start()) + 1,
                }
            )
        if registrations:
            result[relative] = registrations
    return result


__all__.append("collect_hdf_registration_evidence")
