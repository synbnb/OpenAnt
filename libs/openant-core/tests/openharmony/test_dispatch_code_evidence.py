"""TDD contract for OpenHarmony transaction-code evidence extraction."""

from __future__ import annotations

from core.platforms.openharmony.dispatch_code_evidence import (
    build_dispatch_code_evidence,
)


REGISTRATION_FILE = "service.cpp"


def _diagnostics(*selectors: str) -> dict:
    return {
        "unresolved_call_sites": [
            {
                "caller_id": f"{REGISTRATION_FILE}:Service::OnRemoteRequest",
                "file": REGISTRATION_FILE,
                "line": 20,
                "expression": "(this->*memberFunc)(data, reply)",
                "reason": "parenthesized_member_function_pointer",
                "candidate_target_ids": [
                    f"{REGISTRATION_FILE}:Service::Handler{index}"
                    for index, _ in enumerate(selectors)
                ],
                "candidates": [
                    {
                        "target_id": (
                            f"{REGISTRATION_FILE}:Service::Handler{index}"
                        ),
                        "target_name": f"Service::Handler{index}",
                        "selector": selector,
                        "evidence": {
                            "file": REGISTRATION_FILE,
                            "start_line": 10 + index,
                            "end_line": 10 + index,
                            "text": (
                                f"baseFuncs_[{selector}] = "
                                f"&Service::Handler{index}"
                            ),
                        },
                    }
                    for index, selector in enumerate(selectors)
                ],
            }
        ]
    }


def test_resolves_enum_values_and_preserves_registration_evidence():
    source = """
class Service {
public:
    enum {
        ENABLE_SENSOR = 0,
        DISABLE_SENSOR,
        SET_OPTION = 4,
    };
};
"""

    result = build_dispatch_code_evidence(
        _diagnostics("ENABLE_SENSOR", "DISABLE_SENSOR", "SET_OPTION"),
        source_files={REGISTRATION_FILE: source},
    )

    cases = result["sites"][0]["cases"]
    assert [case["value"] for case in cases] == [0, 1, 4]
    assert all(case["resolution"] == "resolved" for case in cases)
    assert all(
        any(item["kind"] == "registration" for item in case["evidence"])
        for case in cases
    )
    assert all(
        any(item["kind"] == "constant_definition" for item in case["evidence"])
        for case in cases
    )


def test_resolves_macro_constexpr_alias_and_bitwise_expression():
    source = """
#define BASE_CODE 0x20U
constexpr int NEXT_CODE = BASE_CODE + 2;
constexpr int MASKED_CODE = (NEXT_CODE << 1) | 1;
"""

    result = build_dispatch_code_evidence(
        _diagnostics("BASE_CODE", "NEXT_CODE", "MASKED_CODE"),
        source_files={REGISTRATION_FILE: source},
    )

    assert [case["value"] for case in result["sites"][0]["cases"]] == [32, 34, 69]


def test_does_not_guess_unknown_or_conflicting_symbols():
    source = """
#define CONFLICTING_CODE 1
constexpr int CONFLICTING_CODE = 2;
"""

    result = build_dispatch_code_evidence(
        _diagnostics("UNKNOWN_CODE", "CONFLICTING_CODE"),
        source_files={REGISTRATION_FILE: source},
    )

    cases = result["sites"][0]["cases"]
    assert cases[0]["value"] is None
    assert cases[0]["resolution"] == "unresolved_symbol"
    assert cases[1]["value"] is None
    assert cases[1]["resolution"] == "ambiguous_symbol"
    assert result["summary"]["unresolved_symbols"] == 1
    assert result["summary"]["conflicts"] == 1
