"""OpenHarmony source-locator building blocks.

The package is intentionally additive.  The first slice contains the
OpenGrok response models and normalization helpers; network orchestration is
kept in :mod:`core.source_locator.opengrok_client` and is opt-in.
"""

from .opengrok_client import (
    EndpointCapability,
    OpenGrokError,
    OpenGrokPathError,
    OpenGrokProtocolError,
    ProbeResult,
    RequestAttempt,
    SearchHit,
    SearchResponse,
    SourceDocument,
    normalize_base_url,
    normalize_search_line,
    normalize_source_path,
)

__all__ = [
    "EndpointCapability",
    "OpenGrokError",
    "OpenGrokPathError",
    "OpenGrokProtocolError",
    "ProbeResult",
    "RequestAttempt",
    "SearchHit",
    "SearchResponse",
    "SourceDocument",
    "normalize_base_url",
    "normalize_search_line",
    "normalize_source_path",
]
