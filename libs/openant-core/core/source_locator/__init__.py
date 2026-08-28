"""OpenHarmony source-locator building blocks.

The package is intentionally additive.  The first slice contains the
OpenGrok response models and normalization helpers; network orchestration is
kept in :mod:`core.source_locator.opengrok_client` and is opt-in.
"""

from .opengrok_client import (
    EndpointCapability,
    OpenGrokError,
    OpenGrokHTTPError,
    OpenGrokPathError,
    OpenGrokProtocolError,
    OpenGrokClient,
    OpenGrokTransportError,
    ProbeResult,
    RequestAttempt,
    SearchHit,
    SearchResponse,
    SourceDocument,
    normalize_base_url,
    normalize_search_line,
    normalize_source_path,
)
from .config import (
    GitCodeConfig,
    ManifestConfig,
    OpenGrokConfig,
    SourceLocatorAuth,
    SourceLocatorConfig,
    SourceLocatorConfigError,
    load_source_locator_config,
    parse_source_locator_config,
)
from .target_normalizer import (
    LocatorQuery,
    TargetNormalizationError,
    TargetSpec,
    build_initial_queries,
    normalize_and_plan,
    normalize_target,
)

__all__ = [
    "EndpointCapability",
    "OpenGrokError",
    "OpenGrokHTTPError",
    "OpenGrokClient",
    "OpenGrokPathError",
    "OpenGrokProtocolError",
    "OpenGrokTransportError",
    "ProbeResult",
    "RequestAttempt",
    "SearchHit",
    "SearchResponse",
    "SourceDocument",
    "normalize_base_url",
    "normalize_search_line",
    "normalize_source_path",
    "GitCodeConfig",
    "ManifestConfig",
    "OpenGrokConfig",
    "SourceLocatorAuth",
    "SourceLocatorConfig",
    "SourceLocatorConfigError",
    "load_source_locator_config",
    "parse_source_locator_config",
    "LocatorQuery",
    "TargetNormalizationError",
    "TargetSpec",
    "build_initial_queries",
    "normalize_and_plan",
    "normalize_target",
]
