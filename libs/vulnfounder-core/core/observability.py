"""Small helpers for user-facing, real-time pipeline observability."""

import sys


def print_chinese_log(message: str, *, category: str = "运行说明") -> None:
    """Write one Chinese explanation line to the live scan stream.

    The Go Web runner forwards stderr line-by-line through SSE.  Normalising
    embedded newlines keeps one explanation as one event, while ``flush`` makes
    it visible immediately.  This helper is additive: callers should continue
    emitting their existing English diagnostics unchanged.
    """
    text = str(message).replace("\r", " ").replace("\n", " ").strip()
    print(f"【{category}】{text}", file=sys.stderr, flush=True)

