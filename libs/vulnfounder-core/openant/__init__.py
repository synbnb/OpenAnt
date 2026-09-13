"""Compatibility package for integrations that still import :mod:`openant`.

New code should import :mod:`vulnfounder`.  This adapter remains intentionally
small so the legacy Python module can be removed after the migration window.
"""

from vulnfounder import __version__

__all__ = ["__version__"]
