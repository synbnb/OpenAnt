"""Legacy ``openant.cli`` compatibility alias.

Replacing the module object, instead of copying exported names, preserves
monkeypatching and integrations that access private helper attributes.
"""

import sys

from vulnfounder import cli as _implementation

sys.modules[__name__] = _implementation
