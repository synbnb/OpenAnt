"""Regression tests for C/C++ language selection of shared ``.h`` headers.

OpenHarmony uses ``.h`` for both C headers and C++ headers.  The C parser
cannot model C++ class members correctly, so the extractor must choose the
grammar from the header content when the extension is ambiguous.
"""

import importlib.util
import sys
from pathlib import Path


CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

_spec = importlib.util.spec_from_file_location(
    "c_function_extractor_header_language",
    str(CORE / "parsers" / "c" / "function_extractor.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
FunctionExtractor = _mod.FunctionExtractor


def test_cpp_inline_methods_in_shared_header_are_extracted(tmp_path):
    """A C++ class method in a ``.h`` file must retain its method scope/code."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "epoller.h").write_text(
        """
#pragma once
#include <sys/socket.h>

namespace demo {
class EpollServer {
public:
    void RunForEvents(int server_fd) {
        (void)accept(server_fd, nullptr, nullptr);
    }
};
}  // namespace demo
""",
        encoding="utf-8",
    )

    functions = FunctionExtractor(str(repo)).extract_all(["epoller.h"])["functions"]

    method_id = "epoller.h:demo::EpollServer::RunForEvents"
    assert method_id in functions, f"C++ inline method missing: {sorted(functions)}"
    method = functions[method_id]
    assert method["class_name"] == "EpollServer"
    assert method["unit_type"] == "method"
    assert method["start_line"] == 8
    assert method["end_line"] == 10
    assert "accept(server_fd" in method["code"]


def test_c_top_level_function_in_shared_header_keeps_c_behavior(tmp_path):
    """A plain C header remains parseable as a top-level C function."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "socket.h").write_text(
        """
#pragma once
int open_socket(int fd) {
    return fd;
}
""",
        encoding="utf-8",
    )

    functions = FunctionExtractor(str(repo)).extract_all(["socket.h"])["functions"]

    function_id = "socket.h:open_socket"
    assert function_id in functions, f"C header function missing: {sorted(functions)}"
    assert functions[function_id]["unit_type"] == "function"
