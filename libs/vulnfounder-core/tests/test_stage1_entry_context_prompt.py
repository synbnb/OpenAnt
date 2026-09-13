from prompts.vulnerability_analysis import format_reachability_context_for_prompt


def test_stage1_prompt_contains_top_level_entry_and_source_backed_nodes():
    rendered = format_reachability_context_for_prompt({
        "semantic_reachability_seed": False,
        "entry_context": {
            "status": "path_found",
            "top_level_entry": "main.cpp:main",
            "upstream_complete": True,
            "graph_versions": ["g1"],
            "root_entry_points": [{"id": "main.cpp:main", "kind": "structural_or_explicit"}],
            "entry_paths": [[{
                "id": "main.cpp:main",
                "file": "main.cpp",
                "line_start": 1,
                "line_end": 3,
                "source_excerpt": "int main() { Handle(input); }",
            }]],
        },
    })
    assert "Deterministic Entry-Path Context" in rendered
    assert "main.cpp:main" in rendered
    assert "main.cpp:1" in rendered
    assert "independently verify" in rendered
    assert "Attack-Chain Context" in rendered
    assert "unknown/not evaluated" in rendered


def test_stage1_prompt_renders_callsite_specific_attack_chain_without_promoting_it():
    rendered = format_reachability_context_for_prompt({
        "entry_context": {
            "status": "path_found",
            "generic_entry_path_found": True,
            "generic_entry_path_source_complete": True,
            "top_level_entry": "socket.cpp:HandleMsg",
            "upstream_complete": True,
            "attack_chain_context": {
                "status": "incomplete",
                "complete": False,
                "provenance": "context_enhancer",
                "missing_evidence": ["dangerous_parameter_sink_binding_unverified"],
                "callsite_contexts": [{
                    "callsite_id": "network.cpp:154",
                    "dangerous_operation": "SPUtils::LoadCmd",
                    "dangerous_parameter": "cmd",
                    "source": "UDP payload -> shared state",
                    "sink": "popen(cmd)",
                    "ordered_steps": ["HandleMsg", "ThreadGetHapNetwork", "LoadCmd"],
                }],
            },
        },
    })
    assert "Callsite-specific context(s)" in rendered
    assert "network.cpp:154" in rendered
    assert "dangerous_parameter=cmd" in rendered
    assert "Complete: no" in rendered
    assert "dangerous_parameter_sink_binding_unverified" in rendered


def test_stage1_prompt_renders_upstream_boundary_signals_as_untrusted():
    rendered = format_reachability_context_for_prompt({
        "entry_context": {
            "status": "path_found",
            "attack_chain_context": {"status": "incomplete", "complete": False},
            "upstream_boundary_signals": [{
                "unit_id": "socket.cpp:HandleMsg",
                "kind": "external_input",
                "confidence": "high",
                "boundary": "socket",
                "direction": "receive",
                "evidence_excerpt": "recvBuf = RecvBuf()",
            }],
        },
    })
    assert "Upstream Boundary Signals" in rendered
    assert "socket.cpp:HandleMsg" in rendered
    assert "UNTRUSTED, NOT A COMPLETE CHAIN" in rendered


def test_stage1_prompt_renders_candidate_dispatch_path_separately():
    rendered = format_reachability_context_for_prompt({
        "entry_context": {
            "status": "candidate_path_found",
            "candidate_path_count": 1,
            "candidate_entry_path_ids": [[
                "socket.cpp:HandleMsg", "item.cpp:ItemData", "sink.cpp:Sink"
            ]],
            "candidate_entry_paths": [[
                {"id": "socket.cpp:HandleMsg", "file": "socket.cpp", "line_start": 10,
                 "source_excerpt": "recvfrom(fd, buf, size, 0);"},
                {"id": "item.cpp:ItemData", "file": "item.cpp", "line_start": 20,
                 "source_excerpt": "return item;"},
                {"id": "sink.cpp:Sink", "file": "sink.cpp", "line_start": 30,
                 "source_excerpt": "popen(cmd, \"r\");"},
            ]],
            "candidate_entry_path_edge_statuses": [["candidate", "native"]],
            "candidate_missing_evidence": ["candidate_dispatch_or_binding_not_proven"],
        },
    })
    assert "Candidate Entry-Path Context" in rendered
    assert "UNVERIFIED" in rendered
    assert "socket.cpp:HandleMsg" in rendered
    assert "candidate_dispatch_or_binding_not_proven" in rendered


def test_stage1_prompt_renders_ordered_full_source_bundle():
    rendered = format_reachability_context_for_prompt({
        "entry_context": {
            "status": "path_found",
            "primary_entry_path_kind": "strict",
            "primary_entry_path": [{
                "id": "entry.cpp:Handle",
                "file": "entry.cpp",
                "line_start": 10,
                "source_excerpt": "recv(fd, buf, len, 0);",
            }, {
                "id": "sink.cpp:Sink",
                "file": "sink.cpp",
                "line_start": 40,
                "source_excerpt": "popen(cmd, \"r\");",
            }],
            "primary_entry_path_ids": [["entry.cpp:Handle", "sink.cpp:Sink"]],
            "primary_path_source_bundle": {
                "schema_version": 2,
                "kind": "strict",
                "order": "entry_to_target",
                "source_complete": True,
                "nodes": [
                    {"order": 1, "id": "entry.cpp:Handle", "file": "entry.cpp",
                     "line_start": 10, "line_end": 20,
                     "source": "void Handle() { recv(fd, buf, len, 0); }",
                     "source_complete": True},
                    {"order": 2, "id": "sink.cpp:Sink", "file": "sink.cpp",
                     "line_start": 40, "line_end": 44,
                     "source": "void Sink() { popen(cmd, \"r\"); }",
                     "source_complete": True},
                ],
                "edges": [{"caller": "entry.cpp:Handle", "callee": "sink.cpp:Sink",
                           "status": "native"}],
            },
        },
    })
    assert "Ordered Primary Path Full-Source Bundle" in rendered
    assert "void Handle() { recv(fd, buf, len, 0); }" in rendered
    assert "void Sink() { popen(cmd, \"r\"); }" in rendered
    assert rendered.index("void Handle()") < rendered.index("void Sink()")
    assert "Bundle source complete: yes" in rendered
