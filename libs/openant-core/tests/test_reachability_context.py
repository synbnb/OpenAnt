from core.reachability_context import (
    build_reachability_context,
    _rank_entry_paths,
    _select_primary_entry_path,
)


def test_entry_path_ranking_uses_method_name_not_source_filename():
    """A helper in ``*_listen.cpp`` is not itself a socket listener."""
    functions = {
        "dns_resolv_listen.cpp:Internal::ProcGetCacheSize": {
            "name": "Internal::ProcGetCacheSize"
        },
        "dns_resolv_listen.cpp:Internal::StartListen": {
            "name": "Internal::StartListen"
        },
        "sink.cpp:Sink": {"name": "Sink"},
    }
    paths = [
        ["dns_resolv_listen.cpp:Internal::ProcGetCacheSize", "sink.cpp:Sink"],
        ["dns_resolv_listen.cpp:Internal::StartListen", "sink.cpp:Sink"],
    ]
    ranked = _rank_entry_paths(paths, functions)
    assert ranked[0][0] == "dns_resolv_listen.cpp:Internal::StartListen"


def test_primary_path_prefers_validated_upstream_over_semantic_self_root():
    """A retained target root must not hide an available caller chain."""
    functions = {
        "log.cpp:LogCollector::onDataRecv": {"name": "LogCollector::onDataRecv"},
        "main.cpp:main": {"name": "main"},
        "main.cpp:Entry": {"name": "Entry"},
    }
    strict = [
        ["log.cpp:LogCollector::onDataRecv"],
        ["main.cpp:main", "main.cpp:Entry", "log.cpp:LogCollector::onDataRecv"],
    ]
    kind, primary, statuses = _select_primary_entry_path(strict, [], functions)
    assert kind == "strict"
    assert primary == strict[1]
    assert statuses == []


def test_primary_path_prefers_receive_loop_over_process_main():
    """A serving/communication loop is the useful boundary when recorded."""
    functions = {
        "main.cpp:main": {"name": "main"},
        "socket.cpp:ServingThread": {"name": "ServingThread"},
        "sink.cpp:Sink": {"name": "Sink"},
    }
    strict = [
        ["main.cpp:main", "sink.cpp:Sink"],
        ["socket.cpp:ServingThread", "sink.cpp:Sink"],
    ]
    kind, primary, _ = _select_primary_entry_path(strict, [], functions)
    assert kind == "strict"
    assert primary == strict[1]


def test_reachability_context_contains_top_level_entry_and_source_nodes(tmp_path):
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"graph_version":"g1","functions":{'
        '"main.cpp:main":{"name":"main","file_path":"main.cpp","start_line":1,"end_line":3,"unit_type":"main","code":"int main(){}"},'
        '"svc.cpp:Service::Handle":{"name":"Service::Handle","file_path":"svc.cpp","start_line":10,"end_line":12,"unit_type":"method","code":"void Service::Handle(){}"},'
        '"sink.cpp:Sink":{"name":"Sink","file_path":"sink.cpp","start_line":20,"end_line":22,"unit_type":"function","code":"void Sink(){}"}},'
        '"call_graph":{"main.cpp:main":["svc.cpp:Service::Handle"],"svc.cpp:Service::Handle":["sink.cpp:Sink"]}}',
        encoding="utf-8",
    )
    dataset = {"units":[{"id":"sink.cpp:Sink"}],"metadata":{}}
    enriched = build_reachability_context(dataset, [str(graph_path)], platform="generic")
    context = enriched["units"][0]["reachability_context"]
    assert context["status"] == "path_found"
    assert context["top_level_entry"] == "main.cpp:main"
    assert context["entry_path_ids"] == [[
        "main.cpp:main", "svc.cpp:Service::Handle", "sink.cpp:Sink"
    ]]
    assert context["entry_paths"][0][0]["source_excerpt"] == "int main(){}"
    assert context["generic_entry_path_found"] is True
    assert context["primary_entry_path_kind"] == "strict"
    assert context["primary_top_level_entry"] == "main.cpp:main"
    bundle = context["primary_path_source_bundle"]
    assert bundle["order"] == "entry_to_target"
    assert bundle["source_complete"] is True
    assert [node["id"] for node in bundle["nodes"]] == [
        "main.cpp:main", "svc.cpp:Service::Handle", "sink.cpp:Sink"
    ]
    assert bundle["nodes"][0]["source"] == "int main(){}"
    assert context["supporting_context_bundle"]["nodes"] == []
    assert context["attack_chain_context_status"] == "not_evaluated"
    assert context["attack_chain_context_complete"] is None
    assert "dangerous_parameter_not_identified" in context["attack_chain_missing_evidence"]
    assert enriched["metadata"]["reachability_context"]["units_with_paths"] == 1


def test_reachability_context_preserves_unknown_when_no_entry_is_proven(tmp_path):
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"graph_version":"g2","functions":{'
        '"a.cpp:A":{"name":"A","file_path":"a.cpp","start_line":1,"end_line":2,"code":"void A(){}"}},'
        '"call_graph":{}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"a.cpp:A"}],"metadata":{}},
        [str(graph_path)],
    )
    context = enriched["units"][0]["reachability_context"]
    assert context["status"] == "unknown"
    assert context["top_level_entry"] is None
    assert context["generic_entry_path_found"] is False
    assert context["attack_chain_context_status"] == "not_evaluated"


def test_reachability_context_does_not_call_incidental_file_read_a_top_level_entry(tmp_path):
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"graph_version":"g3","functions":{'
        '"sink.cpp:Sink":{"name":"Sink","file_path":"sink.cpp",'
        '"start_line":4,"end_line":8,"unit_type":"method",'
        '"code":"void Sink(){ open(fd, \\"r\\"); }"}},"call_graph":{}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"sink.cpp:Sink"}],"metadata":{}},
        [str(graph_path)],
    )
    context = enriched["units"][0]["reachability_context"]
    assert context["status"] == "unknown"
    assert enriched["metadata"]["reachability_context"]["incidental_root_count"] == 1


def test_reachability_context_attaches_callsite_ledger_without_claiming_attack_chain_complete(tmp_path):
    graph_dir = tmp_path / "cpp"
    graph_dir.mkdir()
    graph_path = graph_dir / "effective_call_graph.json"
    graph_path.write_text(
        '{"graph_version":"g4","functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":10,"end_line":20,"code":"void Handle(){}"},'
        '"sink.cpp:Sink":{"name":"Sink","file_path":"sink.cpp",'
        '"start_line":30,"end_line":40,"code":"void Sink(){}"}},'
        '"call_graph":{"socket.cpp:Handle":["sink.cpp:Sink"]}}',
        encoding="utf-8",
    )
    (graph_dir / "callsite_ledger.json").write_text(
        '{"call_sites":[{"site_id":"site-1","caller_id":"socket.cpp:Handle",'
        '"linked_target_ids":["sink.cpp:Sink"],"candidate_completeness":"complete",'
        '"file":"socket.cpp","line_start":14,"line_end":14,'
        '"expression":"Sink(data)"}]}',
        encoding="utf-8",
    )
    (graph_dir / "object_flow_facts.json").write_text(
        '{"facts":[{"fact_id":"flow-1","fact_kind":"cross_function_argument_flow",'
        '"status":"candidate","caller_id":"socket.cpp:Handle",'
        '"target_id":"sink.cpp:Sink","file":"socket.cpp","line_start":14,'
        '"expression":"Sink(data)","value":{"variables":["data"],'
        '"argument_pairs":[{"index":0,"caller_expression":"data",'
        '"callee_parameter":"input"}]},"attributes":{"call_site_id":"site-1"}}]}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"sink.cpp:Sink"}],"metadata":{}},
        [str(graph_path)],
    )
    context = enriched["units"][0]["reachability_context"]
    assert context["attack_chain_context_status"] == "incomplete"
    assert context["attack_chain_context_complete"] is False
    callsites = context["attack_chain_context"]["callsite_contexts"]
    assert callsites[0]["callsite_id"] == "site-1"
    assert callsites[0]["location"] == "socket.cpp:14"
    assert callsites[0]["flow_facts"][0]["fact_kind"] == "cross_function_argument_flow"
    assert callsites[0]["flow_facts"][0]["value"]["argument_pairs"][0]["callee_parameter"] == "input"
    assert "source_to_sink_dataflow_not_traced" in context["attack_chain_missing_evidence"]


def test_reachability_context_preserves_enhancer_data_flow_as_incomplete_candidate(tmp_path):
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{"a.cpp:A":{"name":"A","file_path":"a.cpp",'
        '"start_line":1,"end_line":2,"code":"void A(){}"}},"call_graph":{}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context({
        "units": [{
            "id": "a.cpp:A",
            "llm_context": {"data_flow": {
                "inputs": ["UDP payload"],
                "tainted_variables": ["cmd"],
                "security_relevant_flows": ["payload -> cmd"],
            }},
        }],
        "metadata": {},
    }, [str(graph_path)])
    context = enriched["units"][0]["reachability_context"]
    assert context["attack_chain_context_status"] == "incomplete"
    assert context["attack_chain_context_complete"] is False
    candidate = context["attack_chain_context"]["callsite_contexts"][0]
    assert candidate["source"] == "UDP payload"
    assert candidate["state_flow"]["tainted_variables"] == ["cmd"]


def test_reachability_context_separates_candidate_dispatch_path_from_strict_path(tmp_path):
    graph_dir = tmp_path / "graph"
    graph_dir.mkdir()
    graph_path = graph_dir / "call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":1,"end_line":4,"code":"void Handle(){ ItemData(); }"},'
        '"item.cpp:ItemData":{"name":"ItemData","file_path":"item.cpp",'
        '"start_line":10,"end_line":14,"code":"void ItemData(){ Work(); }"},'
        '"work.cpp:Work":{"name":"Work","file_path":"work.cpp",'
        '"start_line":20,"end_line":24,"code":"void Work(){ Sink(); }"},'
        '"sink.cpp:Sink":{"name":"Sink","file_path":"sink.cpp",'
        '"start_line":30,"end_line":34,"code":"void Sink(){}"}},'
        '"call_graph":{"item.cpp:ItemData":["work.cpp:Work"],'
        '"work.cpp:Work":["sink.cpp:Sink"]}}',
        encoding="utf-8",
    )
    (graph_dir / "callsite_ledger.json").write_text(
        '{"call_sites":[{"site_id":"dispatch-1",'
        '"caller_id":"socket.cpp:Handle",'
        '"candidate_target_ids":["item.cpp:ItemData"],'
        '"binding_status":"partial","dispatch_status":"partial",'
        '"candidate_completeness":"unknown","graph_status":"edge_missing",'
        '"file":"socket.cpp","line_start":2,"expression":"profiler->ItemData()"}]}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[
            {"id":"socket.cpp:Handle", "is_entry_point":True},
            {"id":"sink.cpp:Sink"},
        ], "metadata":{}},
        [str(graph_path)],
    )
    context = next(
        unit["reachability_context"] for unit in enriched["units"]
        if unit["id"] == "sink.cpp:Sink"
    )
    assert context["generic_entry_path_found"] is False
    assert context["candidate_entry_path_found"] is True
    assert context["candidate_entry_path_ids"][0] == [
        "socket.cpp:Handle", "item.cpp:ItemData", "work.cpp:Work", "sink.cpp:Sink"
    ]
    assert context["candidate_entry_path_edge_statuses"][0][0] == "candidate"
    assert context["primary_entry_path_kind"] == "candidate"
    assert context["primary_top_level_entry"] == "socket.cpp:Handle"
    assert context["primary_entry_path_source_complete"] is True


def test_candidate_path_requires_source_callsite_evidence(tmp_path):
    graph_dir = tmp_path / "graph"
    graph_dir.mkdir()
    graph_path = graph_dir / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":1,"end_line":4,"code":"void Handle(){ Work(); }"},'
        '"work.cpp:Work":{"name":"Work","file_path":"work.cpp",'
        '"start_line":10,"end_line":14,"code":"void Work(){}"}},'
        '"call_graph":{}}',
        encoding="utf-8",
    )
    (graph_dir / "callsite_ledger.json").write_text(
        '{"call_sites":[{"site_id":"dispatch-1",'
        '"caller_id":"socket.cpp:Handle",'
        '"candidate_target_ids":["work.cpp:Work"],'
        '"binding_status":"partial","dispatch_status":"partial",'
        '"candidate_completeness":"unknown","graph_status":"edge_missing"}]}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"socket.cpp:Handle", "is_entry_point":True},
                  {"id":"work.cpp:Work"}], "metadata":{}},
        [str(graph_path)],
    )
    context = next(
        unit["reachability_context"] for unit in enriched["units"]
        if unit["id"] == "work.cpp:Work"
    )
    assert context["candidate_entry_path_found"] is True
    assert context["candidate_entry_path_source_complete"] is True
    assert context["candidate_entry_path_validation"][0]["valid"] is False
    assert any(
        issue.startswith("candidate_callsite_source_evidence_missing:")
        for issue in context["candidate_entry_path_validation"][0]["issues"]
    )


def test_candidate_path_with_source_callsite_evidence_validates(tmp_path):
    graph_dir = tmp_path / "graph"
    graph_dir.mkdir()
    graph_path = graph_dir / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":1,"end_line":4,"code":"void Handle(){ Work(data); }"},'
        '"work.cpp:Work":{"name":"Work","file_path":"work.cpp",'
        '"start_line":10,"end_line":14,"code":"void Work(){}"}},'
        '"call_graph":{}}',
        encoding="utf-8",
    )
    (graph_dir / "callsite_ledger.json").write_text(
        '{"call_sites":[{"site_id":"dispatch-1",'
        '"caller_id":"socket.cpp:Handle",'
        '"candidate_target_ids":["work.cpp:Work"],'
        '"binding_status":"partial","dispatch_status":"partial",'
        '"candidate_completeness":"unknown","graph_status":"edge_missing",'
        '"file":"socket.cpp","line_start":2,"line_end":2,'
        '"expression":"Work(data)"}]}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"socket.cpp:Handle", "is_entry_point":True},
                  {"id":"work.cpp:Work"}], "metadata":{}},
        [str(graph_path)],
    )
    context = next(
        unit["reachability_context"] for unit in enriched["units"]
        if unit["id"] == "work.cpp:Work"
    )
    assert context["candidate_entry_path_validation"][0]["valid"] is True


def test_context_rejects_constant_false_logging_path_to_file_sink(tmp_path):
    """Do not compose LOGI(false) with SpLog's write-only continuation."""
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":1,"end_line":3,"unit_type":"handler",'
        '"code":"void Handle(){ ItemData(); }"},'
        '"network.cpp:ItemData":{"name":"Network::ItemData","file_path":"network.cpp",'
        '"start_line":10,"end_line":14,"code":"void ItemData(){ LOGI(\\"done\\"); }"},'
        '"log.cpp:SpLog":{"name":"SpLog","file_path":"log.cpp",'
        '"start_line":20,"end_line":28,"code":"void SpLog(bool isWriteLog){ '
        'if (!isWriteLog) { return; } GetLogFilePath(); }"},'
        '"log.cpp:GetLogFilePath":{"name":"GetLogFilePath","file_path":"log.cpp",'
        '"start_line":30,"end_line":34,"code":"void GetLogFilePath(){ TarFile(); }"},'
        '"log.cpp:TarFile":{"name":"TarFile","file_path":"log.cpp",'
        '"start_line":35,"end_line":39,"code":"void TarFile(){ LoadCmd(); }"},'
        '"sink.cpp:LoadCmd":{"name":"LoadCmd","file_path":"sink.cpp",'
        '"start_line":40,"end_line":42,"code":"void LoadCmd(){}"}},'
        '"call_graph":{'
        '"socket.cpp:Handle":["network.cpp:ItemData"],'
        '"network.cpp:ItemData":["log.cpp:SpLog"],'
        '"log.cpp:SpLog":["log.cpp:GetLogFilePath"],'
        '"log.cpp:GetLogFilePath":["log.cpp:TarFile"],'
        '"log.cpp:TarFile":["sink.cpp:LoadCmd"]}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"socket.cpp:Handle", "is_entry_point": True},
                  {"id":"sink.cpp:LoadCmd"}], "metadata":{}},
        [str(graph_path)],
    )
    context = next(
        unit["reachability_context"] for unit in enriched["units"]
        if unit["id"] == "sink.cpp:LoadCmd"
    )
    all_paths = context["entry_path_ids"] + context["candidate_entry_path_ids"]
    assert not any("log.cpp:SpLog" in path for path in all_paths)


def test_candidate_context_does_not_stop_at_worker_only_llm_entry(tmp_path):
    """Keep the upstream external boundary visible past a detached worker root."""
    graph_dir = tmp_path / "graph"
    graph_dir.mkdir()
    graph_path = graph_dir / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":1,"end_line":4,"code":"void Handle(){ ItemData(); }"},'
        '"item.cpp:ItemData":{"name":"ItemData","file_path":"item.cpp",'
        '"start_line":10,"end_line":14,"code":"void ItemData(){ Thread(); }"},'
        '"worker.cpp:Thread":{"name":"Thread","file_path":"worker.cpp",'
        '"start_line":20,"end_line":24,"code":"void Thread(){ Sink(); }"},'
        '"sink.cpp:Sink":{"name":"Sink","file_path":"sink.cpp",'
        '"start_line":30,"end_line":34,"code":"void Sink(){}"}},'
        '"call_graph":{"item.cpp:ItemData":["worker.cpp:Thread"],'
        '"worker.cpp:Thread":["sink.cpp:Sink"]}}',
        encoding="utf-8",
    )
    (graph_dir / "callsite_ledger.json").write_text(
        '{"call_sites":[{"site_id":"socket-item",'
        '"caller_id":"socket.cpp:Handle",'
        '"candidate_target_ids":["item.cpp:ItemData"],'
        '"binding_status":"partial","dispatch_status":"partial",'
        '"candidate_completeness":"unknown","graph_status":"edge_missing",'
        '"file":"socket.cpp","line_start":2,'
        '"expression":"item->ItemData(payload)"}]}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[
            {"id":"socket.cpp:Handle", "is_entry_point":True,
             "semantic_reachability_seed":True,
             "llm_reachability_signals":[
                 {"kind":"external_input", "confidence":"high"}
             ]},
            {"id":"worker.cpp:Thread", "is_entry_point":True,
             "llm_reachability_signals":[
                 {"kind":"entry_point", "confidence":"high"}
             ]},
            {"id":"sink.cpp:Sink"},
        ], "metadata":{}},
        [str(graph_path)],
    )
    context = next(
        unit["reachability_context"] for unit in enriched["units"]
        if unit["id"] == "sink.cpp:Sink"
    )
    assert context["candidate_entry_path_found"] is True
    assert context["candidate_entry_path_ids"][0] == [
        "socket.cpp:Handle", "item.cpp:ItemData",
        "worker.cpp:Thread", "sink.cpp:Sink",
    ]
    assert context["candidate_entry_path_edge_statuses"][0] == [
        "candidate", "native", "native",
    ]
    assert context["primary_entry_path_kind"] == "candidate"
    assert context["primary_top_level_entry"] == "socket.cpp:Handle"


def test_entry_root_still_searches_upstream_dispatcher(tmp_path):
    """An entry-marked target must not hide its caller/dispatcher."""
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"server.cpp:Start":{"name":"Start","file_path":"server.cpp",'
        '"start_line":1,"end_line":3,"unit_type":"init",'
        '"code":"void Start(){ Handle(); }"},'
        '"socket.cpp:Handle":{"name":"Handle","file_path":"socket.cpp",'
        '"start_line":10,"end_line":14,"unit_type":"handler",'
        '"code":"void Handle(){ Target(); }"},'
        '"target.cpp:Target":{"name":"Target","file_path":"target.cpp",'
        '"start_line":20,"end_line":24,"unit_type":"handler",'
        '"code":"void Target(){}"}},'
        '"call_graph":{"server.cpp:Start":["socket.cpp:Handle"],'
        '"socket.cpp:Handle":["target.cpp:Target"]}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"target.cpp:Target", "is_entry_point":True}], "metadata":{}},
        [str(graph_path)],
    )
    context = enriched["units"][0]["reachability_context"]
    assert context["generic_entry_path_found"] is True
    assert any(path[:3] == [
        "server.cpp:Start", "socket.cpp:Handle", "target.cpp:Target"
    ] for path in context["entry_path_ids"])
    assert context["top_level_entry"] == "server.cpp:Start"


def test_context_rejects_synthetic_callback_scope_cycle(tmp_path):
    """Do not compose sibling lambda nodes through their enclosing method."""
    graph_path = tmp_path / "effective_call_graph.json"
    graph_path.write_text(
        '{"functions":{'
        '"a.cpp:Outer.CallbackA":{"name":"Outer.CallbackA","file_path":"a.cpp",'
        '"start_line":1,"end_line":2,"code":"auto a(){}"},'
        '"a.cpp:Outer":{"name":"Outer","file_path":"a.cpp",'
        '"start_line":3,"end_line":4,"code":"void Outer(){}"},'
        '"a.cpp:Outer.CallbackB":{"name":"Outer.CallbackB","file_path":"a.cpp",'
        '"start_line":5,"end_line":6,"code":"auto b(){}"}},'
        '"call_graph":{"a.cpp:Outer.CallbackA":["a.cpp:Outer"],'
        '"a.cpp:Outer":["a.cpp:Outer.CallbackB"]}}',
        encoding="utf-8",
    )
    enriched = build_reachability_context(
        {"units":[{"id":"a.cpp:Outer.CallbackB", "is_entry_point":True}],
         "metadata":{}},
        [str(graph_path)],
    )
    context = enriched["units"][0]["reachability_context"]
    assert context["entry_path_ids"] == [["a.cpp:Outer.CallbackB"]]
