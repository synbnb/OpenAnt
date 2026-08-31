"""SL-09 worker 的离线端到端推进测试。

这里使用仿真的 OpenGrok 响应和仓库 Manifest，验证 worker 真的会把每一
个阶段产物写入 session，并在仓库确认前停住；测试不访问网络，也不执行
Git clone。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CORE_ROOT))

from core.source_locator import (  # noqa: E402
    EndpointCapability,
    LocatorSessionStore,
    OpenGrokHTTPError,
    ProbeResult,
    RepositoryMapping,
    SearchHit,
    SearchResponse,
    SourceDocument,
    SourceLocatorRuntime,
    SourceLocatorWorker,
    LLMSearchPlanner,
    PlannerBudget,
    LLMRoleAttributor,
    load_manifest,
    runtime_from_config,
)
from core.source_locator.target_normalizer import normalize_target  # noqa: E402
from core.source_locator.worker import _budget_int, _line_kind, _mapping_role_score  # noqa: E402


TARGET_PATH = "/openharmony/base/startup/init/services/param/param_service.c"


def test_generated_dependency_name_is_not_protocol_dispatch() -> None:
    """A generated dependency filename must not satisfy the dispatch predicate."""

    target = normalize_target("/dev/unix/socket/fd_holder")
    line = "build/base/startup/init/check_deps_handler.py: case data"
    assert _line_kind(line, target) != "protocol_dispatch"


def test_server_registration_wrapper_shape_is_generic_and_source_backed() -> None:
    target = normalize_target("/dev/unix/socket/paramservice")
    assert _line_kind("info.server = PIPE_NAME;", target) == "socket_server_registration"
    assert _line_kind("info.server = NULL;", target) != "socket_server_registration"
    assert _line_kind("ret = ParamServerCreate(&task, &info);", target) == "socket_server_registration"
    assert _line_kind("CreateSocketListener(&listener, endpoint);", target) == "socket_server_registration"


def test_repository_mapping_ranking_prefers_server_roles_over_noisy_text_hits() -> None:
    from core.source_locator import EvidenceStore

    store = EvidenceStore()
    server_ids = [
        store.add_evidence(
            kind="service_config",
            source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
            line_start=441,
            excerpt="info.server = PIPE_NAME;",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="socket_server_registration",
            source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
            line_start=445,
            excerpt="ret = ParamServerCreate(&task, &info);",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="socket_accept_read",
            source_path="/openharmony/base/startup/init/services/param/linux/param_request.c",
            line_start=101,
            excerpt="recv(fd, buffer, size, 0);",
            tool_name="fixture",
        ).evidence_id,
        store.add_evidence(
            kind="protocol_dispatch",
            source_path="/openharmony/base/startup/init/services/param/linux/param_request.c",
            line_start=76,
            excerpt="switch (recvMsg->type) {",
            tool_name="fixture",
        ).evidence_id,
    ]
    noisy_ids = [
        store.add_evidence(
            kind="literal_match",
            source_path=f"/openharmony/foundation/filemanagement/dfs_service/src/noisy_{index}.cpp",
            line_start=index + 1,
            excerpt="NotifyParamService paramservice;",
            tool_name="fixture",
        ).evidence_id
        for index in range(40)
    ]
    startup = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(server_ids),
    )
    noisy = RepositoryMapping(
        project_name="filemanagement_dfs_service",
        source_root="foundation/filemanagement/dfs_service",
        repo_url="https://gitcode.com/openharmony/filemanagement_dfs_service",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/foundation/filemanagement/dfs_service/src/noisy_0.cpp",
        evidence_ids=tuple(noisy_ids),
    )

    startup_score, _ = _mapping_role_score(startup, store)
    noisy_score, _ = _mapping_role_score(noisy, store)
    assert startup_score > noisy_score


def test_llm_search_default_budget_is_twenty_rounds_and_hard_capped() -> None:
    assert _budget_int({}, "max_llm_actions", default=20, maximum=20, minimum=0) == 20
    assert _budget_int({"max_llm_actions": 99}, "max_llm_actions", default=20, maximum=20, minimum=0) == 20


class _FakeOpenGrok:
    def __init__(self) -> None:
        self.search_calls = 0
        self.document = SourceDocument(
            path=TARGET_PATH,
            source="fixture",
            content=(
                '#define PARAM_SERVICE "/dev/unix/socket/paramservice"\n'
                'service_name = "/dev/unix/socket/paramservice"\n'
                "int bind(int fd, void *addr) { return 0; }\n"
                "int accept(int fd, void *addr) { return 0; }\n"
                "int dispatch_request(int fd) { return 0; }\n"
                'request_payload = "/dev/unix/socket/paramservice";\n'
                "int connect(int fd, void *addr) { return 0; }\n"
                "int send(int fd, void *buf) { return 0; }\n"
            ),
        )
        self.response = SearchResponse(
            time_ms=1,
            result_count=1,
            start_document=0,
            end_document=0,
            results={
                TARGET_PATH: tuple(
                    SearchHit(line=line, line_number=str(number))
                    for number, line in enumerate(self.document.content.splitlines(), 1)
                )
            },
        )

    def probe(self, *, probe_path: str | None = None) -> ProbeResult:
        del probe_path
        capabilities = {
            name: EndpointCapability(name=name, available=True, status_code=200)
            for name in ("search", "raw", "file_content", "xref")
        }
        return ProbeResult(
            base_url="https://fixture.example/source",
            api_prefix="/api/v1",
            reachable=True,
            version="1.14.11",
            capabilities=capabilities,
        )

    def search(self, **kwargs) -> SearchResponse:
        self.search_calls += 1
        del kwargs
        return self.response

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        if path != TARGET_PATH:
            raise OpenGrokHTTPError(
                "fixture path not found",
                status_code=404,
                endpoint="/raw/" + path.lstrip("/"),
            )
        del max_bytes
        return self.document


def test_worker_reaches_confirmation_with_all_audit_artifacts(tmp_path: Path) -> None:
    sessions = tmp_path / "sessions"
    machine = LocatorSessionStore(sessions).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 12, "max_results": 8, "max_hits_per_file": 8},
        session_id="loc_worker123456",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    runtime = SourceLocatorRuntime(client=_FakeOpenGrok(), manifest=manifest)

    session = SourceLocatorWorker(machine, runtime=runtime).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert session.repository_mappings is not None
    mapping = session.repository_mappings["mappings"][0]
    assert mapping["project_name"] == "startup_init"
    assert mapping["status"] == "resolved"
    assert session.server_attribution is not None
    assert session.server_attribution["status"] == "HIGH"
    assert session.client_attribution is not None
    assert session.client_attribution["status"] == "HIGH"

    session_dir = sessions / session.session_id
    expected = {
        "target.json",
        "probe.json",
        "search_plan.json",
        "evidence.json",
        "path_classification.json",
        "server_attribution.json",
        "client_attribution.json",
        "repository_resolutions.json",
        "verification.json",
        "confirmation_summary.json",
        "session.json",
        "events.jsonl",
    }
    assert expected <= {path.name for path in session_dir.iterdir()}
    evidence = json.loads((session_dir / "evidence.json").read_text(encoding="utf-8"))
    kinds = {item["kind"] for item in evidence["evidence"]}
    assert {"service_config", "socket_bind_listen", "socket_accept_read", "protocol_dispatch"} <= kinds
    summary = json.loads((session_dir / "confirmation_summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["project_name"] == "startup_init"
    assert summary["repository"]["repo_url"] == "https://gitcode.com/openharmony/startup_init"
    assert summary["repository"]["destination"].endswith("source_code_base/startup_init")
    assert summary["server"]["confirmed"] is True
    assert summary["evidence"]
    assert all("source_path" in item and "excerpt" in item for item in summary["evidence"])


def test_worker_follows_source_defined_alias_to_cpp_listener(tmp_path: Path) -> None:
    """A target path should discover a related macro without an LLM call."""

    fake = _FakeOpenGrok()
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 20, "max_results": 8, "max_hits_per_file": 8},
        session_id="loc_workermacro1",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    plan = json.loads(
        (tmp_path / "sessions" / session.session_id / "search_plan.json").read_text(encoding="utf-8")
    )
    assert plan["follow_up"]["related_macros"] == ["PARAM_SERVICE"]
    assert any(
        action.startswith("full:cxx:PARAM_SERVICE")
        for action in session.executed_actions
    )


def test_worker_stops_safely_without_opengrok_configuration(tmp_path: Path) -> None:
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/unknown",
        session_id="loc_worker987654",
    )
    session = SourceLocatorWorker(machine).run_until_pause(max_steps=32)
    assert session.state == "OPENGROK_UNAVAILABLE"
    assert session.last_error == "未配置 source_locator.opengrok"


def test_runtime_from_explicit_config_loads_manifest_without_network(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "source_locator": {
                    "enabled": True,
                    "target_revision": "OpenHarmony-6.1-LTS",
                    "opengrok": {
                        "base_url": "https://fixture.example/source",
                        "project": "openharmony",
                        "api_prefix": "/api/v1",
                        "max_retries": 0,
                    },
                    "manifest": {"source": "local", "path": "tests/source_locator/fixtures/manifests/ohos.xml"},
                    "gitcode": {"destination_root": "source_code_base"},
                }
            }
        ),
        encoding="utf-8",
    )

    runtime = runtime_from_config(config, project_root=CORE_ROOT)
    assert runtime.client is not None
    assert runtime.manifest is not None
    assert runtime.manifest.projects[0].name == "communication"
    assert runtime.target_revision == "OpenHarmony-6.1-LTS"


def test_feedback_keeps_old_evidence_and_does_not_repeat_initial_queries(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()
    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerfeedback1",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    worker = SourceLocatorWorker(machine, runtime=SourceLocatorRuntime(client=fake, manifest=manifest))
    first = worker.run_until_pause(max_steps=32)
    assert first.state == "AWAIT_USER_CONFIRMATION"
    first_evidence = json.loads(
        (tmp_path / "sessions" / first.session_id / "evidence.json").read_text(encoding="utf-8")
    )
    first_calls = fake.search_calls

    machine.reject("这是错误候选，请重新检查服务端", required_role="server_consumer")
    machine.resume_after_feedback()
    after = worker.run_until_pause(max_steps=32)

    assert after.state == "PARTIAL"
    assert fake.search_calls == first_calls
    second_evidence = json.loads(
        (tmp_path / "sessions" / first.session_id / "evidence.json").read_text(encoding="utf-8")
    )
    assert second_evidence == first_evidence


def test_worker_executes_one_validated_llm_search_action_and_keeps_raw_response_out(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        evidence_id = context["evidence_ids"][0]
        return {
            "kind": "search_definition",
            "query": "PARAM_SERVICE_SOCKET",
            "justification": "验证初始命中对应的宏定义",
            "expected_relation": "macro_definition",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerllm1234",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model)
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    )

    session = worker.run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert "llm_search.json" in session.artifacts
    payload = json.loads((tmp_path / "sessions" / session.session_id / "llm_search.json").read_text(encoding="utf-8"))
    assert payload["plan"]["status"] == "READY"
    assert payload["execution"]["status"] == "ok"
    assert "raw model response" not in json.dumps(payload, ensure_ascii=False)
    assert any(item.startswith("search_definition:") for item in session.executed_actions)
    events = LocatorSessionStore(tmp_path / "sessions").events(session.session_id).load()
    llm_events = [event for event in events if event.type == "llm.search.round"]
    assert len(llm_events) == 2
    event_details = llm_events[0].details
    assert event_details["round"] == 1
    assert event_details["plan"]["action"]["kind"] == "search_definition"
    assert event_details["execution"]["query"]["params"]["def"] == "PARAM_SERVICE_SOCKET"
    assert event_details["evidence_ids"]
    assert "raw model response" not in json.dumps(event_details, ensure_ascii=False)
    assert llm_events[1].details["plan"]["status"] == "REPEATED"


def test_worker_persists_one_evidence_constrained_llm_role_review(tmp_path: Path) -> None:
    fake = _FakeOpenGrok()
    calls: list[str] = []

    def role_model(prompt: str):
        calls.append(prompt)
        context = json.loads(prompt)
        evidence_id = context["evidence"][0]["evidence_id"]
        return {
            "server": {
                "status": "confirmed",
                "confidence": "high",
                "subject": "ParamService",
                "evidence_ids": [evidence_id],
                "reason": "模型依据已读取的服务端源码证据确认角色",
            },
            "client": {
                "status": "unresolved",
                "confidence": "low",
                "subject": "",
                "evidence_ids": [],
                "reason": "当前证据没有确认客户端边界",
            },
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workerrole1234",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    role_attributor = LLMRoleAttributor(model_call=role_model)
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_role_attributor=role_attributor),
    )

    session = worker.run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert len(calls) == 1
    assert "llm_role_attribution.json" in session.artifacts
    role_payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "llm_role_attribution.json").read_text(encoding="utf-8")
    )
    assert role_payload["server"]["status"] == "confirmed"
    assert "raw model response" not in json.dumps(role_payload, ensure_ascii=False)
    server_payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "server_attribution.json").read_text(encoding="utf-8")
    )
    assert server_payload["predicates"]["llm_server_confirmed"] is True
    assert server_payload["semantic_decision"]["status"] == "confirmed"


def test_worker_feeds_each_llm_tool_result_into_next_round(tmp_path: Path) -> None:
    """Semantic rounds must observe evidence produced by the prior tool call."""

    fake = _FakeOpenGrok()
    contexts: list[dict[str, object]] = []

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        contexts.append(context)
        evidence_id = context["evidence_ids"][0]
        if len(contexts) == 1:
            return {
                "kind": "read_file",
                # The live OpenGrok index returns /openharmony/... paths,
                # while a model may use the tree-relative /base/... spelling.
                # The worker should resolve that alias from existing evidence.
                "query": "/base/startup/init/services/param/param_service.c",
                "justification": "读取初始命中的服务文件，确认源码操作",
                "expected_relation": "socket_accept_read",
                "purpose": "normal",
                "evidence_used": [evidence_id],
            }
        return {
            "kind": "search_full",
            "query": "ReceiveFds",
            "justification": "根据刚读取的源码继续找消费函数",
            "expected_relation": "socket_accept_read",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_queries": 20, "max_results": 8, "max_hits_per_file": 8, "max_llm_actions": 2},
        session_id="loc_workerllmround",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model)
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert len(contexts) == 2
    assert len(contexts[1]["evidence_ids"]) > len(contexts[0]["evidence_ids"])
    payload = json.loads(
        (tmp_path / "sessions" / session.session_id / "llm_search.json").read_text(encoding="utf-8")
    )
    assert payload["round_count"] == 2
    assert [item["plan"]["action"]["kind"] for item in payload["rounds"]] == ["read_file", "search_full"]
    assert payload["rounds"][0]["execution"]["requested_path"].startswith("/base/")
    assert payload["rounds"][0]["execution"]["path"] == TARGET_PATH
    search_plan = json.loads(
        (tmp_path / "sessions" / session.session_id / "search_plan.json").read_text(encoding="utf-8")
    )
    assert any(
        execution.get("kind") == "read_file" and execution.get("path") == TARGET_PATH
        for execution in search_plan["executions"]
    )


class _RecoveryOpenGrok:
    """OpenGrok fixture whose first evidence set misses registration.

    The recovery planner must find the second source file, after which the
    ordinary trace/attribution stages—not model prose—confirm the server.
    """

    def __init__(self) -> None:
        self.path = "/openharmony/base/startup/init/services/param/linux/param_server.c"
        self.document = SourceDocument(
            path=self.path,
            source="fixture",
            content=(
                '#define PARAM_SERVICE "/dev/unix/socket/paramservice"\n'
                'service_name = "/dev/unix/socket/paramservice"\n'
                "int start_service(void) {\n"
                "    return CreateSocketListener(&listener, endpoint);\n"
                "}\n"
                "int handle_request(int fd) {\n"
                "    recv(fd, buffer, size, 0);\n"
                "    switch (request_type) { case 1: return 0; default: return -1; }\n"
                "}\n"
            ),
        )
        self.response = SearchResponse(
            time_ms=1,
            result_count=1,
            start_document=0,
            end_document=0,
            results={
                self.path: (
                    SearchHit(
                        line="ret = CreateSocketListener(&listener, endpoint);",
                        line_number="4",
                    ),
                )
            },
        )

    def search(self, **kwargs) -> SearchResponse:
        del kwargs
        return self.response

    def read_source(self, path: str, *, max_bytes: int | None = None) -> SourceDocument:
        if path != self.path:
            raise OpenGrokHTTPError("fixture path not found", status_code=404, endpoint="/raw/" + path.lstrip("/"))
        del max_bytes
        return self.document


def test_worker_recovers_missing_server_predicate_with_bounded_llm_round(tmp_path: Path) -> None:
    """A missing acquire/bind predicate enters recovery and returns to trace."""

    from core.source_locator import EvidenceStore
    from core.source_locator.worker import _json_write

    root = tmp_path / "sessions"
    machine = LocatorSessionStore(root).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2, "max_llm_recovery_runs": 1},
        session_id="loc_workerrecovery",
    )
    target = normalize_target("/dev/unix/socket/paramservice", target_revision="OpenHarmony-6.1-LTS")
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    evidence = EvidenceStore()
    identity = evidence.add_evidence(
        kind="literal_match",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=1,
        excerpt='#define PARAM_SERVICE "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="service_config",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=2,
        excerpt='service_name = "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="socket_accept_read",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=4,
        excerpt="recv(fd, buffer, size, 0);",
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="protocol_dispatch",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=5,
        excerpt="switch (request_type)",
        tool_name="fixture",
    )
    session_dir = root / machine.session.session_id
    _json_write(session_dir / "evidence.json", evidence.to_dict())
    _json_write(session_dir / "search_plan.json", {"executions": []})
    mapping = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(item.evidence_id for item in evidence.evidence),
    )
    for state, updates in (
        ("NORMALIZE_TARGET", {"target": target.to_dict()}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {"repository_mappings": {"mappings": [mapping.to_dict()]}}),
        ("VERIFY_EVIDENCE", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)

    contexts: list[dict[str, object]] = []

    def model(prompt: str):
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        contexts.append(context)
        return {
            "kind": "search_full",
            "query": "CreateSocketListener",
            "justification": "补充缺失的服务端注册证据",
            "expected_relation": "socket_server_registration",
            "purpose": "recovery",
            "evidence_used": [context["evidence_ids"][0] or identity.evidence_id],
        }

    planner = LLMSearchPlanner(model_call=model, budget=PlannerBudget(max_actions=2, max_model_calls=2))
    worker = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=_RecoveryOpenGrok(), manifest=manifest, llm_planner=planner),
    )

    recovered = worker.advance()
    assert recovered.state == "RECOVER_EVIDENCE"
    after_recovery = worker.advance()
    assert after_recovery.state == "TRACE_EVIDENCE"
    assert contexts and contexts[0]["phase"] == "verification_recovery"
    assert "socket_acquire_or_bind" in contexts[0]["recovery"]["missing_predicates"]
    assert (session_dir / "evidence_recovery.json").exists()
    assert json.loads((session_dir / "llm_search.json").read_text(encoding="utf-8"))["round_count"] >= 1
    final = worker.run_until_pause(max_steps=16)
    assert final.state == "AWAIT_USER_CONFIRMATION"
    assert final.server_attribution and final.server_attribution["status"] == "HIGH"


def test_worker_enters_confirmation_when_server_predicate_remains_missing(tmp_path: Path) -> None:
    """A resolved mapping remains confirmable when attribution is incomplete.

    The missing predicate is deliberately kept in the persisted attribution
    and confirmation summary.  It is an advisory warning, not a terminal
    ``PARTIAL`` gate; cloning can only start after the explicit state-machine
    confirmation operation.
    """

    from core.source_locator import EvidenceStore
    from core.source_locator.worker import _json_write

    root = tmp_path / "sessions"
    machine = LocatorSessionStore(root).create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        session_id="loc_workeradvisory",
    )
    target = normalize_target("/dev/unix/socket/paramservice", target_revision="OpenHarmony-6.1-LTS")
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    evidence = EvidenceStore()
    evidence.add_evidence(
        kind="literal_match",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=1,
        excerpt='#define PARAM_SERVICE "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="service_config",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=2,
        excerpt='service_name = "/dev/unix/socket/paramservice"',
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="socket_accept_read",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=4,
        excerpt="recv(fd, buffer, size, 0);",
        tool_name="fixture",
    )
    evidence.add_evidence(
        kind="protocol_dispatch",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        line_start=5,
        excerpt="switch (request_type)",
        tool_name="fixture",
    )
    session_dir = root / machine.session.session_id
    _json_write(session_dir / "evidence.json", evidence.to_dict())
    mapping = RepositoryMapping(
        project_name="startup_init",
        source_root="base/startup/init",
        repo_url="https://gitcode.com/openharmony/startup_init",
        revision="OpenHarmony-6.1-LTS",
        source_path="/openharmony/base/startup/init/services/param/linux/param_service.c",
        evidence_ids=tuple(item.evidence_id for item in evidence.evidence),
    )
    for state, updates in (
        ("NORMALIZE_TARGET", {"target": target.to_dict()}),
        ("PROBE_OPENGROK", {}),
        ("SEARCH_INITIAL", {}),
        ("TRACE_EVIDENCE", {}),
        ("ATTRIBUTION_SERVER", {}),
        ("LOCATE_CLIENT_COMM", {}),
        ("RESOLVE_REPOSITORIES", {"repository_mappings": {"mappings": [mapping.to_dict()]}}),
        ("VERIFY_EVIDENCE", {}),
    ):
        machine.transition(state, summary_zh=state, updates=updates)

    session = SourceLocatorWorker(
        machine,
        # No planner is configured: this directly exercises the post-recovery
        # fallback and makes sure it still presents the resolved mapping.
        runtime=SourceLocatorRuntime(manifest=manifest),
    ).advance()

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert session.last_error is None
    assert session.server_attribution
    assert session.server_attribution["confirmed"] is False
    assert session.server_attribution["predicates"]["socket_acquire_or_bind"] is False

    summary = json.loads((session_dir / "confirmation_summary.json").read_text(encoding="utf-8"))
    assert summary["repository"]["project_name"] == "startup_init"
    assert summary["server"]["missing_predicates"] == ["socket_acquire_or_bind"]
    assert summary["server"]["predicate_gate"] == "advisory"
    assert any("socket_acquire_or_bind" in warning for warning in summary["warnings"])

    events = LocatorSessionStore(root).events(session.session_id).load()
    assert events[-1].type == "verification.await_confirmation"
    assert events[-1].details["predicate_gate"] == "advisory"

    # A confirmation is still an explicit state-machine operation; advancing
    # alone never enters CLONE.
    assert SourceLocatorWorker(machine, runtime=SourceLocatorRuntime(manifest=manifest)).advance().state == "AWAIT_USER_CONFIRMATION"
    machine.confirm(confirmation_id="test-confirmation")
    assert machine.session.state == "CLONE"


def test_worker_retries_duplicate_llm_action_before_accepting_novel_action(tmp_path: Path) -> None:
    """Duplicate model proposals are fed back instead of terminating the loop."""

    fake = _FakeOpenGrok()
    calls = 0
    prompts: list[dict[str, object]] = []

    def model(prompt: str):
        nonlocal calls
        calls += 1
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        prompts.append(context)
        evidence_id = context["evidence_ids"][0]
        query = "PARAM_SERVICE" if calls < 3 else "CreateSocketListener"
        return {
            "kind": "search_full",
            "query": query,
            "justification": "寻找下一条源码证据",
            "expected_relation": "socket_server_registration",
            "purpose": "normal",
            "evidence_used": [evidence_id],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2},
        session_id="loc_workerretry01",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(
        model_call=model,
        budget=PlannerBudget(max_actions=2, max_model_calls=3),
    )
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)
    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert calls == 3
    assert len(prompts) == 3
    assert prompts[2]["recovery"]["last_feedback"]
    assert prompts[2]["executed_actions"]


def test_worker_allows_different_search_semantics_for_same_query(tmp_path: Path) -> None:
    """A full-text and definition search for one term are not the same action."""

    fake = _FakeOpenGrok()
    calls = 0

    def model(prompt: str):
        nonlocal calls
        calls += 1
        context_text = prompt.split("<untrusted-context>\n", 1)[1].split("\n</untrusted-context>", 1)[0]
        context = json.loads(context_text)
        return {
            "kind": "search_full" if calls == 1 else "search_definition",
            "query": "same_semantic_term",
            "justification": "分别检查全文引用和定义位置",
            "expected_relation": "symbol_reference",
            "purpose": "normal",
            "evidence_used": [context["evidence_ids"][0]],
        }

    machine = LocatorSessionStore(tmp_path / "sessions").create(
        "/dev/unix/socket/paramservice",
        target_revision="OpenHarmony-6.1-LTS",
        budget={"max_llm_actions": 2},
        session_id="loc_workersemmode",
    )
    manifest = load_manifest(Path(__file__).parent / "fixtures" / "manifests" / "ohos.xml")
    planner = LLMSearchPlanner(model_call=model, budget=PlannerBudget(max_actions=2, max_model_calls=2))
    session = SourceLocatorWorker(
        machine,
        runtime=SourceLocatorRuntime(client=fake, manifest=manifest, llm_planner=planner),
    ).run_until_pause(max_steps=32)

    assert session.state == "AWAIT_USER_CONFIRMATION"
    assert calls == 2
    assert "search_full:same_semantic_term" in session.executed_actions
    assert "search_definition:same_semantic_term" in session.executed_actions
