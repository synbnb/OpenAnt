"""Bounded execution of deterministic OpenGrok locator queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .opengrok_client import OpenGrokError, SearchResponse
from .target_normalizer import (
    LocatorQuery,
    TargetNormalizationError,
    TargetSpec,
    build_initial_queries,
)


class SearchPlannerError(ValueError):
    """Raised when a query plan cannot satisfy the execution contract."""


def _safe_message(value: Any) -> str:
    return " ".join(str(value).split())[:240]


@dataclass(frozen=True)
class SearchExecution:
    """Audit record for one planned query."""

    query: LocatorQuery
    status: str
    response: SearchResponse | None = None
    error_type: str | None = None
    error_message: str | None = None
    status_code: int | None = None

    def __post_init__(self) -> None:
        if self.status not in {"ok", "error", "skipped_duplicate"}:
            raise SearchPlannerError("查询执行状态无效")
        if self.status == "ok" and self.response is None:
            raise SearchPlannerError("成功查询必须包含响应")
        if self.status != "ok" and self.response is not None:
            raise SearchPlannerError("失败或跳过的查询不能包含响应")
        if self.status == "error" and not self.error_type:
            raise SearchPlannerError("失败查询必须包含错误类型")

    @property
    def result_count(self) -> int:
        return self.response.result_count if self.response is not None else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query.to_dict(),
            "status": self.status,
            "response": self.response.to_dict() if self.response is not None else None,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "status_code": self.status_code,
        }


@dataclass(frozen=True)
class SearchPlanResult:
    """Serializable result of one bounded query-plan execution."""

    executions: tuple[SearchExecution, ...]
    target: TargetSpec | None = None

    @property
    def successful_queries(self) -> int:
        return sum(execution.status == "ok" for execution in self.executions)

    @property
    def failed_queries(self) -> int:
        return sum(execution.status == "error" for execution in self.executions)

    @property
    def skipped_queries(self) -> int:
        return sum(execution.status == "skipped_duplicate" for execution in self.executions)

    @property
    def unique_result_paths(self) -> tuple[str, ...]:
        paths: list[str] = []
        seen: set[str] = set()
        for execution in self.executions:
            if execution.response is None:
                continue
            for path in execution.response.results:
                if path not in seen:
                    seen.add(path)
                    paths.append(path)
        return tuple(paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "openant.source-locator.search-plan.v1",
            "target": self.target.to_dict() if self.target is not None else None,
            "summary": {
                "planned_queries": len(self.executions),
                "successful_queries": self.successful_queries,
                "failed_queries": self.failed_queries,
                "skipped_duplicate_queries": self.skipped_queries,
                "unique_result_files": len(self.unique_result_paths),
            },
            "executions": [execution.to_dict() for execution in self.executions],
        }


class SearchPlanner:
    """Execute only validated, bounded queries through ``OpenGrokClient``."""

    def __init__(
        self,
        client: Any,
        *,
        max_results: int = 50,
        max_hits_per_file: int = 3,
        max_queries: int = 12,
    ) -> None:
        if not hasattr(client, "search") or not callable(client.search):
            raise SearchPlannerError("client 必须提供可调用的 search 方法")
        if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= 1000:
            raise SearchPlannerError("max_results 必须是 1 到 1000 之间的整数")
        if (
            isinstance(max_hits_per_file, bool)
            or not isinstance(max_hits_per_file, int)
            or not 1 <= max_hits_per_file <= 1000
        ):
            raise SearchPlannerError("max_hits_per_file 必须是 1 到 1000 之间的整数")
        if isinstance(max_queries, bool) or not isinstance(max_queries, int) or not 1 <= max_queries <= 32:
            raise SearchPlannerError("max_queries 必须是 1 到 32 之间的整数")
        self.client = client
        self.max_results = max_results
        self.max_hits_per_file = max_hits_per_file
        self.max_queries = max_queries

    def execute_initial(self, target: TargetSpec) -> SearchPlanResult:
        """Build and execute the deterministic first-pass plan for a target."""

        try:
            queries = build_initial_queries(target, max_queries=self.max_queries)
        except TargetNormalizationError as exc:
            raise SearchPlannerError(str(exc)) from exc
        return self.execute(queries, target=target)

    def execute(
        self,
        queries: Iterable[LocatorQuery],
        *,
        target: TargetSpec | None = None,
    ) -> SearchPlanResult:
        """Run a query iterable in order and retain per-query outcomes.

        A duplicate is represented as ``skipped_duplicate`` rather than being
        silently removed, so the audit result explains why fewer HTTP requests
        were made.  A typed OpenGrok failure is recorded and execution then
        continues with the next query; arbitrary programming errors are not
        swallowed.
        """

        try:
            query_list = list(queries)
        except TypeError as exc:
            raise SearchPlannerError("queries 必须是可迭代对象") from exc
        if not query_list:
            raise SearchPlannerError("queries 不能为空")
        if len(query_list) > self.max_queries:
            raise SearchPlannerError(
                f"查询数量 {len(query_list)} 超过上限 {self.max_queries}"
            )

        executions: list[SearchExecution] = []
        seen: set[tuple[str, str, str]] = set()
        for query in query_list:
            if not isinstance(query, LocatorQuery):
                raise SearchPlannerError("queries 只能包含 LocatorQuery")
            key = (query.kind, query.value, query.file_type)
            if key in seen:
                executions.append(SearchExecution(query=query, status="skipped_duplicate"))
                continue
            seen.add(key)
            try:
                response = self.client.search(
                    full=query.value if query.kind == "full" else None,
                    definition=query.value if query.kind == "definition" else None,
                    symbol=query.value if query.kind == "symbol" else None,
                    path=query.value if query.kind == "path" else None,
                    file_type=query.file_type,
                    max_results=self.max_results,
                    max_hits_per_file=self.max_hits_per_file,
                )
            except (OpenGrokError, ValueError) as exc:
                executions.append(
                    SearchExecution(
                        query=query,
                        status="error",
                        error_type=type(exc).__name__,
                        error_message=_safe_message(exc),
                        status_code=getattr(exc, "status_code", None),
                    )
                )
            else:
                if not isinstance(response, SearchResponse):
                    raise SearchPlannerError("OpenGrok client 返回的不是 SearchResponse")
                executions.append(SearchExecution(query=query, status="ok", response=response))
        return SearchPlanResult(tuple(executions), target=target)
