"""Run orchestrator — executes a validated BoundPlan via an Agent.

Executes tasks in topological order (respecting depends_on). Independent
tasks MAY run in parallel in a future revision; v1 is serial for
determinism. When a task fails, every task that transitively depends on it
is marked SKIPPED with an upstream-failure diagnostic.

The orchestrator does NOT judge pass/fail. It collects results into a
RunRecord; the run validator (M3.6) renders the verdict.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

import structlog

from .models import (
    BoundPlan,
    BoundTask,
    RunRecord,
    RunTaskRecord,
    TaskStatus,
)

log = structlog.get_logger(__name__)


class TaskResultLike(Protocol):
    """Shape the orchestrator needs from an agent's TaskResult."""

    @property
    def action(self) -> str: ...
    @property
    def adapter_id(self) -> str: ...
    @property
    def findings(self) -> dict[str, Any] | None: ...
    @property
    def evidence(self) -> list[str]: ...
    @property
    def status(self) -> Any: ...  # str or TaskStatus
    @property
    def error(self) -> str | None: ...


class AgentAPI(Protocol):
    def receive_task(
        self,
        action: str,
        criteria: dict[str, Any],
        inputs: dict[str, Any],
        task_id: str | None = None,
    ) -> TaskResultLike: ...


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _default_run_id_factory() -> str:
    return f"run-{uuid.uuid4().hex[:12]}"


def _topo_order(tasks: tuple[BoundTask, ...]) -> list[BoundTask]:
    """Kahn's algorithm. Deterministic tie-break by action id so runs are
    reproducible."""
    by_action = {t.action: t for t in tasks}
    in_degree = {t.action: 0 for t in tasks}
    adj: dict[str, list[str]] = {t.action: [] for t in tasks}
    for t in tasks:
        for dep in t.depends_on:
            if dep in in_degree:
                adj[dep].append(t.action)
                in_degree[t.action] += 1
    # tie-break alphabetically
    ready = sorted([a for a, d in in_degree.items() if d == 0])
    order: list[BoundTask] = []
    while ready:
        a = ready.pop(0)
        order.append(by_action[a])
        for next_action in sorted(adj[a]):
            in_degree[next_action] -= 1
            if in_degree[next_action] == 0:
                ready.append(next_action)
        ready.sort()
    if len(order) != len(tasks):
        raise ValueError("bound plan has a cycle — plan validator should have caught this")
    return order


def _status_to_enum(status: Any) -> TaskStatus:
    """Accept either a TaskStatus or a string."""
    if isinstance(status, TaskStatus):
        return status
    try:
        return TaskStatus(str(status))
    except ValueError:
        return TaskStatus.FAILED  # conservative default


class RunOrchestrator:
    """Drives a BoundPlan through an Agent, collecting RunTaskRecords.

    The agent may be any object satisfying AgentAPI. For M3.7 + CLI usage,
    a mock agent injects canned results; in production the real harness
    agent handles adapter execution.
    """

    def __init__(
        self,
        agent: AgentAPI,
        clock: Callable[[], datetime] = _default_clock,
        run_id_factory: Callable[[], str] = _default_run_id_factory,
    ) -> None:
        self._agent = agent
        self._clock = clock
        self._run_id_factory = run_id_factory

    def execute(self, plan: BoundPlan, run_id: str | None = None) -> RunRecord:
        rid = run_id or self._run_id_factory()
        started_at = self._clock()
        order = _topo_order(plan.tasks)

        # Track which actions have failed so dependents can be short-circuited.
        failed_actions: set[str] = set()
        record = RunRecord(
            run_id=rid,
            spec_ref=plan.spec_ref,
            spec_hash=plan.spec_hash,
            started_at=started_at,
        )

        for task in order:
            task_started = self._clock()

            # Short-circuit on upstream failure (direct or transitive).
            if any(dep in failed_actions for dep in task.depends_on):
                failed_dep = next(dep for dep in task.depends_on if dep in failed_actions)
                log.info("task_skipped_upstream_failure", action=task.action, dep=failed_dep)
                record.tasks.append(
                    RunTaskRecord(
                        action=task.action,
                        adapter_id=task.adapter_id,
                        status=TaskStatus.SKIPPED,
                        findings=None,
                        evidence=[],
                        error=f"upstream action {failed_dep} did not complete",
                        started_at=task_started,
                        finished_at=self._clock(),
                    )
                )
                failed_actions.add(task.action)  # propagate skip as failure downstream
                continue

            try:
                result = self._agent.receive_task(
                    action=task.action,
                    criteria=task.criteria,
                    inputs=task.inputs,
                )
            except Exception as exc:  # noqa: BLE001 - become a task record
                log.warning(
                    "agent_raised",
                    action=task.action,
                    exc_type=type(exc).__name__,
                    exc=str(exc),
                )
                record.tasks.append(
                    RunTaskRecord(
                        action=task.action,
                        adapter_id=task.adapter_id,
                        status=TaskStatus.FAILED,
                        findings=None,
                        evidence=[],
                        error=f"agent raised {type(exc).__name__}: {exc}",
                        started_at=task_started,
                        finished_at=self._clock(),
                    )
                )
                failed_actions.add(task.action)
                continue

            status = _status_to_enum(result.status)
            record.tasks.append(
                RunTaskRecord(
                    action=task.action,
                    adapter_id=result.adapter_id or task.adapter_id,
                    status=status,
                    findings=result.findings,
                    evidence=list(result.evidence),
                    error=result.error,
                    started_at=task_started,
                    finished_at=self._clock(),
                )
            )
            if status != TaskStatus.COMPLETED:
                failed_actions.add(task.action)

        record.finished_at = self._clock()
        return record
