"""M3.5 — run orchestrator tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from aieos_pipeline_runner.models import BoundPlan, BoundTask, TaskStatus
from aieos_pipeline_runner.orchestrator import RunOrchestrator


@dataclass
class _TR:
    """Test-friendly TaskResult that satisfies TaskResultLike."""

    action: str
    adapter_id: str
    findings: dict[str, Any] | None
    evidence: list[str]
    status: TaskStatus
    error: str | None = None


class _MockAgent:
    """Records invocation order and returns canned results by action."""

    def __init__(self, results: dict[str, _TR] | None = None) -> None:
        self._results = dict(results or {})
        self.calls: list[str] = []

    def receive_task(self, action, criteria, inputs, task_id=None):  # noqa: D401
        self.calls.append(action)
        if action in self._results:
            return self._results[action]
        return _TR(
            action=action,
            adapter_id="adapter-x",
            findings={"ok": True},
            evidence=[f"evidence-{action}"],
            status=TaskStatus.COMPLETED,
        )


def _bt(action: str, depends_on: tuple[str, ...] = ()) -> BoundTask:
    return BoundTask(
        action=action,
        adapter_id="adapter-x",
        adapter_version="1.0.0",
        criteria={},
        inputs={},
        depends_on=depends_on,
    )


def _plan(tasks: tuple[BoundTask, ...]) -> BoundPlan:
    return BoundPlan(spec_ref="inline://test", spec_hash="0" * 64, tasks=tasks)


FIXED_NOW = datetime(2026, 4, 18, 10, 0, 0, tzinfo=UTC)


def test_tasks_execute_in_dependency_order():
    agent = _MockAgent()
    plan = _plan(
        (
            _bt("sign.artifact", depends_on=("build.artifact",)),
            _bt("build.artifact", depends_on=("test.unit",)),
            _bt("test.unit"),
        )
    )
    orchestrator = RunOrchestrator(
        agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "run-1"
    )

    orchestrator.execute(plan)

    assert agent.calls == ["test.unit", "build.artifact", "sign.artifact"]


def test_independent_tasks_ordering_is_determinstic_but_not_strict():
    """Tasks without dependencies are tie-broken alphabetically."""
    agent = _MockAgent()
    plan = _plan((_bt("security.sca"), _bt("security.sast"), _bt("test.unit")))
    orchestrator = RunOrchestrator(agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "r")

    orchestrator.execute(plan)

    # alphabetical tie-break
    assert agent.calls == sorted(agent.calls)


def test_run_record_collects_all_results():
    agent = _MockAgent(
        results={
            "test.unit": _TR(
                action="test.unit",
                adapter_id="adapter-pytest-unit",
                findings={"tests": 5},
                evidence=["junit-1"],
                status=TaskStatus.COMPLETED,
            ),
            "build.artifact": _TR(
                action="build.artifact",
                adapter_id="adapter-buildah-image",
                findings=None,
                evidence=["oci-digest-sha256:abc"],
                status=TaskStatus.COMPLETED,
            ),
        }
    )
    plan = _plan(
        (
            _bt("test.unit"),
            _bt("build.artifact", depends_on=("test.unit",)),
        )
    )
    orchestrator = RunOrchestrator(
        agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "run-xyz"
    )

    record = orchestrator.execute(plan)

    assert record.run_id == "run-xyz"
    assert record.spec_ref == "inline://test"
    assert len(record.tasks) == 2
    assert record.tasks[0].findings == {"tests": 5}
    assert record.tasks[0].evidence == ["junit-1"]
    assert record.tasks[1].evidence == ["oci-digest-sha256:abc"]
    assert all(t.started_at == FIXED_NOW for t in record.tasks)


def test_failed_task_stops_direct_dependents():
    agent = _MockAgent(
        results={
            "test.unit": _TR(
                action="test.unit",
                adapter_id="adapter-pytest-unit",
                findings=None,
                evidence=[],
                status=TaskStatus.FAILED,
                error="3 tests failed",
            )
        }
    )
    plan = _plan(
        (
            _bt("test.unit"),
            _bt("build.artifact", depends_on=("test.unit",)),
            _bt("sign.artifact", depends_on=("build.artifact",)),
        )
    )
    orchestrator = RunOrchestrator(agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "r")

    record = orchestrator.execute(plan)

    # test.unit runs and fails
    unit = next(t for t in record.tasks if t.action == "test.unit")
    assert unit.status == TaskStatus.FAILED
    # build.artifact skipped (direct dep)
    build = next(t for t in record.tasks if t.action == "build.artifact")
    assert build.status == TaskStatus.SKIPPED
    assert "test.unit" in build.error
    # sign.artifact skipped (transitive)
    sign = next(t for t in record.tasks if t.action == "sign.artifact")
    assert sign.status == TaskStatus.SKIPPED
    # Agent was only called for test.unit (downstream skipped without invocation)
    assert agent.calls == ["test.unit"]


def test_orchestrator_does_not_evaluate_success():
    """RunRecord includes a failed task; orchestrator DOES NOT emit a PASS/FAIL
    verdict — that's M3.6's job. RunRecord carries facts only."""
    agent = _MockAgent(
        results={
            "test.unit": _TR(
                action="test.unit",
                adapter_id="a",
                findings={"tests": 1, "failures": 1},
                evidence=["junit-1"],
                status=TaskStatus.FAILED,
                error="1 failure",
            )
        }
    )
    plan = _plan((_bt("test.unit"),))
    orchestrator = RunOrchestrator(agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "r")

    record = orchestrator.execute(plan)

    # Record reflects the failed task
    assert record.tasks[0].status == TaskStatus.FAILED
    # But RunRecord itself has no overall status field — this is deliberate.
    assert not hasattr(record, "overall_status")
    assert not hasattr(record, "result")


def test_agent_exception_becomes_failed_task_record():
    class _RaisingAgent:
        def receive_task(self, action, criteria, inputs, task_id=None):
            raise RuntimeError("agent crashed")

    plan = _plan((_bt("test.unit"),))
    orchestrator = RunOrchestrator(
        agent=_RaisingAgent(), clock=lambda: FIXED_NOW, run_id_factory=lambda: "r"
    )

    record = orchestrator.execute(plan)

    assert record.tasks[0].status == TaskStatus.FAILED
    assert "RuntimeError" in record.tasks[0].error
    assert "agent crashed" in record.tasks[0].error


def test_cycle_in_plan_raises_since_plan_validator_should_have_caught_it():
    agent = _MockAgent()
    plan = _plan(
        (
            _bt("a.x", depends_on=("b.y",)),
            _bt("b.y", depends_on=("a.x",)),
        )
    )
    orchestrator = RunOrchestrator(agent=agent, clock=lambda: FIXED_NOW, run_id_factory=lambda: "r")

    with pytest.raises(ValueError, match="cycle"):
        orchestrator.execute(plan)
