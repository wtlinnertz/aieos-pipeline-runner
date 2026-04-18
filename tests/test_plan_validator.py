"""M3.4 — plan validator tests."""

from __future__ import annotations

from aieos_pipeline_runner.models import (
    BoundPlan,
    BoundTask,
    LoadedSpec,
    SpecKind,
    UnresolvedAction,
    ValidationResult,
)
from aieos_pipeline_runner.plan_validator import validate_plan


def _ci_spec(actions: list[dict]) -> LoadedSpec:
    return LoadedSpec(
        kind=SpecKind.CI,
        content={
            "spec_version": "1.0.0",
            "code_repo": "wtlinnertz/x",
            "actions": actions,
            "policies": {"timeout_seconds": 1800, "retry": {"max_retries": 0}},
        },
        source_ref="inline://test",
        content_hash="0" * 64,
    )


def _bound_task(
    action: str,
    adapter_id: str = "adapter-x",
    adapter_version: str = "1.0.0",
    depends_on: tuple[str, ...] = (),
) -> BoundTask:
    return BoundTask(
        action=action,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        criteria={},
        inputs={},
        depends_on=depends_on,
    )


def test_complete_plan_passes():
    spec = _ci_spec(
        [
            {"action": "test.unit", "criteria": {}},
            {"action": "build.artifact", "criteria": {}, "depends_on": ["test.unit"]},
        ]
    )
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(
            _bound_task("test.unit", adapter_id="adapter-pytest-unit"),
            _bound_task(
                "build.artifact",
                adapter_id="adapter-buildah-image",
                depends_on=("test.unit",),
            ),
        ),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.PASS
    assert [c.check for c in report.checks] == [
        "all_actions_accounted_for",
        "no_unresolved_actions",
        "bound_adapters_attested",
        "dag_valid",
        "no_extra_tasks",
    ]


def test_missing_action_fails():
    """Spec declares two actions; plan omits one entirely (not even as unresolved)."""
    spec = _ci_spec(
        [
            {"action": "test.unit", "criteria": {}},
            {"action": "build.artifact", "criteria": {}},
        ]
    )
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(_bound_task("test.unit"),),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    missing_check = next(c for c in report.checks if c.check == "all_actions_accounted_for")
    assert missing_check.result == ValidationResult.FAIL
    assert any("build.artifact" in d for d in missing_check.details)


def test_ambiguous_resolution_fails():
    spec = _ci_spec([{"action": "test.unit", "criteria": {}}])
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(),
        unresolved=(
            UnresolvedAction(
                action="test.unit",
                reason="ambiguous",
                candidates=("adapter-a@1.0.0", "adapter-b@1.0.0"),
            ),
        ),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    unresolved_check = next(c for c in report.checks if c.check == "no_unresolved_actions")
    assert unresolved_check.result == ValidationResult.FAIL
    assert any("ambiguous" in d for d in unresolved_check.details)


def test_no_adapter_resolution_fails():
    spec = _ci_spec([{"action": "security.dast", "criteria": {}}])
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(),
        unresolved=(UnresolvedAction(action="security.dast", reason="no_adapter"),),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    u = next(c for c in report.checks if c.check == "no_unresolved_actions")
    assert any("no_adapter" in d for d in u.details)


def test_invalid_attestation_fails():
    """Missing adapter_id simulates a registry-chain break — plan validator
    refuses the plan."""
    spec = _ci_spec([{"action": "test.unit", "criteria": {}}])
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(_bound_task("test.unit", adapter_id="", adapter_version=""),),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    ac = next(c for c in report.checks if c.check == "bound_adapters_attested")
    assert ac.result == ValidationResult.FAIL


def test_dag_mismatch_fails():
    """A task depends_on references an action not in the bound plan."""
    spec = _ci_spec([{"action": "build.artifact", "criteria": {}, "depends_on": ["test.unit"]}])
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(_bound_task("build.artifact", depends_on=("test.unit",)),),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    dag_check = next(c for c in report.checks if c.check == "dag_valid")
    assert dag_check.result == ValidationResult.FAIL
    assert any("test.unit" in d for d in dag_check.details)


def test_cycle_in_bound_plan_fails():
    spec = _ci_spec(
        [
            {"action": "a.x", "criteria": {}, "depends_on": ["b.y"]},
            {"action": "b.y", "criteria": {}, "depends_on": ["a.x"]},
        ]
    )
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(
            _bound_task("a.x", depends_on=("b.y",)),
            _bound_task("b.y", depends_on=("a.x",)),
        ),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    dag_check = next(c for c in report.checks if c.check == "dag_valid")
    assert any("cycle" in d for d in dag_check.details)


def test_extra_tasks_detected():
    spec = _ci_spec([{"action": "test.unit", "criteria": {}}])
    plan = BoundPlan(
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=(_bound_task("test.unit"), _bound_task("build.artifact")),
    )

    report = validate_plan(spec, plan)

    assert report.result == ValidationResult.FAIL
    extra_check = next(c for c in report.checks if c.check == "no_extra_tasks")
    assert extra_check.result == ValidationResult.FAIL
    assert any("build.artifact" in d for d in extra_check.details)
