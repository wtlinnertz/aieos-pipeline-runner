"""Plan validator — judges a BoundPlan PASS/FAIL against five checks.

The plan validator is the second of three validators; it runs after the
resolver and refuses to hand a broken plan to the orchestrator.

Attestation validity is enforced at the registry (M2.2) — by the time an
entry appears in a BoundPlan, the harness has already verified its
attestation at registration. The plan validator asserts that link in the
chain is intact by requiring every task to carry an adapter_id; it does
not re-run crypto verification.
"""

from __future__ import annotations

from typing import Any

from .models import (
    BoundPlan,
    LoadedSpec,
    SpecKind,
    ValidationResult,
    ValidatorCheck,
    ValidatorReport,
)


def _all_action_instances(spec: LoadedSpec) -> list[dict[str, Any]]:
    if spec.kind == SpecKind.CI:
        return list(spec.content.get("actions", []))
    instances: list[dict[str, Any]] = []
    for env in spec.content.get("environments", []):
        instances.extend(env.get("actions", []))
    return instances


def _check_all_actions_resolved(spec: LoadedSpec, plan: BoundPlan) -> ValidatorCheck:
    """Every action in the spec appears either as a BoundTask or as an
    UnresolvedAction. No action silently disappears."""
    spec_actions = [inst["action"] for inst in _all_action_instances(spec)]
    plan_actions = [t.action for t in plan.tasks] + [u.action for u in plan.unresolved]
    missing = sorted(set(spec_actions) - set(plan_actions))
    if missing:
        return ValidatorCheck(
            check="all_actions_accounted_for",
            result=ValidationResult.FAIL,
            details=[f"spec action missing from plan: {a}" for a in missing],
        )
    return ValidatorCheck(check="all_actions_accounted_for", result=ValidationResult.PASS)


def _check_no_unresolved(plan: BoundPlan) -> ValidatorCheck:
    """The unresolved list must be empty — the resolver records ambiguity
    or no-adapter explicitly, and the plan validator refuses to promote
    either state into a run."""
    if not plan.unresolved:
        return ValidatorCheck(check="no_unresolved_actions", result=ValidationResult.PASS)
    details = []
    for u in plan.unresolved:
        extra = f" (candidates: {list(u.candidates)})" if u.candidates else ""
        details.append(f"{u.action}: {u.reason}{extra}")
    return ValidatorCheck(
        check="no_unresolved_actions",
        result=ValidationResult.FAIL,
        details=details,
    )


def _check_bound_adapters_attested(plan: BoundPlan) -> ValidatorCheck:
    """Every BoundTask carries an adapter_id — resolver only binds to
    registered entries, and the registry refuses unattested entries (M2.2).
    Empty adapter_id here is a harness-plumbing bug."""
    unattested: list[str] = []
    for t in plan.tasks:
        if not t.adapter_id or not t.adapter_version:
            unattested.append(
                f"{t.action}: missing adapter_id/adapter_version — "
                "resolver or registry chain is broken"
            )
    if unattested:
        return ValidatorCheck(
            check="bound_adapters_attested",
            result=ValidationResult.FAIL,
            details=unattested,
        )
    return ValidatorCheck(check="bound_adapters_attested", result=ValidationResult.PASS)


def _check_dag_valid(plan: BoundPlan) -> ValidatorCheck:
    """Task dependency graph must be acyclic and reference only bound actions.
    This duplicates part of the spec validator's check but runs against the
    final plan so a resolver bug that drops actions surfaces here."""
    nodes = {t.action for t in plan.tasks}
    edges: list[tuple[str, str]] = []
    dangling: set[str] = set()
    for t in plan.tasks:
        for dep in t.depends_on:
            if dep not in nodes:
                dangling.add(dep)
                continue
            edges.append((dep, t.action))
    if dangling:
        return ValidatorCheck(
            check="dag_valid",
            result=ValidationResult.FAIL,
            details=[f"task depends on action not in bound plan: {d}" for d in sorted(dangling)],
        )
    # Kahn's topo sort
    in_degree = {n: 0 for n in nodes}
    adj: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        adj[src].append(dst)
        in_degree[dst] += 1
    queue = [n for n, d in in_degree.items() if d == 0]
    visited = 0
    while queue:
        n = queue.pop()
        visited += 1
        for m in adj[n]:
            in_degree[m] -= 1
            if in_degree[m] == 0:
                queue.append(m)
    if visited != len(nodes):
        return ValidatorCheck(
            check="dag_valid",
            result=ValidationResult.FAIL,
            details=["bound plan dependency graph has a cycle"],
        )
    return ValidatorCheck(check="dag_valid", result=ValidationResult.PASS)


def _check_no_extra_tasks(spec: LoadedSpec, plan: BoundPlan) -> ValidatorCheck:
    """The plan contains exactly what the spec requires — no synthetic or
    injected tasks. Defensive; a resolver bug that adds tasks surfaces here."""
    spec_actions = {inst["action"] for inst in _all_action_instances(spec)}
    plan_actions = {t.action for t in plan.tasks}
    extras = sorted(plan_actions - spec_actions)
    if extras:
        return ValidatorCheck(
            check="no_extra_tasks",
            result=ValidationResult.FAIL,
            details=[f"plan contains action not in spec: {a}" for a in extras],
        )
    return ValidatorCheck(check="no_extra_tasks", result=ValidationResult.PASS)


def validate_plan(spec: LoadedSpec, plan: BoundPlan) -> ValidatorReport:
    """Run all five checks and return a ValidatorReport."""
    checks = [
        _check_all_actions_resolved(spec, plan),
        _check_no_unresolved(plan),
        _check_bound_adapters_attested(plan),
        _check_dag_valid(plan),
        _check_no_extra_tasks(spec, plan),
    ]
    return ValidatorReport.from_checks(checks)
