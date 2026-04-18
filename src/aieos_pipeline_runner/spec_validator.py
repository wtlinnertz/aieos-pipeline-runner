"""Spec validator — judges a loaded spec PASS/FAIL against four checks.

Checks:
  schema_valid          — loader already validated; re-validation is defensive
                          and keeps the report self-contained.
  actions_in_taxonomy   — every action identifier exists in the frozen v1.0
                          taxonomy (vendored as taxonomy-actions.json).
  criteria_shape        — every criterion is an object. (v1 contracts do not
                          declare per-action criteria schemas; tighter shape
                          checks are deferred to a contract-extension pass.)
  dag_valid             — the implied dependency/promotion graph is a DAG.

Returns a ValidatorReport. No suggestions, no redesign — evidence only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .models import (
    LoadedSpec,
    SpecKind,
    ValidationResult,
    ValidatorCheck,
    ValidatorReport,
)

PACKAGE_ROOT = Path(__file__).parent
TAXONOMY_PATH = PACKAGE_ROOT / "vendored" / "taxonomy-actions.json"
CI_SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "ci-spec.schema.json"
CD_SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "cd-spec.schema.json"


def _taxonomy_actions() -> set[str]:
    doc = json.loads(TAXONOMY_PATH.read_text())
    return set(doc["actions"])


def _all_action_instances(spec: LoadedSpec) -> list[dict[str, Any]]:
    if spec.kind == SpecKind.CI:
        return list(spec.content.get("actions", []))
    instances: list[dict[str, Any]] = []
    for env in spec.content.get("environments", []):
        instances.extend(env.get("actions", []))
    return instances


def _has_cycle(nodes: set[str], edges: list[tuple[str, str]]) -> bool:
    """Kahn's topo sort. Returns True if a cycle is present."""
    in_degree = {n: 0 for n in nodes}
    adj: dict[str, list[str]] = {n: [] for n in nodes}
    for src, dst in edges:
        if src not in in_degree or dst not in in_degree:
            continue
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
    return visited != len(nodes)


def _check_schema(spec: LoadedSpec) -> ValidatorCheck:
    schema_path = CI_SCHEMA_PATH if spec.kind == SpecKind.CI else CD_SCHEMA_PATH
    schema = json.loads(schema_path.read_text())
    errors = sorted(
        Draft202012Validator(schema).iter_errors(spec.content), key=lambda e: list(e.path)
    )
    if errors:
        details = [
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors[:5]
        ]
        return ValidatorCheck(check="schema_valid", result=ValidationResult.FAIL, details=details)
    return ValidatorCheck(check="schema_valid", result=ValidationResult.PASS)


def _check_actions_in_taxonomy(spec: LoadedSpec) -> ValidatorCheck:
    taxonomy = _taxonomy_actions()
    referenced = [inst["action"] for inst in _all_action_instances(spec)]
    missing = sorted({a for a in referenced if a not in taxonomy})
    if missing:
        return ValidatorCheck(
            check="actions_in_taxonomy",
            result=ValidationResult.FAIL,
            details=[f"{a} not in taxonomy" for a in missing],
        )
    return ValidatorCheck(check="actions_in_taxonomy", result=ValidationResult.PASS)


def _check_criteria_shape(spec: LoadedSpec) -> ValidatorCheck:
    """v1 contracts do not declare per-action criteria schemas. This check
    enforces only that each criteria field is an object; tighter shape
    validation is a deferred contract-extension concern."""
    problems: list[str] = []
    for inst in _all_action_instances(spec):
        criteria = inst.get("criteria", {})
        if not isinstance(criteria, dict):
            problems.append(
                f"{inst['action']}: criteria must be an object (got {type(criteria).__name__})"
            )
    if problems:
        return ValidatorCheck(
            check="criteria_shape", result=ValidationResult.FAIL, details=problems
        )
    return ValidatorCheck(check="criteria_shape", result=ValidationResult.PASS)


def _check_dag_ci(spec: LoadedSpec) -> ValidatorCheck:
    actions = spec.content.get("actions", [])
    nodes = {inst["action"] for inst in actions}
    edges: list[tuple[str, str]] = []
    dangling: set[str] = set()
    for inst in actions:
        target = inst["action"]
        for dep in inst.get("depends_on", []):
            if dep not in nodes:
                dangling.add(dep)
                continue
            edges.append((dep, target))
    if dangling:
        return ValidatorCheck(
            check="dag_valid",
            result=ValidationResult.FAIL,
            details=[
                f"depends_on references action not declared in spec: {d}" for d in sorted(dangling)
            ],
        )
    if _has_cycle(nodes, edges):
        return ValidatorCheck(
            check="dag_valid",
            result=ValidationResult.FAIL,
            details=["CI dependency graph has a cycle"],
        )
    return ValidatorCheck(check="dag_valid", result=ValidationResult.PASS)


def _check_dag_cd(spec: LoadedSpec) -> ValidatorCheck:
    """CD has two graphs: per-environment action deps and promotion edges.
    Both must be acyclic."""
    details: list[str] = []
    for env in spec.content.get("environments", []):
        actions = env.get("actions", [])
        nodes = {inst["action"] for inst in actions}
        edges: list[tuple[str, str]] = []
        for inst in actions:
            for dep in inst.get("depends_on", []):
                if dep in nodes:
                    edges.append((dep, inst["action"]))
                else:
                    details.append(
                        f"env {env['name']}: depends_on references action not in env: {dep}"
                    )
        if _has_cycle(nodes, edges):
            details.append(f"env {env['name']}: action dependency graph has a cycle")

    envs = {env["name"] for env in spec.content.get("environments", [])}
    promo_edges = [(p["from"], p["to"]) for p in spec.content.get("promotions", [])]
    dangling = {n for pair in promo_edges for n in pair} - envs
    if dangling:
        details.append(f"promotions reference undeclared environments: {sorted(dangling)}")
    if _has_cycle(envs, promo_edges):
        details.append("promotion graph has a cycle")

    if details:
        return ValidatorCheck(check="dag_valid", result=ValidationResult.FAIL, details=details)
    return ValidatorCheck(check="dag_valid", result=ValidationResult.PASS)


def validate_spec(spec: LoadedSpec) -> ValidatorReport:
    """Run all four checks and return a ValidatorReport (PASS/FAIL envelope)."""
    checks: list[ValidatorCheck] = [
        _check_schema(spec),
        _check_actions_in_taxonomy(spec),
        _check_criteria_shape(spec),
        _check_dag_ci(spec) if spec.kind == SpecKind.CI else _check_dag_cd(spec),
    ]
    return ValidatorReport.from_checks(checks)
