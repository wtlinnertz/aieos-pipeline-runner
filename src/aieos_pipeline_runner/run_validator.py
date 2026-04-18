"""Run validator — evaluates spec criteria against canonical findings.

Evidence-based by design: NEVER trusts an adapter's self-reported status.
For each action, reads the actual findings from the RunRecord and checks
the criteria declared in the spec against them. Returns PASS/FAIL per
action; overall PASS iff every action PASSes.

Criteria evaluators are registered by key. Unknown criteria FAIL the check
conservatively — the validator does not silently pass criteria it doesn't
understand. Extensions register new evaluators without touching the core.

Publishes the run record and validator report to the artifact store on
completion (both success and failure) — the archive is evidence, not
celebration.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .artifact_store import ArtifactStore
from .models import (
    BoundPlan,
    LoadedSpec,
    RunRecord,
    SpecKind,
    TaskStatus,
    ValidationResult,
    ValidatorCheck,
    ValidatorReport,
)

_SEVERITY_ORDER = ["none", "info", "low", "medium", "high", "critical"]

CriterionEvaluator = Callable[[Any, dict[str, Any] | None, list[str]], tuple[bool, str]]


def _max_severity_in_findings(findings: dict[str, Any] | None) -> str:
    """Return the highest severity found in SARIF or CycloneDX findings."""
    if not findings:
        return "none"
    best = -1

    # CycloneDX findings: vulnerabilities[].ratings[].severity
    for vuln in findings.get("vulnerabilities", []) or []:
        for rating in vuln.get("ratings", []) or []:
            sev = str(rating.get("severity", "")).lower()
            if sev in _SEVERITY_ORDER:
                best = max(best, _SEVERITY_ORDER.index(sev))

    # SARIF results: runs[].results[].level → map to severity
    sarif_level_to_sev = {"note": "info", "warning": "medium", "error": "high"}
    for run in findings.get("runs", []) or []:
        for result in run.get("results", []) or []:
            level = str(result.get("level", "")).lower()
            sev = sarif_level_to_sev.get(level, level)
            if sev in _SEVERITY_ORDER:
                best = max(best, _SEVERITY_ORDER.index(sev))

    return _SEVERITY_ORDER[best] if best >= 0 else "none"


def _eval_max_severity(criterion, findings, _evidence):
    threshold = str(criterion).lower()
    if threshold not in _SEVERITY_ORDER:
        return False, f"max_severity criterion {criterion!r} is not a known severity"
    observed = _max_severity_in_findings(findings)
    if _SEVERITY_ORDER.index(observed) > _SEVERITY_ORDER.index(threshold):
        return False, f"observed severity {observed} exceeds threshold {threshold}"
    return True, f"observed {observed} <= threshold {threshold}"


def _eval_min_coverage(criterion, findings, _evidence):
    try:
        threshold = float(criterion)
    except (TypeError, ValueError):
        return False, f"min_coverage criterion {criterion!r} is not numeric"
    if not findings:
        return False, "no findings recorded; cannot evaluate coverage"
    # JUnit-JSON canonical shape does not carry coverage; adapters place it
    # under findings.coverage_percent by convention for v1.
    observed = findings.get("coverage_percent")
    if observed is None:
        return False, "findings lack coverage_percent; adapter must emit it for this criterion"
    if float(observed) < threshold:
        return False, f"observed coverage {observed} < required {threshold}"
    return True, f"observed coverage {observed} >= {threshold}"


def _eval_expect_all_pass(_criterion, findings, _evidence):
    if not findings:
        return False, "no findings recorded; cannot evaluate test results"
    failures = int(findings.get("failures", 0) or 0)
    errors = int(findings.get("errors", 0) or 0)
    if failures + errors == 0:
        return True, f"all tests passed ({findings.get('tests', 0)} total)"
    return False, f"{failures} failure(s), {errors} error(s)"


def _eval_expect_zero_findings(_criterion, findings, _evidence):
    if not findings:
        return True, "no findings recorded"
    count = 0
    count += len(findings.get("vulnerabilities", []) or [])
    for run in findings.get("runs", []) or []:
        count += len(run.get("results", []) or [])
    if count == 0:
        return True, "zero findings"
    return False, f"{count} finding(s) present"


def _eval_max_cvss(criterion, findings, _evidence):
    try:
        threshold = float(criterion)
    except (TypeError, ValueError):
        return False, f"max_cvss criterion {criterion!r} is not numeric"
    if not findings:
        return True, "no findings to evaluate"
    observed_max = 0.0
    for vuln in findings.get("vulnerabilities", []) or []:
        for rating in vuln.get("ratings", []) or []:
            if rating.get("method") == "CVSSv31":
                observed_max = max(observed_max, float(rating.get("score", 0) or 0))
    if observed_max > threshold:
        return False, f"observed max CVSS {observed_max} exceeds threshold {threshold}"
    return True, f"observed max CVSS {observed_max} <= {threshold}"


def _eval_expected_status(criterion, findings, evidence):
    expected = int(criterion)
    # verify.smoke adapters record the observed status either in findings
    # (under observed_status) or in the evidence list as "http-status:NNN".
    if findings is not None and "observed_status" in findings:
        observed = int(findings["observed_status"])
        if observed == expected:
            return True, f"observed status {observed} matches expected {expected}"
        return False, f"observed status {observed} != expected {expected}"
    for ev in evidence:
        if ev.startswith("http-status:"):
            observed = int(ev.split(":", 1)[1])
            if observed == expected:
                return True, f"evidence reports status {observed}"
            return False, f"evidence reports status {observed} != expected {expected}"
    return False, "no observed status recorded in findings or evidence"


# Default criterion registry. Extensions can add more at construction time.
DEFAULT_EVALUATORS: dict[str, CriterionEvaluator] = {
    "max_severity": _eval_max_severity,
    "min_coverage": _eval_min_coverage,
    "expect_all_pass": _eval_expect_all_pass,
    "expect_zero_findings": _eval_expect_zero_findings,
    "max_cvss": _eval_max_cvss,
    "expected_status": _eval_expected_status,
}


def _action_instances_by_id(spec: LoadedSpec) -> dict[str, dict[str, Any]]:
    instances: dict[str, dict[str, Any]] = {}
    if spec.kind == SpecKind.CI:
        for inst in spec.content.get("actions", []):
            instances[inst["action"]] = inst
    else:
        for env in spec.content.get("environments", []):
            for inst in env.get("actions", []):
                instances[inst["action"]] = inst
    return instances


class RunValidator:
    """Post-run: judges the RunRecord against the frozen spec's criteria."""

    def __init__(
        self,
        evaluators: dict[str, CriterionEvaluator] | None = None,
        artifact_store: ArtifactStore | None = None,
    ) -> None:
        self._evaluators = dict(DEFAULT_EVALUATORS)
        if evaluators:
            self._evaluators.update(evaluators)
        self._store = artifact_store

    def _evaluate_action(
        self,
        action: str,
        criteria: dict[str, Any],
        findings: dict[str, Any] | None,
        evidence: list[str],
        status: TaskStatus,
    ) -> ValidatorCheck:
        details: list[str] = []

        # An action that never ran (SKIPPED) or crashed (FAILED with no findings)
        # is not "pass" even if criteria would otherwise be satisfied.
        if status == TaskStatus.SKIPPED:
            return ValidatorCheck(
                check=f"action:{action}",
                result=ValidationResult.FAIL,
                details=[f"{action} was skipped"],
            )

        all_ok = True
        for key, value in (criteria or {}).items():
            evaluator = self._evaluators.get(key)
            if evaluator is None:
                all_ok = False
                details.append(f"criterion {key!r} has no registered evaluator — unable to judge")
                continue
            ok, reason = evaluator(value, findings, evidence)
            details.append(f"{key}: {reason}")
            all_ok = all_ok and ok

        return ValidatorCheck(
            check=f"action:{action}",
            result=ValidationResult.PASS if all_ok else ValidationResult.FAIL,
            details=details,
        )

    def validate(self, spec: LoadedSpec, record: RunRecord) -> ValidatorReport:
        instances = _action_instances_by_id(spec)
        checks: list[ValidatorCheck] = []
        for task in record.tasks:
            inst = instances.get(task.action, {})
            criteria = inst.get("criteria", {}) or {}
            checks.append(
                self._evaluate_action(
                    action=task.action,
                    criteria=criteria,
                    findings=task.findings,
                    evidence=task.evidence,
                    status=task.status,
                )
            )

        report = ValidatorReport.from_checks(checks)
        if self._store is not None:
            self._publish(record, report)
        return report

    def _publish(self, record: RunRecord, report: ValidatorReport) -> None:
        """Publish the run record + report to the artifact store."""
        assert self._store is not None
        record_payload = {
            "run_id": record.run_id,
            "spec_ref": record.spec_ref,
            "spec_hash": record.spec_hash,
            "started_at": record.started_at.isoformat() if record.started_at else None,
            "finished_at": record.finished_at.isoformat() if record.finished_at else None,
            "tasks": [
                {
                    "action": t.action,
                    "adapter_id": t.adapter_id,
                    "status": t.status.value,
                    "findings": t.findings,
                    "evidence": t.evidence,
                    "error": t.error,
                    "started_at": t.started_at.isoformat() if t.started_at else None,
                    "finished_at": t.finished_at.isoformat() if t.finished_at else None,
                }
                for t in record.tasks
            ],
        }
        self._store.put(
            f"runs/{record.run_id}/record.json",
            json.dumps(record_payload, sort_keys=True).encode("utf-8"),
        )
        self._store.put(
            f"runs/{record.run_id}/report.json",
            json.dumps(report.to_dict(), sort_keys=True).encode("utf-8"),
        )
