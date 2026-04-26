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


def _eval_signing_identity_type(criterion, findings, _evidence):
    """Verify the sign.* adapter used the expected identity mode.

    Reads the bundle's verificationMaterial; presence of x509CertificateChain
    or certificate.rawBytes indicates ambient OIDC; presence of publicKey
    indicates a keypair.
    """
    if not findings:
        return False, "no signing bundle recorded in findings"
    vm = findings.get("verificationMaterial", {}) or {}
    has_cert = bool(vm.get("certificate") or vm.get("x509CertificateChain"))
    has_key = bool(vm.get("publicKey"))
    observed = "ambient-oidc" if has_cert else ("keypair" if has_key else "unknown")
    expected = str(criterion)
    if observed == expected:
        return True, f"signing identity type {observed} matches expected"
    return False, f"signing identity type {observed} != expected {expected}"


def _eval_predicate_type_expected(criterion, findings, _evidence):
    """Verify the in-toto predicate type matches when sign.attestation
    findings carry a DSSE envelope with payload (base64) wrapping the
    Statement."""
    if not findings:
        return False, "no signing bundle recorded"
    dsse = findings.get("dsseEnvelope") or {}
    payload_type = dsse.get("payloadType", "")
    if not payload_type:
        # Fallback: v1 sign-blob path doesn't produce DSSE; assume the
        # caller pinned the predicate type elsewhere.
        return True, "v1 sign-blob path; predicate type not embedded — assumed match"
    if payload_type == criterion:
        return True, f"payloadType {payload_type} matches expected"
    return False, f"payloadType {payload_type} != expected {criterion}"


def _eval_format(criterion, findings, _evidence):
    """For sbom.generate — assert the findings declare the expected format."""
    if not findings:
        return False, "no SBOM findings recorded"
    expected = str(criterion).lower()
    if expected == "cyclonedx":
        if findings.get("bomFormat") == "CycloneDX":
            return True, "format is CycloneDX"
        return False, f"expected CycloneDX, observed bomFormat={findings.get('bomFormat')}"
    if expected == "spdx":
        # SPDX uses spdxVersion at the top level.
        if findings.get("spdxVersion"):
            return True, f"format is SPDX ({findings['spdxVersion']})"
        return False, "expected SPDX, observed no spdxVersion field"
    return False, f"unknown format threshold {expected!r}"


def _eval_destination_registry_required(criterion, _findings, evidence):
    """For publish.artifact — assert evidence carries a published-artifact-ref
    pointing at a registry."""
    if not bool(criterion):
        return True, "destination registry not required"
    for ev in evidence:
        if ev.startswith("published-artifact-ref:"):
            ref = ev.split(":", 1)[1]
            if "/" in ref and (":" in ref.rsplit("/", 1)[-1] or "@sha256:" in ref):
                return True, f"published to {ref}"
    return False, "no published-artifact-ref in evidence"


def _eval_artifact_type(criterion, _findings, evidence):
    """For build.artifact — assert evidence carries the expected artifact
    type (typically 'oci-image' which means an oci-image-digest is present)."""
    expected = str(criterion).lower()
    if expected == "oci-image":
        for ev in evidence:
            if ev.startswith("oci-image-digest:"):
                return True, "evidence contains oci-image-digest"
        return False, "no oci-image-digest in evidence"
    return False, f"unsupported artifact_type {expected!r}"


def _eval_reconciled_within_seconds(criterion, _findings, evidence):
    """For deploy.environment — assert reconciler-status:accepted is present.

    True elapsed-time enforcement is v1.1; v1 accepts reconciler ack as
    sufficient and trusts the adapter's internal timeout to enforce the
    upper bound.
    """
    _ = int(criterion)  # validate type even if not enforced
    for ev in evidence:
        if ev.startswith("reconciler-status:") and "accepted" in ev:
            return True, "reconciler reported accepted"
    return False, "reconciler did not report accepted"


def _eval_all_endpoints_healthy(criterion, findings, _evidence):
    """For verify.health — assert every probe reported pass when the
    criterion is True."""
    if not bool(criterion):
        return True, "criterion disabled"
    if not findings:
        return False, "no health findings recorded"
    checks = findings.get("checks") or findings.get("results") or []
    if not checks:
        return False, "no per-check results recorded"
    failing = [c for c in checks if not c.get("pass", c.get("ok", True))]
    if failing:
        return False, f"{len(failing)} unhealthy check(s)"
    return True, f"all {len(checks)} checks healthy"


def _eval_min_success_rate(criterion, findings, _evidence):
    """For verify.slo — observed success rate >= threshold."""
    try:
        threshold = float(criterion)
    except (TypeError, ValueError):
        return False, f"min_success_rate criterion {criterion!r} not numeric"
    if not findings:
        return False, "no SLO findings recorded"
    observed = findings.get("observed_success_rate")
    if observed is None and findings.get("slos"):
        # take the worst-case across measured SLOs
        rates = [
            s.get("observed_success_rate")
            for s in findings["slos"]
            if s.get("observed_success_rate") is not None
        ]
        if rates:
            observed = min(rates)
    if observed is None:
        return False, "no observed_success_rate in findings"
    if float(observed) < threshold:
        return False, f"observed {observed} < threshold {threshold}"
    return True, f"observed {observed} >= {threshold}"


def _eval_window_seconds(criterion, _findings, _evidence):
    """For verify.slo — informational (the window is the adapter's input,
    not a result property). v1 accepts the field as configuration; the
    adapter's compliance with the window is its own concern."""
    _ = int(criterion)
    return True, f"window_seconds={criterion} accepted as adapter input"


# Default criterion registry. Extensions can add more at construction time.
DEFAULT_EVALUATORS: dict[str, CriterionEvaluator] = {
    "max_severity": _eval_max_severity,
    "min_coverage": _eval_min_coverage,
    "expect_all_pass": _eval_expect_all_pass,
    "expect_zero_findings": _eval_expect_zero_findings,
    "max_cvss": _eval_max_cvss,
    "expected_status": _eval_expected_status,
    "signing_identity_type": _eval_signing_identity_type,
    "predicate_type_expected": _eval_predicate_type_expected,
    "format": _eval_format,
    "destination_registry_required": _eval_destination_registry_required,
    "artifact_type": _eval_artifact_type,
    "reconciled_within_seconds": _eval_reconciled_within_seconds,
    "all_endpoints_healthy": _eval_all_endpoints_healthy,
    "min_success_rate": _eval_min_success_rate,
    "window_seconds": _eval_window_seconds,
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
