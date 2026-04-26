"""M3.6 — run validator tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from aieos_pipeline_runner.artifact_store import FilesystemArtifactStore
from aieos_pipeline_runner.models import (
    LoadedSpec,
    RunRecord,
    RunTaskRecord,
    SpecKind,
    TaskStatus,
    ValidationResult,
)
from aieos_pipeline_runner.run_validator import RunValidator


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


def _record(tasks: list[RunTaskRecord], run_id: str = "run-1") -> RunRecord:
    return RunRecord(
        run_id=run_id,
        spec_ref="inline://test",
        spec_hash="0" * 64,
        tasks=list(tasks),
        started_at=datetime(2026, 4, 18, 10, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 4, 18, 10, 0, 5, tzinfo=UTC),
    )


def test_all_actions_pass_returns_overall_pass():
    spec = _ci_spec(
        [
            {"action": "test.unit", "criteria": {"expect_all_pass": True}},
            {"action": "security.sast", "criteria": {"max_severity": "high"}},
        ]
    )
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"tests": 5, "failures": 0, "errors": 0},
                evidence=["junit-1"],
            ),
            RunTaskRecord(
                action="security.sast",
                adapter_id="b",
                status=TaskStatus.COMPLETED,
                findings={
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {}}, "results": []}],
                },
                evidence=["sarif-1"],
            ),
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.PASS
    assert all(c.result == ValidationResult.PASS for c in report.checks)


def test_one_action_fails_returns_overall_fail():
    spec = _ci_spec(
        [
            {"action": "test.unit", "criteria": {"expect_all_pass": True}},
        ]
    )
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"tests": 5, "failures": 1, "errors": 0},
                evidence=["junit-1"],
            ),
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL
    action_check = next(c for c in report.checks if c.check == "action:test.unit")
    assert action_check.result == ValidationResult.FAIL


def test_validator_reads_findings_not_adapter_status():
    """Adapter reports COMPLETED but findings show a critical vulnerability —
    the validator looks at findings and FAILs."""
    spec = _ci_spec([{"action": "security.sca", "criteria": {"max_severity": "high"}}])
    record = _record(
        [
            RunTaskRecord(
                action="security.sca",
                adapter_id="lying-adapter",
                status=TaskStatus.COMPLETED,  # adapter self-reports success
                findings={
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "vulnerabilities": [
                        {
                            "id": "CVE-X",
                            "source": {"name": "nvd"},
                            "ratings": [
                                {"method": "CVSSv31", "score": 9.8, "severity": "critical"}
                            ],
                            "affects": [{"ref": "pkg:npm/x@1"}],
                        }
                    ],
                },
                evidence=["cdx-1"],
            )
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL
    check = report.checks[0]
    assert "critical exceeds threshold high" in " ".join(check.details)


def test_skipped_task_is_not_pass_even_with_no_criteria():
    spec = _ci_spec([{"action": "build.artifact", "criteria": {}}])
    record = _record(
        [
            RunTaskRecord(
                action="build.artifact",
                adapter_id="",
                status=TaskStatus.SKIPPED,
                findings=None,
                evidence=[],
                error="upstream test.unit failed",
            )
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL


def test_unknown_criterion_fails_conservatively():
    """An unregistered criterion key does NOT silently pass — the validator
    'judges, it does not help'."""
    spec = _ci_spec([{"action": "test.unit", "criteria": {"invented_criterion": "whatever"}}])
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"tests": 1, "failures": 0, "errors": 0},
                evidence=[],
            )
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL
    assert "no registered evaluator" in " ".join(report.checks[0].details)


def test_run_record_and_report_published_to_artifact_store(tmp_path: Path):
    store = FilesystemArtifactStore(tmp_path / "store")
    spec = _ci_spec([{"action": "test.unit", "criteria": {"expect_all_pass": True}}])
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"tests": 1, "failures": 0, "errors": 0},
                evidence=["junit-1"],
            )
        ]
    )

    validator = RunValidator(artifact_store=store)
    validator.validate(spec, record)

    raw_record = store.get("runs/run-1/record.json")
    raw_report = store.get("runs/run-1/report.json")
    assert raw_record is not None
    assert raw_report is not None
    record_parsed = json.loads(raw_record.decode())
    report_parsed = json.loads(raw_report.decode())
    assert record_parsed["run_id"] == "run-1"
    assert report_parsed["result"] == "PASS"


def test_validator_report_is_structured_json():
    spec = _ci_spec([{"action": "test.unit", "criteria": {"expect_all_pass": True}}])
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"tests": 1, "failures": 0, "errors": 0},
                evidence=[],
            )
        ]
    )

    report = RunValidator().validate(spec, record)
    encoded = json.dumps(report.to_dict(), sort_keys=True)
    parsed = json.loads(encoded)

    assert parsed["result"] in ("PASS", "FAIL")
    assert isinstance(parsed["checks"], list)
    assert parsed["checks"][0]["check"].startswith("action:")


def test_min_coverage_criterion_enforced():
    spec = _ci_spec([{"action": "test.unit", "criteria": {"min_coverage": 80}}])
    record = _record(
        [
            RunTaskRecord(
                action="test.unit",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={
                    "tests": 10,
                    "failures": 0,
                    "errors": 0,
                    "coverage_percent": 72,
                },
                evidence=["junit-1"],
            )
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL
    assert "coverage 72" in " ".join(report.checks[0].details)


def test_max_cvss_criterion_enforced():
    spec = _ci_spec([{"action": "security.sca", "criteria": {"max_cvss": 7.0}}])
    record = _record(
        [
            RunTaskRecord(
                action="security.sca",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "vulnerabilities": [
                        {
                            "id": "CVE-Y",
                            "source": {"name": "nvd"},
                            "ratings": [{"method": "CVSSv31", "score": 8.5, "severity": "high"}],
                            "affects": [{"ref": "pkg:npm/y@1"}],
                        }
                    ],
                },
                evidence=["cdx-1"],
            )
        ]
    )

    report = RunValidator().validate(spec, record)

    assert report.result == ValidationResult.FAIL
    assert "8.5" in " ".join(report.checks[0].details)


# ---------------------------------------- new criterion evaluators (Track I) -


def test_signing_identity_type_keypair_recognized():
    spec = _ci_spec([{"action": "sign.artifact", "criteria": {"signing_identity_type": "keypair"}}])
    record = _record(
        [
            RunTaskRecord(
                action="sign.artifact",
                adapter_id="adapter-cosign-sign",
                status=TaskStatus.COMPLETED,
                findings={
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {"publicKey": {"hint": "abc"}},
                    "messageSignature": {"signature": "deadbeef"},
                },
                evidence=["sigstore-bundle:inline"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_signing_identity_type_mismatch_fails():
    spec = _ci_spec(
        [{"action": "sign.artifact", "criteria": {"signing_identity_type": "ambient-oidc"}}]
    )
    record = _record(
        [
            RunTaskRecord(
                action="sign.artifact",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {"publicKey": {"hint": "x"}},
                    "messageSignature": {"signature": "x"},
                },
                evidence=[],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.FAIL


def test_format_cyclonedx_passes_for_cyclonedx_sbom():
    spec = _ci_spec([{"action": "sbom.generate", "criteria": {"format": "cyclonedx"}}])
    record = _record(
        [
            RunTaskRecord(
                action="sbom.generate",
                adapter_id="adapter-syft-sbom",
                status=TaskStatus.COMPLETED,
                findings={"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
                evidence=["cyclonedx-sbom:inline"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_destination_registry_required_passes_with_real_ref():
    spec = _ci_spec(
        [{"action": "publish.artifact", "criteria": {"destination_registry_required": True}}]
    )
    record = _record(
        [
            RunTaskRecord(
                action="publish.artifact",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings=None,
                evidence=["published-artifact-ref:ghcr.io/wtlinnertz/x@sha256:abc123"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_destination_registry_required_fails_when_missing():
    spec = _ci_spec(
        [{"action": "publish.artifact", "criteria": {"destination_registry_required": True}}]
    )
    record = _record(
        [
            RunTaskRecord(
                action="publish.artifact",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings=None,
                evidence=["exit-code:0"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.FAIL


def test_artifact_type_oci_image_recognized():
    spec = _ci_spec([{"action": "build.artifact", "criteria": {"artifact_type": "oci-image"}}])
    record = _record(
        [
            RunTaskRecord(
                action="build.artifact",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings=None,
                evidence=["oci-image-digest:sha256:abc", "tag:demo:1", "exit-code:0"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_reconciled_within_seconds_accepts_when_reconciler_acked():
    spec = _ci_spec(
        [{"action": "deploy.environment", "criteria": {"reconciled_within_seconds": 300}}]
    )
    record = _record(
        [
            RunTaskRecord(
                action="deploy.environment",
                adapter_id="adapter-flux-handoff",
                status=TaskStatus.COMPLETED,
                findings=None,
                evidence=["reconciled-commit-sha:0123", "reconciler-status:accepted"],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_all_endpoints_healthy_passes_when_all_pass():
    spec = _ci_spec([{"action": "verify.health", "criteria": {"all_endpoints_healthy": True}}])
    record = _record(
        [
            RunTaskRecord(
                action="verify.health",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"checks": [{"pass": True}, {"pass": True}]},
                evidence=[],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS


def test_all_endpoints_healthy_fails_on_any_unhealthy():
    spec = _ci_spec([{"action": "verify.health", "criteria": {"all_endpoints_healthy": True}}])
    record = _record(
        [
            RunTaskRecord(
                action="verify.health",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"checks": [{"pass": True}, {"pass": False}]},
                evidence=[],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.FAIL


def test_min_success_rate_threshold_enforced():
    spec = _ci_spec([{"action": "verify.slo", "criteria": {"min_success_rate": 0.99}}])
    record = _record(
        [
            RunTaskRecord(
                action="verify.slo",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"observed_success_rate": 0.985},
                evidence=[],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.FAIL


def test_window_seconds_accepted_as_input():
    spec = _ci_spec(
        [{"action": "verify.slo", "criteria": {"window_seconds": 600, "min_success_rate": 0.99}}]
    )
    record = _record(
        [
            RunTaskRecord(
                action="verify.slo",
                adapter_id="a",
                status=TaskStatus.COMPLETED,
                findings={"observed_success_rate": 0.999},
                evidence=[],
            )
        ]
    )
    report = RunValidator().validate(spec, record)
    assert report.result == ValidationResult.PASS
