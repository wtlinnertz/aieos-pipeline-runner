"""M3.2 — spec validator tests."""

from __future__ import annotations

import hashlib
import json

from aieos_pipeline_runner.ingestion import load_spec_from_file
from aieos_pipeline_runner.models import LoadedSpec, SpecKind, ValidationResult
from aieos_pipeline_runner.spec_validator import validate_spec


def _load(tmp_path, yaml_text):
    p = tmp_path / "spec.yaml"
    p.write_text(yaml_text)
    return load_spec_from_file(p, expected_hash=hashlib.sha256(p.read_bytes()).hexdigest())


def test_valid_spec_passes(tmp_path, ci_spec_yaml):
    spec = _load(tmp_path, ci_spec_yaml)

    report = validate_spec(spec)

    assert report.result == ValidationResult.PASS
    check_names = [c.check for c in report.checks]
    assert check_names == ["schema_valid", "actions_in_taxonomy", "criteria_shape", "dag_valid"]
    assert all(c.result == ValidationResult.PASS for c in report.checks)


def test_valid_cd_spec_passes(tmp_path, cd_spec_yaml):
    spec = _load(tmp_path, cd_spec_yaml)

    report = validate_spec(spec)

    assert report.result == ValidationResult.PASS


def test_unknown_action_fails(tmp_path):
    # Swap out a known action for a bogus one via content injection.
    # We bypass ingestion's schema validation by constructing LoadedSpec directly
    # with a taxonomy-unknown action.
    content = {
        "spec_version": "1.0.0",
        "code_repo": "wtlinnertz/example",
        "actions": [
            {"action": "test.unit", "criteria": {}},
            {"action": "bogus.action", "criteria": {}, "depends_on": ["test.unit"]},
        ],
        "policies": {"timeout_seconds": 1800, "retry": {"max_retries": 0}},
    }
    spec = LoadedSpec(
        kind=SpecKind.CI, content=content, source_ref="inline://test", content_hash="0" * 64
    )

    report = validate_spec(spec)

    assert report.result == ValidationResult.FAIL
    actions_check = next(c for c in report.checks if c.check == "actions_in_taxonomy")
    assert actions_check.result == ValidationResult.FAIL
    assert any("bogus.action" in d for d in actions_check.details)


def test_cyclic_dependency_fails(tmp_path):
    """Hand-craft a CI spec with a cycle (the schema allows any strings in
    depends_on, so the cycle only surfaces at the DAG check)."""
    content = {
        "spec_version": "1.0.0",
        "code_repo": "wtlinnertz/example",
        "actions": [
            {"action": "test.unit", "criteria": {}, "depends_on": ["build.artifact"]},
            {"action": "build.artifact", "criteria": {}, "depends_on": ["test.unit"]},
        ],
        "policies": {"timeout_seconds": 1800, "retry": {"max_retries": 0}},
    }
    spec = LoadedSpec(
        kind=SpecKind.CI, content=content, source_ref="inline://test", content_hash="0" * 64
    )

    report = validate_spec(spec)

    assert report.result == ValidationResult.FAIL
    dag_check = next(c for c in report.checks if c.check == "dag_valid")
    assert dag_check.result == ValidationResult.FAIL
    assert any("cycle" in d for d in dag_check.details)


def test_dag_check_catches_dangling_dependency(tmp_path):
    content = {
        "spec_version": "1.0.0",
        "code_repo": "wtlinnertz/example",
        "actions": [
            {"action": "test.unit", "criteria": {}, "depends_on": ["build.artifact"]},
        ],
        "policies": {"timeout_seconds": 1800, "retry": {"max_retries": 0}},
    }
    spec = LoadedSpec(
        kind=SpecKind.CI, content=content, source_ref="inline://test", content_hash="0" * 64
    )

    report = validate_spec(spec)

    assert report.result == ValidationResult.FAIL
    dag_check = next(c for c in report.checks if c.check == "dag_valid")
    assert dag_check.result == ValidationResult.FAIL
    assert any("build.artifact" in d for d in dag_check.details)


def test_cd_promotion_cycle_fails(tmp_path):
    content = {
        "spec_version": "1.0.0",
        "artifact_ref": "ghcr.io/x@sha256:dead",
        "environments": [
            {"name": "a", "actions": [{"action": "deploy.environment", "criteria": {}}]},
            {"name": "b", "actions": [{"action": "deploy.environment", "criteria": {}}]},
        ],
        "promotions": [
            {"from": "a", "to": "b", "type": "promote"},
            {"from": "b", "to": "a", "type": "promote"},
        ],
        "rollback_conditions": {},
        "policies": {"timeout_seconds": 3600, "retry": {"max_retries": 0}},
    }
    spec = LoadedSpec(
        kind=SpecKind.CD, content=content, source_ref="inline://test", content_hash="0" * 64
    )

    report = validate_spec(spec)

    assert report.result == ValidationResult.FAIL
    dag_check = next(c for c in report.checks if c.check == "dag_valid")
    assert dag_check.result == ValidationResult.FAIL
    assert any("cycle" in d for d in dag_check.details)


def test_report_is_machine_readable_json(tmp_path, ci_spec_yaml):
    spec = _load(tmp_path, ci_spec_yaml)

    report = validate_spec(spec)
    encoded = json.dumps(report.to_dict(), sort_keys=True)
    # parses as JSON
    parsed = json.loads(encoded)

    assert parsed["result"] in ("PASS", "FAIL")
    assert isinstance(parsed["checks"], list)
    for c in parsed["checks"]:
        assert "check" in c
        assert "result" in c
