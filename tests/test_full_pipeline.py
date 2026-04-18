"""M3.7 — full-pipeline integration test via the mock adapter.

Drives a CI spec through every stage in order:
  ingestion -> spec validator -> resolver -> plan validator ->
  orchestrator -> run validator

All invocations use the mock adapter + mock registry so this test runs
offline without any harness, registry, or adapter binary.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aieos_pipeline_runner.artifact_store import FilesystemArtifactStore
from aieos_pipeline_runner.ingestion import load_spec_from_file
from aieos_pipeline_runner.mock_adapter import MockAgent, MockMode, MockRegistry
from aieos_pipeline_runner.models import ValidationResult
from aieos_pipeline_runner.orchestrator import RunOrchestrator
from aieos_pipeline_runner.plan_validator import validate_plan
from aieos_pipeline_runner.resolver import Resolver
from aieos_pipeline_runner.run_validator import RunValidator
from aieos_pipeline_runner.spec_validator import validate_spec

CI_SPEC = """\
spec_version: "1.0.0"
code_repo: "wtlinnertz/demo"

actions:
  - action: test.unit
    criteria:
      expect_all_pass: true
      min_coverage: 80
  - action: security.sast
    criteria:
      max_severity: high
  - action: build.artifact
    criteria: {}
    depends_on:
      - test.unit

policies:
  timeout_seconds: 1800
  retry:
    max_retries: 0
"""


def _load_ci(tmp_path: Path) -> object:
    p = tmp_path / "ci.spec.yaml"
    p.write_text(CI_SPEC)
    return load_spec_from_file(p, expected_hash=hashlib.sha256(p.read_bytes()).hexdigest())


def test_full_pipeline_pass_path(tmp_path: Path):
    """Every stage green; run validator returns PASS."""
    spec = _load_ci(tmp_path)

    # Stage 1: spec validator
    spec_report = validate_spec(spec)
    assert spec_report.result == ValidationResult.PASS

    # Stage 2: resolver
    resolver = Resolver(registry=MockRegistry())
    plan = resolver.resolve(spec)
    assert plan.tasks and not plan.unresolved

    # Stage 3: plan validator
    plan_report = validate_plan(spec, plan)
    assert plan_report.result == ValidationResult.PASS

    # Stage 4: orchestrator
    agent = MockAgent(default_mode=MockMode.PASS)
    record = RunOrchestrator(agent=agent).execute(plan, run_id="run-pass")
    assert {t.action for t in record.tasks} == {"test.unit", "security.sast", "build.artifact"}

    # Stage 5: run validator + publication
    store = FilesystemArtifactStore(tmp_path / "store")
    run_report = RunValidator(artifact_store=store).validate(spec, record)
    assert run_report.result == ValidationResult.PASS
    assert store.get("runs/run-pass/record.json") is not None
    assert store.get("runs/run-pass/report.json") is not None


def test_full_pipeline_fail_path_fails_at_run_validator(tmp_path: Path):
    """Mock returns a SARIF finding for security.sast; with max_severity=medium
    the 'error' level (mapped to 'high') exceeds the threshold and run
    validator FAILs."""
    spec_with_tighter_threshold = CI_SPEC.replace("max_severity: high", "max_severity: medium")
    p = tmp_path / "ci.spec.yaml"
    p.write_text(spec_with_tighter_threshold)
    spec = load_spec_from_file(p, expected_hash=hashlib.sha256(p.read_bytes()).hexdigest())

    assert validate_spec(spec).result == ValidationResult.PASS

    plan = Resolver(registry=MockRegistry()).resolve(spec)
    assert validate_plan(spec, plan).result == ValidationResult.PASS

    agent = MockAgent(
        default_mode=MockMode.PASS,
        mode_by_action={"security.sast": MockMode.FAIL},
    )
    record = RunOrchestrator(agent=agent).execute(plan, run_id="run-fail")

    run_report = RunValidator().validate(spec, record)

    assert run_report.result == ValidationResult.FAIL
    sast = next(c for c in run_report.checks if c.check == "action:security.sast")
    assert sast.result == ValidationResult.FAIL


def test_full_pipeline_failed_task_skips_dependents(tmp_path: Path):
    """test.unit FAIL (low coverage) -> build.artifact is SKIPPED by the
    orchestrator and also FAILs at the run validator."""
    spec = _load_ci(tmp_path)

    plan = Resolver(registry=MockRegistry()).resolve(spec)

    # Make test.unit return PASS-shaped data but with coverage that violates
    # the spec's min_coverage=80 — run validator rejects; orchestrator sees
    # COMPLETED status; downstream dependents still run (orchestrator only
    # short-circuits on FAILED/SKIPPED, not on criteria violation, since
    # criteria judgment is the run validator's job). That's deliberate.
    agent = MockAgent(default_mode=MockMode.FAIL)
    record = RunOrchestrator(agent=agent).execute(plan, run_id="run-cov-fail")

    run_report = RunValidator().validate(spec, record)

    assert run_report.result == ValidationResult.FAIL


def test_full_pipeline_resolver_refuses_on_no_adapter(tmp_path: Path):
    """A registry that returns no adapters leaves everything unresolved;
    the plan validator refuses the empty plan."""
    spec = _load_ci(tmp_path)

    class _EmptyRegistry:
        def find_adapters(self, _action, context=None):
            return []

    plan = Resolver(registry=_EmptyRegistry()).resolve(spec)
    plan_report = validate_plan(spec, plan)

    assert plan_report.result == ValidationResult.FAIL
    nores = next(c for c in plan_report.checks if c.check == "no_unresolved_actions")
    assert nores.result == ValidationResult.FAIL
