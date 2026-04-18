"""M3.8 — runner CLI tests."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

from aieos_pipeline_runner.cli import EXIT_FAIL, EXIT_INFRA, EXIT_PASS


def _write_spec(tmp_path: Path, content: str, filename: str = "ci.spec.yaml") -> tuple[Path, str]:
    p = tmp_path / filename
    p.write_text(content)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


PASSING_SPEC = """\
spec_version: "1.0.0"
code_repo: "wtlinnertz/demo"

actions:
  - action: test.unit
    criteria:
      expect_all_pass: true
  - action: security.sast
    criteria:
      max_severity: high

policies:
  timeout_seconds: 1800
  retry:
    max_retries: 0
"""

FAILING_SPEC = """\
spec_version: "1.0.0"
code_repo: "wtlinnertz/demo"

actions:
  - action: security.sca
    criteria:
      max_severity: medium

policies:
  timeout_seconds: 1800
  retry:
    max_retries: 0
"""


def _run(argv: list[str], monkeypatch=None, capsys_out_err=None) -> tuple[int, str, str]:
    """Invoke the CLI main() and capture stdout+stderr via io.StringIO."""
    out = io.StringIO()
    err = io.StringIO()
    from aieos_pipeline_runner import cli as cli_module

    # Build args via the parser, then dispatch through run_command which
    # takes injectable streams. This avoids touching sys.stdout.
    parser = cli_module._build_parser()
    args = parser.parse_args(argv)
    code = cli_module.run_command(args, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_cli_exits_0_on_pass(tmp_path: Path):
    spec_path, expected = _write_spec(tmp_path, PASSING_SPEC)

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            expected,
            "--use-mock-adapters",
            "--run-id",
            "run-cli-pass",
        ]
    )

    assert code == EXIT_PASS, err
    # Run report on stderr reports PASS
    report = json.loads(err.strip().splitlines()[-1])
    assert report["result"] == "PASS"


def test_cli_exits_1_on_fail(tmp_path: Path):
    """FAILING_SPEC demands max_severity=medium; mock FAIL mode for
    security.sca emits a critical finding."""
    # Using default mock mode PASS gives empty findings for security.sca
    # which would technically pass. To force a fail, write an always-fail
    # wrapper spec that uses max_severity=medium but set global FAIL mode.
    # Since the CLI uses the default MockAgent (PASS), we instead test with
    # an unknown criterion — which fails conservatively in the run validator.
    spec = """\
spec_version: "1.0.0"
code_repo: "wtlinnertz/demo"

actions:
  - action: test.unit
    criteria:
      unsupported_criterion_must_fail_conservatively: true

policies:
  timeout_seconds: 1800
  retry:
    max_retries: 0
"""
    spec_path, expected = _write_spec(tmp_path, spec, "fail.yaml")

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            expected,
            "--use-mock-adapters",
            "--run-id",
            "run-cli-fail",
        ]
    )

    assert code == EXIT_FAIL, err
    report = json.loads(err.strip().splitlines()[-1])
    assert report["result"] == "FAIL"


def test_cli_exits_2_on_infra_error_missing_hash(tmp_path: Path):
    spec_path, _ = _write_spec(tmp_path, PASSING_SPEC, "no-hash.yaml")

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            # intentionally no --expected-hash
            "--use-mock-adapters",
        ]
    )

    assert code == EXIT_INFRA
    assert "spec ingestion failed" in err


def test_cli_exits_2_on_infra_error_hash_mismatch(tmp_path: Path):
    spec_path, _ = _write_spec(tmp_path, PASSING_SPEC, "mismatch.yaml")

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            "0" * 64,
            "--use-mock-adapters",
        ]
    )

    assert code == EXIT_INFRA
    assert "spec ingestion failed" in err


def test_cli_exits_2_when_mock_flag_absent(tmp_path: Path):
    """Without --use-mock-adapters, the CLI refuses (no real wiring in v1)."""
    spec_path, expected = _write_spec(tmp_path, PASSING_SPEC, "no-mock.yaml")

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            expected,
        ]
    )

    assert code == EXIT_INFRA
    assert "non-mock adapter wiring" in err


def test_cli_emits_structured_events(tmp_path: Path):
    spec_path, expected = _write_spec(tmp_path, PASSING_SPEC, "events.yaml")

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            expected,
            "--use-mock-adapters",
            "--run-id",
            "run-events-1",
        ]
    )

    assert code == EXIT_PASS
    events = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
    # Must include at least run.start, per-action task.start+task.result, run.end
    types = [e["type"] for e in events]
    assert "run.start" in types
    assert "run.end" in types
    assert types.count("task.start") >= 2  # two actions
    assert types.count("task.result") >= 2
    # Every event carries the run_id
    for event in events:
        assert event["run_id"] == "run-events-1"


def test_cli_publishes_run_record_when_artifact_store_supplied(tmp_path: Path):
    spec_path, expected = _write_spec(tmp_path, PASSING_SPEC, "publish.yaml")
    store_dir = tmp_path / "store"

    code, out, err = _run(
        [
            "run",
            "--spec",
            str(spec_path),
            "--expected-hash",
            expected,
            "--use-mock-adapters",
            "--artifact-store",
            str(store_dir),
            "--run-id",
            "run-publish-1",
        ]
    )

    assert code == EXIT_PASS
    assert (store_dir / "runs" / "run-publish-1" / "record.json").is_file()
    assert (store_dir / "runs" / "run-publish-1" / "report.json").is_file()
