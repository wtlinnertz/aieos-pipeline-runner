"""Command-line entry point for the AIEOS pipeline runner.

Usage:
  aieos-pipeline-runner run --spec <path-or-ref> --env <env> \
                            [--expected-hash <sha256>] \
                            [--artifact-store <dir>] \
                            [--use-mock-adapters]

Exit codes (per M3.8 spec):
  0  overall PASS (every validator passes; every action's criteria hold)
  1  overall FAIL (at least one validator fails — spec, plan, or run)
  2  infrastructure error (spec not frozen, hash mismatch, unparseable,
     missing artifact-store, etc.)

v1 defaults to mock adapters so the CLI can be exercised end-to-end
without a live harness. Real harness wiring is a deferred integration.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import TextIO

from .artifact_store import FilesystemArtifactStore
from .events import EmittingAgentProxy, RunEventEmitter
from .ingestion import (
    SpecIntegrityError,
    SpecKindError,
    SpecNotFrozenError,
    SpecSchemaError,
    load_spec_from_file,
)
from .mock_adapter import MockAgent, MockRegistry
from .models import ValidationResult
from .orchestrator import RunOrchestrator
from .plan_validator import validate_plan
from .resolver import Resolver
from .run_validator import RunValidator
from .spec_validator import validate_spec

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INFRA = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aieos-pipeline-runner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Execute a pipeline against a frozen spec")
    run.add_argument("--spec", required=True, help="Path to a frozen CI or CD spec file")
    run.add_argument("--env", default="ci", help="Execution environment context (default: ci)")
    run.add_argument(
        "--expected-hash",
        required=False,
        help="sha256 hex of the spec file (asserts immutability)",
    )
    run.add_argument(
        "--artifact-store",
        required=False,
        help="Directory-backed artifact store to receive the run record + report",
    )
    run.add_argument(
        "--use-mock-adapters",
        action="store_true",
        default=False,
        help="Use the in-process mock adapter for all actions (v1 default path)",
    )
    run.add_argument(
        "--run-id",
        required=False,
        help="Explicit run identifier (default: run-<12 hex chars>)",
    )
    return parser


def run_command(
    args: argparse.Namespace,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute a spec run end-to-end. Returns the CLI exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    # ---- Stage 1: load the spec -----------------------------------------
    try:
        spec = load_spec_from_file(Path(args.spec), expected_hash=args.expected_hash)
    except (
        SpecNotFrozenError,
        SpecIntegrityError,
        SpecSchemaError,
        SpecKindError,
        FileNotFoundError,
    ) as exc:
        err.write(f"[infra] spec ingestion failed: {exc}\n")
        return EXIT_INFRA

    run_id = args.run_id or f"run-{uuid.uuid4().hex[:12]}"
    emitter = RunEventEmitter(run_id=run_id, spec_ref=spec.source_ref, out=out)

    # ---- Stage 2: spec validator ----------------------------------------
    spec_report = validate_spec(spec)
    if spec_report.result == ValidationResult.FAIL:
        err.write(json.dumps(spec_report.to_dict(), sort_keys=True) + "\n")
        return EXIT_FAIL

    # ---- Stage 3: resolver ----------------------------------------------
    if not args.use_mock_adapters:
        err.write(
            "[infra] non-mock adapter wiring is a deferred integration; "
            "pass --use-mock-adapters to proceed with the mock path.\n"
        )
        return EXIT_INFRA
    registry = MockRegistry()
    plan = Resolver(registry=registry, context={"environment": args.env}).resolve(spec)

    # ---- Stage 4: plan validator ----------------------------------------
    plan_report = validate_plan(spec, plan)
    if plan_report.result == ValidationResult.FAIL:
        err.write(json.dumps(plan_report.to_dict(), sort_keys=True) + "\n")
        return EXIT_FAIL

    # ---- Stage 5: orchestrator ------------------------------------------
    emitter.run_start()
    agent = EmittingAgentProxy(MockAgent(), emitter)
    record = RunOrchestrator(agent=agent).execute(plan, run_id=run_id)

    # ---- Stage 6: run validator -----------------------------------------
    store = None
    if args.artifact_store:
        try:
            store = FilesystemArtifactStore(Path(args.artifact_store))
        except OSError as exc:
            err.write(f"[infra] artifact-store unavailable at {args.artifact_store!r}: {exc}\n")
            return EXIT_INFRA
    run_report = RunValidator(artifact_store=store).validate(spec, record)

    overall = (
        ValidationResult.PASS
        if run_report.result == ValidationResult.PASS
        else ValidationResult.FAIL
    )
    emitter.run_end(status="pass" if overall == ValidationResult.PASS else "fail")
    err.write(json.dumps(run_report.to_dict(), sort_keys=True) + "\n")
    return EXIT_PASS if overall == ValidationResult.PASS else EXIT_FAIL


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "run":
        return run_command(args)
    parser.print_help()
    return EXIT_INFRA


if __name__ == "__main__":
    sys.exit(main())
