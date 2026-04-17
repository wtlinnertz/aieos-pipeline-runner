# Spec-Driven CI/CD — Pipeline Runner Context

This is a new repo. Cross-cutting platform infrastructure in the Tooling & Platform tier,
alongside `aieos-agent-harness` and `aieos-artifact-store`. It serves Layer 4 (engineering
execution) and Layer 5 (release & exposure) but belongs to neither.

## What lives here (M3 deliverables)

- Spec ingestion (load frozen CI/CD specs, verify immutability)
- Spec validator (structural validation against schema, DAG cycle check)
- Resolver (bind spec actions to registered adapters via harness registry)
- Plan validator (verify bound plan completeness, no ambiguity)
- Run orchestrator (hand bound plan to harness, collect results)
- Run validator (evaluate spec success criteria against canonical findings)
- Mock adapter harness (test-only, canned findings)
- Runner CLI (`aieos-pipeline-runner run --spec <path-or-ref> --env <env>`)

## Implementation plan

The full plan is at: `~/second-brain/AIEOS Spec-Driven CI-CD Implementation Plan.md`

Read the M3 section before starting any task. The runner depends on:
- M1 frozen artifacts in `aieos-governance-foundation` (taxonomy, schemas, contracts)
- M2 harness capability substrate in `aieos-agent-harness` (registry API, agent interface)

## Key design decisions

- The resolver has NO silent-pick fallback. Ambiguous resolution fails the plan.
- The run validator is evidence-based only. It never trusts an adapter's self-reported PASS/FAIL.
- The run orchestrator does not evaluate success. That's the run validator's job.
- Three distinct validators: spec validator, plan validator, run validator. Keep them separate.
- `runner-interface.md` (CLI args, bound-plan schema, event stream, run-record shape) freezes at v1.0 in `aieos-governance-foundation` before M5 opens.

## Python conventions

- Type hints on public functions.
- `ruff` for linting. `mypy` if config exists.
- `structlog` over `print`. Logging keys in snake_case.
- Dependency injection for anything that touches the outside world.
- Tests in AAA shape. One behavior per test. Name: `test_<unit>_<condition>_<expected>`.
- Full test coverage against mock adapters before M4 ships real ones.

## Three invariants (never violate)

1. Separation of concerns.
2. Freeze-before-promote.
3. Validators judge, they don't help.
