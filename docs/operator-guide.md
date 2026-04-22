# Operator Guide — aieos-pipeline-runner

Audience: operators deploying the AIEOS pipeline runner as the execution
boundary for spec-driven CI/CD.

The pipeline runner is the tool-agnostic CLI that developer pipelines,
entry-point shims (GitHub Actions, webhooks, IDP actions), and operators
all call. It ingests a frozen CI or CD spec, validates it, resolves it
against the harness's registered adapters, executes the resulting plan,
and returns a PASS/FAIL verdict with structured run records. This guide
covers deployment paths, configuration, incident diagnosis, and the
failure-mode taxonomy.

For companion operator concerns on the registry side, see
[aieos-agent-harness/docs/operator-guide.md](https://github.com/wtlinnertz/aieos-agent-harness/blob/main/docs/operator-guide.md).

---

## Deployment

### Install

The runner is a pip-installable Python package:

```bash
pip install git+https://github.com/wtlinnertz/aieos-pipeline-runner.git
```

Python 3.11+ required. Runtime dependencies: `jsonschema[format]`,
`pyyaml`, `structlog`. No runtime dependency on the harness — the runner
declares thin `RegistryAPI` and `AgentAPI` protocols and accepts
implementations via dependency injection. The v1 default is a mock
registry + mock agent packaged with the runner for dry runs; production
wires to the live harness.

### Where it runs

Three common patterns:

1. **Inline in GitHub Actions.** The runner is installed in the workflow
   step and invoked directly. This is the v1 pilot pattern and the
   easiest path to spec-driven CI.
2. **Standalone service.** The runner exposed behind an HTTP endpoint
   that receives trigger events from a webhook listener or IDP action.
   Reasonable for orgs that want a single governance choke point across
   many trigger sources.
3. **One-shot CLI.** Operators invoke the runner directly for ad-hoc
   pipeline runs, dry-run spec validation, or incident triage.

All three call the same CLI. The runner is the tool-agnostic boundary —
anything upstream of the CLI is entry-point shim.

---

## CLI reference

```text
aieos-pipeline-runner run \
    --spec <path-or-ref> \
    [--env <env>] \
    [--expected-hash <sha256>] \
    [--artifact-store <dir>] \
    [--use-mock-adapters] \
    [--run-id <id>]
```

Full documentation of flags, exit codes, event types, bound-plan schema,
and run-record schema lives in the frozen
[runner-interface.md](https://github.com/wtlinnertz/aieos-governance-foundation/blob/main/runner-interface.md)
(tagged `v1.0-runner-interface`). That document is the authoritative
reference. This guide covers operational concerns around that contract.

### Exit codes in operations

- `0` — overall PASS. Every validator (spec, plan, run) passed and every
  criterion held. No further action.
- `1` — overall FAIL. At least one validator refused the input. The run
  report on stderr identifies which check failed. Investigate the
  failing check; most exit 1 cases are pipeline bugs or real criterion
  violations, not infrastructure problems.
- `2` — infrastructure error. The runner couldn't get far enough to even
  judge. Typical causes: spec not frozen, hash mismatch, unparseable
  YAML, artifact store unreachable, `--use-mock-adapters` omitted in v1.
  Investigate the stderr diagnostic; these are deployment problems.

Alerting: a sustained non-zero exit rate from a given pipeline indicates
either a real violation (action for the owning team) or an infra drift
(action for the platform team). Exit 2 should page platform; exit 1
should notify the pipeline's owner.

---

## Configuration surface

The runner has intentionally few configuration knobs. The spec is the
contract; the runner executes it.

### Spec sources

`--spec` accepts a file path today. Artifact-store refs (hash-based
retrieval) are a v1.1 enhancement; the ingestion module has a
`load_spec_from_artifact_store` API that's currently exposed only via
Python import.

### Artifact store

`--artifact-store` points at a directory-backed store. The runner writes
the run record and validator report under `runs/<run_id>/record.json`
and `runs/<run_id>/report.json`. In production, wire this to a shared
storage location your org retains per compliance policy. Retention
policies are out of scope for v1 — archive the directory per your
existing artifact retention rules.

### Adapter mode

`--use-mock-adapters` is the v1 default and the only supported mode.
Real-adapter wiring requires the harness registry to be populated with
attested adapters, which is an operator-managed integration step
separate from the runner itself.

### Run identity

`--run-id` supplies a deterministic run identifier. Without it, the
runner generates `run-<12 hex>`. In CI pipelines, derive the run_id from
the CI system's job identifier so logs correlate across systems:
`run-gha-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}`.

---

## Event stream operations

The runner emits JSON lines on stdout:

- `run.start` / `run.end` — one each per run
- `task.start` / `task.result` — one each per action instance
- `task.evidence` — one per evidence artifact the adapter emits (usually
  one to three per task)

Ship stdout to your log aggregator. The schema is stable; every event
carries `type`, `run_id`, and `timestamp` at minimum. Parse-once, route
by `type` for dashboards.

Metrics derivable from the stream:

- Run duration: `run.end.timestamp - run.start.timestamp`
- Per-action duration: `task.result.timestamp - task.start.timestamp`
  keyed by `task_id`
- Failure rate: `count(task.result.status == "failed")` / `count(task.start)`
- Skip rate: `count(task.result.status == "skipped")` — every skip means
  an upstream task failed

The report (on stderr) is the run's verdict; the event stream is the
trace of how it got there.

---

## Incident diagnosis

### Exit 2: "spec ingestion failed"

The runner rejected the spec before it got to validation. Sub-cases:

- **Hash mismatch.** Caller supplied an `--expected-hash` that doesn't
  match the file's actual sha256. Recompute:
  ```bash
  python3 -c "import hashlib; print(hashlib.sha256(open('<spec>','rb').read()).hexdigest())"
  ```
  If the file hash changed since the pipeline picked it up, something in
  the pipeline is mutating the spec mid-run. That's a governance
  incident — freeze-before-promote is violated.
- **File not found.** Path is wrong, or the CI workspace lost the file
  before the runner step.
- **Unparseable YAML.** Open the file; typical causes are merge-conflict
  markers from a bad rebase.
- **Unknown spec kind.** The runner couldn't tell whether the spec is CI
  or CD from its top-level keys (CI has `code_repo` + `actions`; CD has
  `artifact_ref` + `environments`). The spec is malformed; regenerate
  from template.

### Exit 1: spec validator reports `actions_in_taxonomy` FAIL

The spec references an action not in the frozen v1.0 taxonomy. Either a
typo or a spec authored against a pre-release vocabulary. Fix the spec;
the taxonomy at `taxonomy/actions-v1.md` is authoritative.

### Exit 1: plan validator reports `no_unresolved_actions` FAIL

The resolver couldn't bind an action to an adapter. The report names the
action and the reason:

- `no_adapter` — no adapter is registered in the harness for this
  action. Check with the harness operator; most likely the adapter
  hasn't completed the registration workflow yet.
- `ambiguous` — more than one adapter satisfies the action and the spec
  + org defaults don't narrow to one. The spec's
  `policies.adapter_preferences` must pick exactly one.

### Exit 1: run validator reports per-action FAIL

The action's adapter completed but its canonical findings didn't satisfy
the spec's criteria. The report names the criterion and observation
(e.g., `max_severity: observed critical exceeds threshold high`). Two
responses:

- Real violation — the owning team has a finding to address.
- Criterion too strict for the service's current state — the spec owner
  tunes the threshold and re-freezes.

The run validator never trusts an adapter's self-reported status; it
reads the actual findings. An action whose adapter returned
`status=completed` can still FAIL at the run validator if the findings
show a criterion violation. This is by design — see the run validator's
unit tests for the `test_validator_reads_findings_not_adapter_status`
case.

### Orchestrator reports tasks as SKIPPED

An upstream task in the DAG failed, so downstream tasks were skipped
without invoking their adapters. The run record shows this with an
`error` field on every skipped task naming the upstream action. This is
correct behavior — no additional action required on the skip itself, but
the upstream failure is what to investigate.

---

## Failure-mode taxonomy

The pilot's chaos tests (at
`aieos-artifact-store/.aieos/chaos-tests.sh`) exercise the v1 failure
modes. As an operator you'll see each of these in production:

| Mode | Exit | Typical diagnostic | Response |
|---|---|---|---|
| Hash mismatch | 2 | `spec ingestion failed ... hash` | Recompute hash; investigate spec mutation if unexpected |
| Unknown action | 1 | `actions_in_taxonomy ... not in taxonomy` | Fix spec; taxonomy is authoritative |
| Cyclic DAG | 1 | `dag_valid ... cycle` | Redesign dependency graph |
| Non-mock adapter requested | 2 | `non-mock adapter wiring is a deferred integration` | Use `--use-mock-adapters` until v1.1 |
| Ambiguous resolution | 1 | `no_unresolved_actions ... ambiguous` | Spec declares preference, or operator unregisters stale adapter |
| Criterion violation | 1 | `action:<name> ... observed X exceeds threshold Y` | Fix the underlying issue or tune threshold |
| Flux reconcile refused | 1 | `deploy.environment ... reconciler timeout` | Investigate manifests repo and Flux Kustomization |

---

## Upgrade path

Minor version bumps to the runner are safe for ops: the runner-interface
is frozen at v1.0, and pyproject pins the runner's own deps at
compatible minimums. Major version bumps follow the cutover protocol
(minor schema bump + announced cutover date + grace window).

Upgrade a deployment:

```bash
pip install --upgrade aieos-pipeline-runner
aieos-pipeline-runner run --spec .aieos/ci.spec.yaml --expected-hash <sha> --use-mock-adapters --run-id upgrade-smoke
```

The smoke run uses mock adapters and a known-good spec; any regression
surfaces before pipelines hit it.

---

## Related

- [runner-interface.md](https://github.com/wtlinnertz/aieos-governance-foundation/blob/main/runner-interface.md)
  — frozen public contract of the runner (CLI, events, bound-plan
  schema, run-record schema)
- [spec-authoring-guide.md](https://github.com/wtlinnertz/aieos-governance-foundation/blob/main/docs/spec-authoring-guide.md)
  — how developers author the specs this runner consumes
- [aieos-agent-harness operator guide](https://github.com/wtlinnertz/aieos-agent-harness/blob/main/docs/operator-guide.md)
  — the registry side of the governance plane
