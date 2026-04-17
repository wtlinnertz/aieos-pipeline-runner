# aieos-pipeline-runner

Cross-cutting platform infrastructure in the AIEOS Tooling & Platform tier, alongside `aieos-agent-harness` and `aieos-artifact-store`. Compiles frozen CI and CD specs (produced by Layer 4 Engineering Execution and Layer 5 Release & Exposure) into bound execution plans, hands those plans off to the agent harness for execution, and evaluates the resulting run record against the spec's success criteria. Serves both layers; belongs to neither.

## Status

Scaffolding only. Implementation lands in M3 per `~/second-brain/AIEOS Spec-Driven CI-CD Implementation Plan.md`.

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

## License

MIT. See `LICENSE`.
