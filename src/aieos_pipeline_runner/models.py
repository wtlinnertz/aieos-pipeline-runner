"""Core data models for the pipeline runner.

LoadedSpec — a frozen, parsed CI or CD spec with its source reference and
content hash. Produced by the ingestion layer; consumed by every downstream
stage.

ValidatorReport — common PASS/FAIL envelope used by all three validators
(spec, plan, run). Structured so operators and machines read the same signal.

BoundPlan / BoundTask — the resolver output and the orchestrator input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal


class SpecKind(StrEnum):
    CI = "ci"
    CD = "cd"


class TaskStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ValidationResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class LoadedSpec:
    """A frozen CI or CD spec loaded from its source.

    kind — ci | cd (auto-detected at load time).
    content — parsed YAML as a dict.
    source_ref — a stable reference for the source (file:// URI or
        artifact-store key). Used in event streams and validator reports.
    content_hash — sha256 hex of the raw bytes; immutability anchor.
    """

    kind: SpecKind
    content: dict[str, Any]
    source_ref: str
    content_hash: str


@dataclass
class ValidatorCheck:
    check: str
    result: ValidationResult
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"check": self.check, "result": self.result.value}
        if self.details:
            payload["details"] = list(self.details)
        return payload


@dataclass
class ValidatorReport:
    """Structured PASS/FAIL envelope shared by spec, plan, and run validators."""

    result: ValidationResult
    checks: list[ValidatorCheck] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": self.result.value,
            "checks": [c.to_dict() for c in self.checks],
        }

    @classmethod
    def from_checks(cls, checks: list[ValidatorCheck]) -> ValidatorReport:
        overall = (
            ValidationResult.PASS
            if all(c.result == ValidationResult.PASS for c in checks)
            else ValidationResult.FAIL
        )
        return cls(result=overall, checks=list(checks))


@dataclass(frozen=True)
class BoundTask:
    """One task in the resolved plan — an action bound to a specific adapter."""

    action: str
    adapter_id: str
    adapter_version: str
    criteria: dict[str, Any]
    inputs: dict[str, Any]
    depends_on: tuple[str, ...]


@dataclass(frozen=True)
class UnresolvedAction:
    """An action in the spec that the resolver could not bind unambiguously."""

    action: str
    reason: Literal["no_adapter", "ambiguous"]
    candidates: tuple[str, ...] = ()


@dataclass(frozen=True)
class BoundPlan:
    """The resolver's output — a DAG of bound tasks plus any unresolved actions."""

    spec_ref: str
    spec_hash: str
    tasks: tuple[BoundTask, ...]
    unresolved: tuple[UnresolvedAction, ...] = ()


@dataclass
class RunTaskRecord:
    """What the orchestrator records for one executed task."""

    action: str
    adapter_id: str
    status: TaskStatus
    findings: dict[str, Any] | None
    evidence: list[str]
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


@dataclass
class RunRecord:
    """Orchestrator output. Not a judgment — just the collected facts."""

    run_id: str
    spec_ref: str
    spec_hash: str
    tasks: list[RunTaskRecord] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
