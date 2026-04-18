"""Structured event emission for the runner CLI.

Mirrors the M2.4 harness shape so downstream log forwarders see a uniform
stream regardless of whether events originate in the harness or in the
runner CLI. Events are JSON lines, sort_keys for deterministic output.

EmittingAgentProxy wraps any AgentAPI-compatible agent and emits
task.start / task.evidence / task.result around each receive_task call.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TextIO

from .models import TaskStatus


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    s = ts.isoformat()
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    return s


class RunEventEmitter:
    """Emits JSON-line events for one run."""

    def __init__(
        self,
        run_id: str,
        spec_ref: str = "",
        out: TextIO | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not run_id:
            raise ValueError("run_id must be non-empty")
        self._run_id = run_id
        self._spec_ref = spec_ref
        self._out: TextIO = out if out is not None else sys.stdout
        self._clock = clock or _default_clock

    def _emit(self, payload: dict[str, Any]) -> None:
        enriched = dict(payload)
        enriched["run_id"] = self._run_id
        enriched["timestamp"] = _iso(self._clock())
        self._out.write(json.dumps(enriched, sort_keys=True) + "\n")
        self._out.flush()

    def run_start(self) -> None:
        self._emit({"type": "run.start", "spec_ref": self._spec_ref})

    def task_start(self, task_id: str, action: str, adapter_id: str = "") -> None:
        self._emit(
            {
                "type": "task.start",
                "task_id": task_id,
                "action": action,
                "adapter_id": adapter_id,
            }
        )

    def task_evidence(self, task_id: str, evidence_ref: str) -> None:
        self._emit(
            {
                "type": "task.evidence",
                "task_id": task_id,
                "evidence_ref": evidence_ref,
            }
        )

    def task_result(
        self,
        task_id: str,
        action: str,
        adapter_id: str,
        status: str,
        findings_ref: str = "",
    ) -> None:
        self._emit(
            {
                "type": "task.result",
                "task_id": task_id,
                "action": action,
                "adapter_id": adapter_id,
                "status": status,
                "findings_ref": findings_ref,
            }
        )

    def run_end(self, status: str) -> None:
        self._emit({"type": "run.end", "status": status})


class EmittingAgentProxy:
    """Wraps an AgentAPI-compatible agent and emits task-lifecycle events."""

    def __init__(self, agent: Any, emitter: RunEventEmitter) -> None:
        self._agent = agent
        self._emitter = emitter

    def receive_task(
        self,
        action: str,
        criteria: dict[str, Any],
        inputs: dict[str, Any],
        task_id: str | None = None,
    ) -> Any:
        tid = task_id or f"{action}-{uuid.uuid4().hex[:12]}"
        self._emitter.task_start(task_id=tid, action=action, adapter_id="")
        result = self._agent.receive_task(
            action=action, criteria=criteria, inputs=inputs, task_id=tid
        )
        for ev in result.evidence:
            self._emitter.task_evidence(task_id=tid, evidence_ref=ev)
        status_value = (
            result.status.value if isinstance(result.status, TaskStatus) else str(result.status)
        )
        findings_ref = f"inline://{result.adapter_id}" if result.findings is not None else ""
        self._emitter.task_result(
            task_id=tid,
            action=action,
            adapter_id=result.adapter_id,
            status=status_value,
            findings_ref=findings_ref,
        )
        return result
