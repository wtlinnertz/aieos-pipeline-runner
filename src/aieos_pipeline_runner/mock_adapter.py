"""Mock adapter harness — a test-only agent that satisfies any action
contract by emitting canned canonical findings.

Used to drive the full spec -> validator -> resolver -> plan validator ->
orchestrator -> run validator pipeline without needing a real harness or
real adapters. The CLI (M3.8) also supports invoking this mock for dry
runs before real adapters ship in M4.

Three modes per action:
  PASS       — canned findings that satisfy typical criteria (no failures,
               no vulnerabilities, coverage 100%).
  FAIL       — findings that violate typical criteria (one failure, one
               high-severity vulnerability).
  MALFORMED  — findings that do not match the canonical schema (missing
               required fields). Lets tests exercise the run validator's
               evidence-based judgment.

Registry integration: MockRegistryAPI returns a single canned entry for
any action, so the resolver always binds to the mock adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .models import TaskStatus


class MockMode(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    MALFORMED = "malformed"


@dataclass
class MockEntry:
    """Shape the resolver expects from a registry entry."""

    adapter_id: str = "adapter-mock"
    adapter_version: str = "0.0.1"


class MockRegistry:
    """A registry that resolves every action to the same mock adapter entry."""

    def __init__(self, adapter_id: str = "adapter-mock") -> None:
        self._entry = MockEntry(adapter_id=adapter_id)

    def find_adapters(self, _action: str, context=None):  # noqa: D401
        return [self._entry]


@dataclass
class MockTaskResult:
    """Minimal TaskResult shape the orchestrator consumes."""

    action: str
    adapter_id: str
    findings: dict[str, Any] | None
    evidence: list[str]
    status: TaskStatus
    error: str | None = None


@dataclass
class MockAgent:
    """An AgentAPI that routes action -> canned findings by mode.

    mode_by_action overrides the default_mode per action. Tests can build
    hybrid runs (some actions pass, some fail) by populating this map.
    """

    default_mode: MockMode = MockMode.PASS
    mode_by_action: dict[str, MockMode] = field(default_factory=dict)
    adapter_id: str = "adapter-mock"

    def receive_task(self, action, criteria, inputs, task_id=None):
        mode = self.mode_by_action.get(action, self.default_mode)
        findings, evidence, status = _canned_output(action, mode)
        return MockTaskResult(
            action=action,
            adapter_id=self.adapter_id,
            findings=findings,
            evidence=evidence,
            status=status,
        )


def _canned_output(
    action: str, mode: MockMode
) -> tuple[dict[str, Any] | None, list[str], TaskStatus]:
    """Return (findings, evidence, status) appropriate for the action + mode."""
    namespace = action.split(".", 1)[0]

    if mode == MockMode.MALFORMED:
        # Non-canonical shape — run validator should reject on schema-style
        # criteria (e.g., coverage_percent absent, severity fields missing).
        return ({"malformed": True}, [f"mock-evidence-{action}"], TaskStatus.COMPLETED)

    if namespace == "test":
        if mode == MockMode.PASS:
            return (
                {
                    "name": action,
                    "tests": 2,
                    "failures": 0,
                    "errors": 0,
                    "coverage_percent": 100,
                    "testsuite": [
                        {
                            "name": "mock",
                            "tests": 2,
                            "failures": 0,
                            "errors": 0,
                            "testcase": [
                                {"name": "a", "classname": "mock"},
                                {"name": "b", "classname": "mock"},
                            ],
                        }
                    ],
                },
                [f"junit-report://mock/{action}.json"],
                TaskStatus.COMPLETED,
            )
        return (  # FAIL
            {
                "name": action,
                "tests": 2,
                "failures": 1,
                "errors": 0,
                "coverage_percent": 40,
                "testsuite": [
                    {
                        "name": "mock",
                        "tests": 2,
                        "failures": 1,
                        "errors": 0,
                        "testcase": [
                            {"name": "a", "classname": "mock"},
                            {
                                "name": "b",
                                "classname": "mock",
                                "failure": {"message": "mock failure"},
                            },
                        ],
                    }
                ],
            },
            [f"junit-report://mock/{action}.json"],
            TaskStatus.COMPLETED,
        )

    if namespace == "security" and action in {
        "security.sast",
        "security.dast",
        "security.secret-scan",
    }:
        if mode == MockMode.PASS:
            return (
                {
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "mock", "version": "0"}}, "results": []}],
                },
                [f"sarif-report://mock/{action}.json"],
                TaskStatus.COMPLETED,
            )
        return (
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "mock", "version": "0"}},
                        "results": [
                            {
                                "ruleId": "MOCK-1",
                                "level": "error",
                                "message": {"text": "mock high-severity finding"},
                            }
                        ],
                    }
                ],
            },
            [f"sarif-report://mock/{action}.json"],
            TaskStatus.COMPLETED,
        )

    if action in {"security.sca", "security.container-scan", "security.license-scan"}:
        if mode == MockMode.PASS:
            return (
                {"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": []},
                [f"cdx-findings://mock/{action}.json"],
                TaskStatus.COMPLETED,
            )
        return (
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-MOCK-1",
                        "source": {"name": "mock"},
                        "ratings": [{"method": "CVSSv31", "score": 9.0, "severity": "critical"}],
                        "affects": [{"ref": "pkg:mock/x@1.0.0"}],
                    }
                ],
            },
            [f"cdx-findings://mock/{action}.json"],
            TaskStatus.COMPLETED,
        )

    if action == "sbom.generate":
        if mode == MockMode.PASS:
            return (
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "bom-ref": "pkg:mock/a@1",
                            "type": "library",
                            "name": "a",
                            "version": "1.0.0",
                        }
                    ],
                },
                [f"cdx-sbom://mock/{action}.json"],
                TaskStatus.COMPLETED,
            )
        return (
            {"bomFormat": "CycloneDX"},
            [],
            TaskStatus.COMPLETED,
        )  # missing specVersion + components

    if action.startswith("sign."):
        if mode == MockMode.PASS:
            return (
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {"publicKey": {"hint": "mock"}, "tlogEntries": []},
                    "messageSignature": {
                        "messageDigest": {"algorithm": "SHA2_256", "digest": "deadbeef"},
                        "signature": "mock-sig",
                    },
                },
                [f"sigstore-bundle://mock/{action}.json"],
                TaskStatus.COMPLETED,
            )
        return ({"mediaType": "wrong"}, [], TaskStatus.COMPLETED)

    # build.*, publish.*, deploy.*, verify.* — non-findings actions. No
    # canonical findings; evidence-only. Criteria tied to these actions
    # tend to reference evidence directly (e.g., verify.smoke expected_status).
    if action == "verify.smoke":
        if mode == MockMode.PASS:
            return ({"observed_status": 200}, ["http-status:200"], TaskStatus.COMPLETED)
        return ({"observed_status": 500}, ["http-status:500"], TaskStatus.COMPLETED)

    # Default evidence-only envelope for anything else.
    evidence = [f"mock-evidence://{action}/ok"]
    if mode == MockMode.FAIL:
        evidence = [f"mock-evidence://{action}/fail"]
    return (None, evidence, TaskStatus.COMPLETED)
