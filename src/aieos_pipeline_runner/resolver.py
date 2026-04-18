"""Resolver — binds each spec action to a specific registered adapter.

Config hierarchy (first wins):
  1. Project-level preference: spec.policies.adapter_preferences[action]
  2. Organization default: resolver's org_defaults map
  3. Single-candidate auto-resolve: exactly one registered adapter satisfies
     the action in the requested context.

NO SILENT-PICK FALLBACK. If the hierarchy does not narrow to exactly one
candidate, the resolver records an UnresolvedAction — it does NOT pick by
registration order, alphabetical name, or any other heuristic. The plan
validator (M3.4) refuses to execute a plan with unresolved actions.

The runner never fetches registrations directly; it talks to the harness
via the RegistryAPI protocol. Tests inject a fake. Production wires to
aieos-agent-harness's CapabilityRegistry.
"""

from __future__ import annotations

from typing import Any, Protocol

import structlog

from .models import (
    BoundPlan,
    BoundTask,
    LoadedSpec,
    SpecKind,
    UnresolvedAction,
)

log = structlog.get_logger(__name__)


class RegistryEntryLike(Protocol):
    """Minimum shape the resolver needs from a registry entry."""

    @property
    def adapter_id(self) -> str: ...
    @property
    def adapter_version(self) -> str: ...


class RegistryAPI(Protocol):
    """Minimal registry interface the resolver depends on."""

    def find_adapters(
        self,
        action: str,
        context: dict[str, str] | None = None,
    ) -> list[RegistryEntryLike]: ...


def _all_action_instances(spec: LoadedSpec) -> list[dict[str, Any]]:
    if spec.kind == SpecKind.CI:
        return list(spec.content.get("actions", []))
    instances: list[dict[str, Any]] = []
    for env in spec.content.get("environments", []):
        instances.extend(env.get("actions", []))
    return instances


class Resolver:
    """Binds spec actions to registry adapters via a strict preference chain."""

    def __init__(
        self,
        registry: RegistryAPI,
        org_defaults: dict[str, str] | None = None,
        context: dict[str, str] | None = None,
    ) -> None:
        self._registry = registry
        self._org_defaults = dict(org_defaults or {})
        self._context = dict(context or {})

    def _resolve_one(
        self,
        action: str,
        spec_preferences: dict[str, str],
    ) -> tuple[RegistryEntryLike | None, UnresolvedAction | None]:
        """Return (entry, None) on success or (None, UnresolvedAction) on failure."""
        candidates = list(self._registry.find_adapters(action, context=self._context))
        if not candidates:
            return None, UnresolvedAction(action=action, reason="no_adapter", candidates=())

        preferred = spec_preferences.get(action) or self._org_defaults.get(action)
        if preferred:
            matches = [c for c in candidates if c.adapter_id == preferred]
            if len(matches) == 1:
                return matches[0], None
            if len(matches) > 1:
                # Preferred adapter has multiple versions — still ambiguous unless
                # the caller's preference encodes a version.
                return None, UnresolvedAction(
                    action=action,
                    reason="ambiguous",
                    candidates=tuple(f"{c.adapter_id}@{c.adapter_version}" for c in matches),
                )
            # preferred adapter is not among registered candidates — fall through
            # but do NOT auto-pick; record ambiguity if multiple remain.

        if len(candidates) == 1:
            return candidates[0], None
        return None, UnresolvedAction(
            action=action,
            reason="ambiguous",
            candidates=tuple(f"{c.adapter_id}@{c.adapter_version}" for c in candidates),
        )

    def resolve(self, spec: LoadedSpec) -> BoundPlan:
        spec_prefs = (
            spec.content.get("policies", {}).get("adapter_preferences", {}) if spec.content else {}
        )

        tasks: list[BoundTask] = []
        unresolved: list[UnresolvedAction] = []

        for inst in _all_action_instances(spec):
            action = inst["action"]
            entry, missing = self._resolve_one(action, spec_prefs)
            if missing is not None or entry is None:
                unresolved.append(
                    missing or UnresolvedAction(action=action, reason="no_adapter", candidates=())
                )
                log.info(
                    "action_unresolved",
                    action=action,
                    reason=(missing.reason if missing else "no_adapter"),
                )
                continue
            tasks.append(
                BoundTask(
                    action=action,
                    adapter_id=entry.adapter_id,
                    adapter_version=entry.adapter_version,
                    criteria=dict(inst.get("criteria", {})),
                    inputs=dict(inst.get("config", {})),
                    depends_on=tuple(inst.get("depends_on", [])),
                )
            )

        return BoundPlan(
            spec_ref=spec.source_ref,
            spec_hash=spec.content_hash,
            tasks=tuple(tasks),
            unresolved=tuple(unresolved),
        )
