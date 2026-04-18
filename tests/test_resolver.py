"""M3.3 — resolver tests."""

from __future__ import annotations

from dataclasses import dataclass

from aieos_pipeline_runner.models import LoadedSpec, SpecKind
from aieos_pipeline_runner.resolver import RegistryAPI, Resolver


@dataclass
class _Entry:
    adapter_id: str
    adapter_version: str


class _FakeRegistry:
    """In-memory registry double. action -> list of entries."""

    def __init__(self, table: dict[str, list[_Entry]] | None = None) -> None:
        self._table = dict(table or {})

    def find_adapters(self, action, context=None):  # noqa: D401
        return list(self._table.get(action, []))


def _ci_spec(
    *,
    actions: list[dict],
    adapter_preferences: dict[str, str] | None = None,
) -> LoadedSpec:
    content = {
        "spec_version": "1.0.0",
        "code_repo": "wtlinnertz/example",
        "actions": actions,
        "policies": {
            "timeout_seconds": 1800,
            "retry": {"max_retries": 0},
        },
    }
    if adapter_preferences is not None:
        content["policies"]["adapter_preferences"] = adapter_preferences
    return LoadedSpec(
        kind=SpecKind.CI,
        content=content,
        source_ref="inline://test",
        content_hash="0" * 64,
    )


def test_single_adapter_resolves():
    registry = _FakeRegistry({"test.unit": [_Entry("adapter-pytest-unit", "1.0.0")]})
    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {"min_coverage": 80}}])
    resolver = Resolver(registry=registry)

    plan = resolver.resolve(spec)

    assert len(plan.tasks) == 1
    assert plan.tasks[0].adapter_id == "adapter-pytest-unit"
    assert plan.tasks[0].adapter_version == "1.0.0"
    assert plan.tasks[0].criteria == {"min_coverage": 80}
    assert plan.unresolved == ()


def test_project_preference_overrides_org_default():
    registry = _FakeRegistry(
        {"test.unit": [_Entry("adapter-a", "1.0.0"), _Entry("adapter-b", "1.0.0")]}
    )
    spec = _ci_spec(
        actions=[{"action": "test.unit", "criteria": {}}],
        adapter_preferences={"test.unit": "adapter-b"},
    )
    resolver = Resolver(registry=registry, org_defaults={"test.unit": "adapter-a"})

    plan = resolver.resolve(spec)

    assert len(plan.tasks) == 1
    assert plan.tasks[0].adapter_id == "adapter-b"


def test_org_default_used_when_no_project_preference():
    registry = _FakeRegistry(
        {"test.unit": [_Entry("adapter-a", "1.0.0"), _Entry("adapter-b", "1.0.0")]}
    )
    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {}}])
    resolver = Resolver(registry=registry, org_defaults={"test.unit": "adapter-b"})

    plan = resolver.resolve(spec)

    assert plan.tasks[0].adapter_id == "adapter-b"


def test_no_adapter_returns_unresolved():
    registry = _FakeRegistry({})
    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {}}])
    resolver = Resolver(registry=registry)

    plan = resolver.resolve(spec)

    assert plan.tasks == ()
    assert len(plan.unresolved) == 1
    assert plan.unresolved[0].reason == "no_adapter"
    assert plan.unresolved[0].action == "test.unit"


def test_multiple_adapters_no_preference_returns_ambiguous():
    """Critical: when the hierarchy cannot narrow, do NOT pick by order."""
    registry = _FakeRegistry(
        {"test.unit": [_Entry("adapter-a", "1.0.0"), _Entry("adapter-b", "1.0.0")]}
    )
    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {}}])
    resolver = Resolver(registry=registry)  # no org_defaults

    plan = resolver.resolve(spec)

    assert plan.tasks == ()
    assert len(plan.unresolved) == 1
    assert plan.unresolved[0].reason == "ambiguous"
    assert set(plan.unresolved[0].candidates) == {"adapter-a@1.0.0", "adapter-b@1.0.0"}


def test_preferred_adapter_not_among_candidates_falls_to_ambiguity():
    """Preference points at an unregistered adapter; multiple candidates remain."""
    registry = _FakeRegistry(
        {"test.unit": [_Entry("adapter-a", "1.0.0"), _Entry("adapter-b", "1.0.0")]}
    )
    spec = _ci_spec(
        actions=[{"action": "test.unit", "criteria": {}}],
        adapter_preferences={"test.unit": "adapter-not-registered"},
    )
    resolver = Resolver(registry=registry)

    plan = resolver.resolve(spec)

    assert plan.tasks == ()
    assert plan.unresolved[0].reason == "ambiguous"


def test_bound_plan_preserves_dependency_dag():
    registry = _FakeRegistry(
        {
            "test.unit": [_Entry("adapter-pytest-unit", "1.0.0")],
            "build.artifact": [_Entry("adapter-buildah-image", "1.0.0")],
            "sign.artifact": [_Entry("adapter-cosign-sign", "1.0.0")],
        }
    )
    spec = _ci_spec(
        actions=[
            {"action": "test.unit", "criteria": {}},
            {"action": "build.artifact", "criteria": {}, "depends_on": ["test.unit"]},
            {
                "action": "sign.artifact",
                "criteria": {},
                "depends_on": ["build.artifact"],
            },
        ]
    )
    resolver = Resolver(registry=registry)

    plan = resolver.resolve(spec)

    assert [t.action for t in plan.tasks] == ["test.unit", "build.artifact", "sign.artifact"]
    assert plan.tasks[1].depends_on == ("test.unit",)
    assert plan.tasks[2].depends_on == ("build.artifact",)


def test_bound_plan_carries_spec_ref_and_hash():
    registry = _FakeRegistry({"test.unit": [_Entry("adapter-pytest-unit", "1.0.0")]})
    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {}}])
    resolver = Resolver(registry=registry)

    plan = resolver.resolve(spec)

    assert plan.spec_ref == "inline://test"
    assert plan.spec_hash == "0" * 64


def test_context_is_forwarded_to_registry_lookup():
    captured: dict = {}

    class _CapturingRegistry(RegistryAPI):
        def find_adapters(self, action, context=None):
            captured["action"] = action
            captured["context"] = dict(context) if context else None
            return [_Entry("adapter-x", "1.0.0")]

    spec = _ci_spec(actions=[{"action": "test.unit", "criteria": {}}])
    resolver = Resolver(registry=_CapturingRegistry(), context={"environment": "ci"})

    plan = resolver.resolve(spec)

    assert plan.tasks[0].adapter_id == "adapter-x"
    assert captured == {"action": "test.unit", "context": {"environment": "ci"}}
