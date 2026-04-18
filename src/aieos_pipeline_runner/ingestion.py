"""Spec ingestion: load a frozen CI or CD spec from a file or artifact store.

Immutability is the invariant — the runner refuses to execute against an
unfrozen spec. Two load paths:

- file path + expected_hash: the caller asserts a sha256 hash. Mismatch
  raises SpecIntegrityError; absent hash raises SpecNotFrozenError.
- artifact-store key: content-addressed by convention. The key encodes the
  hash; the returned LoadedSpec records both.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .artifact_store import ArtifactStore
from .models import LoadedSpec, SpecKind

PACKAGE_ROOT = Path(__file__).parent
CI_SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "ci-spec.schema.json"
CD_SCHEMA_PATH = PACKAGE_ROOT / "schemas" / "cd-spec.schema.json"


class SpecNotFrozenError(Exception):
    """The caller tried to load a spec without asserting a content hash."""


class SpecIntegrityError(Exception):
    """The loaded spec's sha256 did not match the expected hash."""


class SpecSchemaError(Exception):
    """The loaded spec failed schema validation."""

    def __init__(self, message: str, errors: list[str]) -> None:
        super().__init__(message)
        self.errors = errors


class SpecKindError(Exception):
    """The loader could not determine whether the spec is CI or CD."""


def _sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _detect_kind(content: dict[str, Any]) -> SpecKind:
    """Distinguish CI from CD by top-level keys. Raises on ambiguity."""
    is_cd = "artifact_ref" in content and "environments" in content
    is_ci = "code_repo" in content and "actions" in content
    if is_cd and not is_ci:
        return SpecKind.CD
    if is_ci and not is_cd:
        return SpecKind.CI
    raise SpecKindError(
        "cannot determine spec kind — expected either "
        "{code_repo, actions} (CI) or {artifact_ref, environments} (CD). "
        f"Observed top-level keys: {sorted(content.keys())}"
    )


def _validate_against_schema(content: dict[str, Any], kind: SpecKind) -> None:
    schema_path = CI_SCHEMA_PATH if kind == SpecKind.CI else CD_SCHEMA_PATH
    schema = json.loads(schema_path.read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(content), key=lambda e: list(e.path))
    if errors:
        formatted = [
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors[:10]
        ]
        raise SpecSchemaError(
            f"{kind.value} spec failed schema validation: {formatted[0]}",
            formatted,
        )


def load_spec_from_file(path: Path, expected_hash: str | None = None) -> LoadedSpec:
    """Load a spec from a local file path.

    expected_hash must be the sha256 hex digest of the raw file bytes. A
    missing expected_hash raises SpecNotFrozenError — the runner refuses
    to execute against specs the caller has not vouched for.
    """
    raw = Path(path).read_bytes()
    actual = _sha256_hex(raw)
    if expected_hash is None:
        raise SpecNotFrozenError(
            f"refusing to load unfrozen spec at {path}; supply expected_hash "
            f"(computed sha256: {actual}) to assert immutability"
        )
    if actual != expected_hash:
        raise SpecIntegrityError(
            f"spec at {path} has hash {actual}; caller expected {expected_hash}"
        )

    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise SpecSchemaError("spec root must be a mapping", [f"<root>: got {type(data).__name__}"])
    kind = _detect_kind(data)
    _validate_against_schema(data, kind)
    return LoadedSpec(
        kind=kind,
        content=data,
        source_ref=f"file://{Path(path).resolve()}",
        content_hash=actual,
    )


def load_spec_from_artifact_store(store: ArtifactStore, key: str) -> LoadedSpec:
    """Load a spec from the artifact store by key.

    Artifact-store entries are treated as content-addressed. The key's
    stability is the store's responsibility; the ingester records both
    the key (as source_ref) and the computed content hash.
    """
    raw = store.get(key)
    if raw is None:
        raise SpecNotFrozenError(f"no spec found in artifact store at {key!r}")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise SpecSchemaError("spec root must be a mapping", [f"<root>: got {type(data).__name__}"])
    kind = _detect_kind(data)
    _validate_against_schema(data, kind)
    return LoadedSpec(
        kind=kind,
        content=data,
        source_ref=f"artifact-store://{key}",
        content_hash=_sha256_hex(raw),
    )
