"""M3.1 — spec ingestion tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aieos_pipeline_runner.artifact_store import FilesystemArtifactStore
from aieos_pipeline_runner.ingestion import (
    SpecIntegrityError,
    SpecKindError,
    SpecNotFrozenError,
    SpecSchemaError,
    load_spec_from_artifact_store,
    load_spec_from_file,
)
from aieos_pipeline_runner.models import SpecKind


def test_load_spec_from_file(ci_spec_file):
    path, expected = ci_spec_file

    loaded = load_spec_from_file(path, expected_hash=expected)

    assert loaded.kind == SpecKind.CI
    assert loaded.content_hash == expected
    assert loaded.source_ref.startswith("file://")
    assert loaded.content["spec_version"] == "1.0.0"


def test_load_cd_spec_from_file(cd_spec_file):
    path, expected = cd_spec_file

    loaded = load_spec_from_file(path, expected_hash=expected)

    assert loaded.kind == SpecKind.CD
    assert loaded.content_hash == expected


def test_load_spec_from_artifact_store(tmp_path: Path, ci_spec_yaml):
    store = FilesystemArtifactStore(tmp_path / "store")
    key = "specs/artifact-store/ci.spec.yaml"
    store.put(key, ci_spec_yaml.encode("utf-8"))

    loaded = load_spec_from_artifact_store(store, key)

    assert loaded.kind == SpecKind.CI
    assert loaded.source_ref == f"artifact-store://{key}"
    assert loaded.content_hash == hashlib.sha256(ci_spec_yaml.encode()).hexdigest()


def test_reject_unfrozen_spec(ci_spec_file):
    """Loading without expected_hash refuses — the runner requires assertion."""
    path, _ = ci_spec_file

    with pytest.raises(SpecNotFrozenError):
        load_spec_from_file(path)


def test_load_raises_on_hash_mismatch(ci_spec_file):
    path, _ = ci_spec_file

    with pytest.raises(SpecIntegrityError):
        load_spec_from_file(path, expected_hash="0" * 64)


def test_validate_spec_against_schema_pass(ci_spec_file):
    path, expected = ci_spec_file

    # No exception -> schema validation passed.
    loaded = load_spec_from_file(path, expected_hash=expected)
    assert loaded is not None


def test_validate_spec_against_schema_fail(tmp_path: Path):
    bad = (
        'spec_version: "not-semver"\n'
        'code_repo: "wtlinnertz/x"\n'
        "actions: []\n"  # violates minItems: 1
        "policies:\n"
        "  timeout_seconds: 1800\n"
        "  retry:\n"
        "    max_retries: 0\n"
    )
    path = tmp_path / "bad.spec.yaml"
    path.write_text(bad)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(SpecSchemaError) as exc_info:
        load_spec_from_file(path, expected_hash=expected)

    assert len(exc_info.value.errors) >= 1


def test_unknown_spec_kind_rejected(tmp_path: Path):
    """A document that matches neither CI nor CD shape raises."""
    bad = "hello: world\n"
    path = tmp_path / "mystery.yaml"
    path.write_text(bad)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()

    with pytest.raises(SpecKindError):
        load_spec_from_file(path, expected_hash=expected)


def test_artifact_store_key_not_found(tmp_path: Path):
    store = FilesystemArtifactStore(tmp_path / "store")

    with pytest.raises(SpecNotFrozenError):
        load_spec_from_artifact_store(store, "missing-key")
