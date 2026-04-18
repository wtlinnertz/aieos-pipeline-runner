"""Shared test fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


@pytest.fixture
def ci_spec_yaml() -> str:
    """A minimal valid CI spec (modeled on the artifact-store example)."""
    return """\
spec_version: "1.0.0"
code_repo: "wtlinnertz/aieos-artifact-store"

actions:
  - action: test.unit
    criteria:
      min_coverage: 80
  - action: build.artifact
    criteria:
      artifact_type: oci-image
    depends_on:
      - test.unit

policies:
  timeout_seconds: 1800
  retry:
    max_retries: 1
    backoff: exponential
"""


@pytest.fixture
def cd_spec_yaml() -> str:
    """A minimal valid CD spec."""
    return """\
spec_version: "1.0.0"
artifact_ref: "ghcr.io/wtlinnertz/aieos-artifact-store@sha256:dead"

environments:
  - name: dev
    lifetime: persistent
    actions:
      - action: deploy.environment
        criteria:
          reconciled_within_seconds: 300

promotions: []

rollback_conditions:
  trigger_on:
    - verify.smoke FAIL

policies:
  timeout_seconds: 3600
  retry:
    max_retries: 0
    backoff: none
"""


@pytest.fixture
def ci_spec_file(tmp_path: Path, ci_spec_yaml: str) -> tuple[Path, str]:
    """Returns (path, expected_sha256_hex)."""
    p = tmp_path / "ci.spec.yaml"
    p.write_text(ci_spec_yaml)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture
def cd_spec_file(tmp_path: Path, cd_spec_yaml: str) -> tuple[Path, str]:
    p = tmp_path / "cd.spec.yaml"
    p.write_text(cd_spec_yaml)
    return p, hashlib.sha256(p.read_bytes()).hexdigest()
