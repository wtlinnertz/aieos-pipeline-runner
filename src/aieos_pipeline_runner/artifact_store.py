"""Minimal artifact-store abstraction for the pipeline runner.

The runner only reads — specs, cached frozen artifacts, run records. Writes
happen via the run validator publishing run records (implemented in M3.6)
or via out-of-band ingest. Same key-value shape as aieos-agent-harness so
the two components can share a backend.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class ArtifactStore(Protocol):
    def put(self, key: str, content: bytes) -> None: ...
    def get(self, key: str) -> bytes | None: ...
    def list(self, prefix: str) -> list[str]: ...


class FilesystemArtifactStore:
    """Filesystem-backed ArtifactStore for tests and local dev."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        if key.startswith("/") or ".." in key.split("/"):
            raise ValueError(f"invalid key: {key!r}")
        return self._root / key

    def put(self, key: str, content: bytes) -> None:
        path = self._path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def get(self, key: str) -> bytes | None:
        path = self._path_for(key)
        return path.read_bytes() if path.is_file() else None

    def list(self, prefix: str) -> list[str]:
        base = self._root / prefix
        if not base.exists():
            return []
        if base.is_file():
            return [prefix]
        keys: list[str] = []
        for p in base.rglob("*"):
            if p.is_file():
                keys.append(p.relative_to(self._root).as_posix())
        return sorted(keys)
