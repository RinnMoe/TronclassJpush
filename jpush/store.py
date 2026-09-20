"""Credential persistence implementations."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol

from .models import Credentials


class Store(Protocol):
    def load(self) -> Credentials | None: ...

    def save(self, credentials: Credentials) -> None: ...


class FileStore:
    """Persist credentials as a restrictive JSON file."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def load(self) -> Credentials | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        if not isinstance(data, dict):
            raise TypeError("credential file must contain a JSON object")
        return Credentials.from_dict(data)

    def save(self, credentials: Credentials) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(credentials.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        try:
            self.path.chmod(0o600)
        except OSError:
            # Windows ACLs do not map cleanly to POSIX mode bits; the file is
            # still written successfully and inherits the directory ACL.
            pass

    Load = load
    Save = save


class MemoryStore:
    """Small in-memory store useful for tests and short-lived applications."""

    def __init__(self, credentials: Credentials | None = None) -> None:
        self.credentials = credentials

    def load(self) -> Credentials | None:
        return self.credentials

    def save(self, credentials: Credentials) -> None:
        self.credentials = credentials

    Load = load
    Save = save
