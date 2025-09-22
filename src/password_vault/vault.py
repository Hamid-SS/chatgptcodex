"""Vault management logic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from .crypto import KDFConfig, build_cipher, decrypt, encrypt, generate_salt

VAULT_VERSION = 1
VERIFICATION_PLAINTEXT = b"password-vault"


class VaultError(Exception):
    """Base class for vault related errors."""


class VaultLockedError(VaultError):
    """Raised when the master password is incorrect."""


@dataclass
class Entry:
    """Plaintext representation of a vault entry."""

    name: str
    username: str
    password: str
    url: str | None = None
    notes: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Entry":
        created_at = (
            datetime.fromisoformat(data["created_at"]).astimezone(timezone.utc)
            if data.get("created_at")
            else None
        )
        updated_at = (
            datetime.fromisoformat(data["updated_at"]).astimezone(timezone.utc)
            if data.get("updated_at")
            else None
        )
        return cls(
            name=data["name"],
            username=data["username"],
            password=data["password"],
            url=data.get("url"),
            notes=data.get("notes"),
            created_at=created_at,
            updated_at=updated_at,
        )


class Vault:
    """Represents a password vault stored on disk."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    def initialize(self, master_password: str, *, overwrite: bool = False) -> None:
        """Create a new vault file."""

        if self.exists() and not overwrite:
            raise FileExistsError(f"Vault already exists: {self.path}")

        config = KDFConfig(salt=generate_salt())
        cipher = build_cipher(master_password, config)
        verification = encrypt(cipher, VERIFICATION_PLAINTEXT)

        data = {
            "version": VAULT_VERSION,
            "kdf": config.to_dict(),
            "verification": verification,
            "entries": {},
        }

        self._write(data)

    # ------------------------------------------------------------------
    # High level operations
    # ------------------------------------------------------------------
    def list_entries(self, master_password: str) -> list[str]:
        data, _ = self._load_and_unlock(master_password)
        return sorted(data.get("entries", {}).keys())

    def add_entry(
        self,
        master_password: str,
        name: str,
        username: str,
        password: str,
        *,
        url: str | None = None,
        notes: str | None = None,
        overwrite: bool = False,
    ) -> None:
        data, cipher = self._load_and_unlock(master_password)

        entries: dict[str, Any] = data.setdefault("entries", {})
        now = datetime.now(timezone.utc)

        if name in entries and not overwrite:
            raise VaultError(f"Entry '{name}' already exists")

        created_at = now
        existing = entries.get(name)
        if existing and existing.get("created_at"):
            created_at = datetime.fromisoformat(existing["created_at"])

        entry_data = Entry(
            name=name,
            username=username,
            password=password,
            url=url,
            notes=notes,
            created_at=created_at,
            updated_at=now,
        )

        payload = json.dumps(entry_data.to_dict()).encode("utf-8")
        encrypted = encrypt(cipher, payload)

        entries[name] = {
            "payload": encrypted,
            "created_at": created_at.isoformat(),
            "updated_at": now.isoformat(),
        }

        self._write(data)

    def get_entry(self, master_password: str, name: str) -> Entry:
        data, cipher = self._load_and_unlock(master_password)
        entries: dict[str, Any] = data.get("entries", {})
        if name not in entries:
            raise VaultError(f"Entry '{name}' not found")

        record = entries[name]
        payload = decrypt(cipher, record["payload"])
        entry_dict = json.loads(payload.decode("utf-8"))
        entry = Entry.from_dict(entry_dict)
        entry.created_at = (
            datetime.fromisoformat(record["created_at"]).astimezone(timezone.utc)
            if record.get("created_at")
            else None
        )
        entry.updated_at = (
            datetime.fromisoformat(record["updated_at"]).astimezone(timezone.utc)
            if record.get("updated_at")
            else None
        )
        return entry

    def remove_entry(self, master_password: str, name: str) -> None:
        data, _ = self._load_and_unlock(master_password)
        entries: dict[str, Any] = data.get("entries", {})
        if name not in entries:
            raise VaultError(f"Entry '{name}' not found")
        del entries[name]
        self._write(data)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _load_and_unlock(self, master_password: str) -> tuple[dict[str, Any], Fernet]:
        data = self._read()
        config = KDFConfig.from_dict(data["kdf"])
        cipher = build_cipher(master_password, config)
        try:
            decrypted = decrypt(cipher, data["verification"])
        except ValueError as exc:  # pragma: no cover - explicit error
            raise VaultLockedError("Incorrect master password") from exc
        if decrypted != VERIFICATION_PLAINTEXT:
            raise VaultError("Vault verification failed")
        return data, cipher

    def _read(self) -> dict[str, Any]:
        if not self.exists():
            raise FileNotFoundError(f"Vault not found: {self.path}")
        raw = self.path.read_text("utf-8")
        return json.loads(raw)

    def _write(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


__all__ = ["Vault", "VaultError", "VaultLockedError", "Entry"]
