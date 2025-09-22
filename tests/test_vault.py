from __future__ import annotations

import json
from pathlib import Path

import pytest

from password_vault.vault import Entry, Vault, VaultError, VaultLockedError


@pytest.fixture()
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "vault.json"


@pytest.fixture()
def vault(vault_path: Path) -> Vault:
    v = Vault(vault_path)
    v.initialize("master-password")
    return v


def test_initialize_creates_vault_file(vault_path: Path) -> None:
    vault = Vault(vault_path)
    vault.initialize("secret")
    assert vault.exists()

    with vault_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["version"] == 1
    assert data["entries"] == {}


def test_list_returns_entry_names(vault: Vault) -> None:
    assert vault.list_entries("master-password") == []
    vault.add_entry("master-password", "email", username="user", password="pwd")
    vault.add_entry("master-password", "bank", username="banker", password="secure")
    assert vault.list_entries("master-password") == ["bank", "email"]


def test_add_and_get_entry(vault: Vault) -> None:
    vault.add_entry(
        "master-password",
        "github",
        username="octocat",
        password="token",
        url="https://github.com",
        notes="2FA enabled",
    )
    entry = vault.get_entry("master-password", "github")
    assert isinstance(entry, Entry)
    assert entry.name == "github"
    assert entry.username == "octocat"
    assert entry.password == "token"
    assert entry.url == "https://github.com"
    assert entry.notes == "2FA enabled"
    assert entry.created_at is not None
    assert entry.updated_at is not None


def test_add_requires_overwrite(vault: Vault) -> None:
    vault.add_entry("master-password", "email", username="user", password="pwd")
    with pytest.raises(VaultError):
        vault.add_entry("master-password", "email", username="user", password="pwd")

    vault.add_entry(
        "master-password",
        "email",
        username="user",
        password="new",
        overwrite=True,
    )
    entry = vault.get_entry("master-password", "email")
    assert entry.password == "new"


def test_remove_entry(vault: Vault) -> None:
    vault.add_entry("master-password", "email", username="user", password="pwd")
    vault.remove_entry("master-password", "email")
    assert vault.list_entries("master-password") == []
    with pytest.raises(VaultError):
        vault.get_entry("master-password", "email")


def test_incorrect_master_password(vault: Vault) -> None:
    with pytest.raises(VaultLockedError):
        vault.list_entries("wrong")

    vault.add_entry("master-password", "email", username="user", password="pwd")
    with pytest.raises(VaultLockedError):
        vault.get_entry("wrong", "email")
