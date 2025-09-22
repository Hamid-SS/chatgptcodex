"""Utilities for key derivation and encryption."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

DEFAULT_SCRYPT_N: Final[int] = 2**14
DEFAULT_SCRYPT_R: Final[int] = 8
DEFAULT_SCRYPT_P: Final[int] = 1
KEY_LENGTH: Final[int] = 32
SALT_LENGTH: Final[int] = 16


@dataclass(frozen=True)
class KDFConfig:
    """Configuration used to derive encryption keys."""

    salt: bytes
    n: int = DEFAULT_SCRYPT_N
    r: int = DEFAULT_SCRYPT_R
    p: int = DEFAULT_SCRYPT_P

    def to_dict(self) -> dict[str, int | str]:
        return {
            "name": "scrypt",
            "salt": base64.urlsafe_b64encode(self.salt).decode("ascii"),
            "n": self.n,
            "r": self.r,
            "p": self.p,
        }

    @classmethod
    def from_dict(cls, data: dict[str, int | str]) -> "KDFConfig":
        if data.get("name") != "scrypt":
            raise ValueError("Unsupported KDF")
        salt_b64 = data.get("salt")
        if not isinstance(salt_b64, str):
            raise ValueError("Invalid salt in config")
        return cls(
            salt=base64.urlsafe_b64decode(salt_b64.encode("ascii")),
            n=int(data.get("n", DEFAULT_SCRYPT_N)),
            r=int(data.get("r", DEFAULT_SCRYPT_R)),
            p=int(data.get("p", DEFAULT_SCRYPT_P)),
        )


def generate_salt() -> bytes:
    """Generate a random salt."""

    return secrets.token_bytes(SALT_LENGTH)


def derive_key(password: str, config: KDFConfig) -> bytes:
    """Derive an encryption key from the provided password and configuration."""

    raw_key = hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=config.salt,
        n=config.n,
        r=config.r,
        p=config.p,
        dklen=KEY_LENGTH,
    )
    return base64.urlsafe_b64encode(raw_key)


def build_cipher(password: str, config: KDFConfig) -> Fernet:
    """Create a Fernet cipher for the given password and configuration."""

    key = derive_key(password, config)
    return Fernet(key)


def encrypt(fernet: Fernet, data: bytes) -> str:
    """Encrypt bytes and return a base64 encoded string."""

    token = fernet.encrypt(data)
    return token.decode("ascii")


def decrypt(fernet: Fernet, token: str) -> bytes:
    """Decrypt a base64 encoded string."""

    try:
        return fernet.decrypt(token.encode("ascii"))
    except InvalidToken as exc:  # pragma: no cover - re-raised for clarity
        raise ValueError("Invalid encryption token") from exc


__all__ = [
    "KDFConfig",
    "DEFAULT_SCRYPT_N",
    "DEFAULT_SCRYPT_R",
    "DEFAULT_SCRYPT_P",
    "generate_salt",
    "derive_key",
    "build_cipher",
    "encrypt",
    "decrypt",
]
