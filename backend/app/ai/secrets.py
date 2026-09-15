"""Encryption of provider API keys at rest (AES-256-GCM, key derived from AEGIS_SECRET_KEY with HKDF-SHA256).

The provider ID is bound as associated data, so a ciphertext cannot be moved to another provider row.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PREFIX = "v1:"


class SecretError(ValueError):
    """Raised when a stored key cannot be decrypted. Messages never contain key material."""


class SecretBox:
    def __init__(self, secret_key: str) -> None:
        if len(secret_key) < 32:
            raise SecretError("AEGIS_SECRET_KEY must contain at least 32 characters")
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"aegis-llm-provider-keys",
            info=b"aegis-llm-key-v1",
        ).derive(secret_key.encode("utf-8"))

    def __repr__(self) -> str:
        return "SecretBox(<redacted>)"

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, token: str, context: str) -> str:
        if not token.startswith(_PREFIX):
            raise SecretError("Stored key has an unknown format")
        try:
            raw = base64.urlsafe_b64decode(token[len(_PREFIX) :].encode("ascii"))
            plaintext = AESGCM(self._key).decrypt(raw[:12], raw[12:], context.encode("utf-8"))
        except (InvalidTag, ValueError):
            raise SecretError(
                "Stored API key could not be decrypted (AEGIS_SECRET_KEY changed or data was altered); re-enter the key"
            ) from None
        return plaintext.decode("utf-8")


def key_hint(value: str) -> str:
    return f"…{value[-4:]}" if len(value) >= 12 else "set"
