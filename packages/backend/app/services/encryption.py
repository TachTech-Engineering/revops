"""
Credential Encryption Service

Provides secure encryption/decryption of connector credentials using Fernet symmetric encryption.
Generates encryption keys and manages secure storage of sensitive configuration data.
"""

import json
import base64
import secrets
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


class CredentialEncryption:
    """
    Handles encryption and decryption of sensitive connector credentials.
    Uses Fernet symmetric encryption (AES-128-CBC with HMAC).
    """

    def __init__(self, key: str | None = None):
        """
        Initialize encryption service with a Fernet key.

        Args:
            key: Base64-encoded Fernet key. If None, uses key from settings.
                 If settings key is empty, generates a new key (dev mode only).
        """
        encryption_key = key or settings.encryption_key

        if not encryption_key:
            # In development, generate a key if none provided
            # In production, this should be set via environment variable
            encryption_key = Fernet.generate_key().decode()

        try:
            self.fernet = Fernet(encryption_key.encode())
        except Exception as e:
            raise EncryptionError(f"Invalid encryption key: {e}")

    def encrypt(self, data: dict[str, Any]) -> bytes:
        """
        Encrypt a dictionary of credentials.

        Args:
            data: Dictionary containing sensitive credentials

        Returns:
            Encrypted bytes suitable for database storage

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            json_data = json.dumps(data, default=str)
            encrypted = self.fernet.encrypt(json_data.encode())
            return encrypted
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt credentials: {e}")

    def decrypt(self, encrypted: bytes) -> dict[str, Any]:
        """
        Decrypt encrypted credentials back to a dictionary.

        Args:
            encrypted: Encrypted bytes from database

        Returns:
            Dictionary containing decrypted credentials

        Raises:
            EncryptionError: If decryption fails (wrong key, corrupted data, etc.)
        """
        try:
            decrypted = self.fernet.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except InvalidToken:
            raise EncryptionError("Invalid encryption key or corrupted data")
        except json.JSONDecodeError:
            raise EncryptionError("Decrypted data is not valid JSON")
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt credentials: {e}")

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key.

        Returns:
            Base64-encoded Fernet key suitable for ENCRYPTION_KEY env var
        """
        return Fernet.generate_key().decode()

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes | None = None) -> tuple[str, bytes]:
        """
        Derive a Fernet key from a password using PBKDF2.
        Useful for scenarios where a master password is preferred over a random key.

        Args:
            password: Password to derive key from
            salt: Optional salt bytes. If None, generates a new salt.

        Returns:
            Tuple of (base64-encoded Fernet key, salt bytes)
        """
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), salt


# Singleton instance for use throughout the application
_encryption_service: CredentialEncryption | None = None


def get_encryption_service() -> CredentialEncryption:
    """
    Get the singleton encryption service instance.

    Returns:
        CredentialEncryption instance
    """
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = CredentialEncryption()
    return _encryption_service
