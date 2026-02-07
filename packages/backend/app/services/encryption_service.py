"""
Encryption service for sensitive data like SSO credentials.
Uses Fernet symmetric encryption with keys from configuration.
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings


def _get_fernet() -> Fernet:
    """
    Get a Fernet instance using the configured encryption key.
    If no key is configured, generates one from the secret_key.
    """
    encryption_key = settings.encryption_key

    if encryption_key:
        # Use the configured Fernet key directly
        try:
            return Fernet(encryption_key.encode())
        except Exception:
            # If the key isn't a valid Fernet key, derive one from it
            pass

    # Derive a Fernet key from the secret_key using PBKDF2
    # This ensures we always have a valid encryption key
    salt = b"panther_dashboard_sso_v1"  # Static salt for deterministic key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(settings.secret_key.encode()))
    return Fernet(key)


def encrypt_credential(plaintext: str) -> bytes:
    """
    Encrypt a credential (like client_secret) for storage.

    Args:
        plaintext: The secret to encrypt

    Returns:
        Encrypted bytes that can be stored in the database
    """
    fernet = _get_fernet()
    return fernet.encrypt(plaintext.encode())


def decrypt_credential(ciphertext: bytes) -> str:
    """
    Decrypt a stored credential.

    Args:
        ciphertext: The encrypted bytes from the database

    Returns:
        The decrypted plaintext string
    """
    fernet = _get_fernet()
    return fernet.decrypt(ciphertext).decode()


def generate_fernet_key() -> str:
    """
    Generate a new Fernet encryption key.
    Use this to generate a key for the ENCRYPTION_KEY environment variable.

    Returns:
        A base64-encoded Fernet key string
    """
    return Fernet.generate_key().decode()
