"""
Encryption service for sensitive data like SSO credentials.
Uses Fernet symmetric encryption with keys from configuration.
"""

import base64
import logging

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings

logger = logging.getLogger(__name__)

# Static salt for deterministic key derivation from SECRET_KEY.
_DERIVATION_SALT = b"panther_dashboard_sso_v1"

# Cache of built Fernet instances keyed by the material they were built from,
# so a settings change during a test/reload is picked up but PBKDF2 (100k
# iterations) does not run on every encrypt/decrypt call.
_fernet_cache: dict[tuple[str, str], Fernet] = {}

# Emit the "derived from SECRET_KEY" warning once per key, not per call.
_warned_derivations: set[str] = set()


class EncryptionKeyError(RuntimeError):
    """ENCRYPTION_KEY is set but is not a usable Fernet key.

    This is deliberately fatal. The previous behaviour was
    ``except Exception: pass`` followed by a silent fallback to a key derived
    from SECRET_KEY: a single typo in ENCRYPTION_KEY then encrypted every SSO
    and connector credential under a completely different key, with no signal
    at all, and rotating SECRET_KEY afterwards made them permanently
    undecryptable. Failing loudly is the only safe option.
    """


def _derive_key_from_secret() -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_DERIVATION_SALT,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(settings.secret_key.encode()))


def _build_fernet(encryption_key: str) -> Fernet:
    if encryption_key:
        # A configured key must be a valid Fernet key. No fallback.
        try:
            return Fernet(encryption_key.encode())
        except Exception as exc:
            raise EncryptionKeyError(
                "ENCRYPTION_KEY is set but is not a valid Fernet key "
                "(expected 32 url-safe base64-encoded bytes, i.e. a 44-character "
                "string ending in '='). Generate one with "
                '`python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"`. Refusing to fall back to a '
                "key derived from SECRET_KEY, which would silently encrypt "
                "credentials under the wrong key."
            ) from exc

    # Genuinely unset: keep the legacy derive-from-SECRET_KEY behaviour so
    # existing deployments that never set ENCRYPTION_KEY keep working, but say
    # so loudly -- rotating SECRET_KEY will make stored credentials
    # undecryptable.
    if settings.secret_key not in _warned_derivations:
        _warned_derivations.add(settings.secret_key)
        logger.warning(
            "ENCRYPTION_KEY is not set; deriving the Fernet key from SECRET_KEY. "
            "Stored SSO/connector credentials will become undecryptable if "
            "SECRET_KEY is ever rotated. Set ENCRYPTION_KEY to a dedicated "
            "Fernet key (see generate_fernet_key())."
        )
    return Fernet(_derive_key_from_secret())


def _get_fernet() -> Fernet:
    """
    Get a Fernet instance using the configured encryption key.

    Raises EncryptionKeyError if ENCRYPTION_KEY is set but malformed. Falls back
    to a key derived from SECRET_KEY only when ENCRYPTION_KEY is unset.
    """
    encryption_key = (settings.encryption_key or "").strip()
    cache_key = (encryption_key, settings.secret_key)

    cached = _fernet_cache.get(cache_key)
    if cached is not None:
        return cached

    fernet = _build_fernet(encryption_key)
    _fernet_cache[cache_key] = fernet
    return fernet


def validate_encryption_config() -> None:
    """Fail fast on a malformed ENCRYPTION_KEY.

    Safe to call at startup: it builds (and caches) the Fernet instance so a
    bad key surfaces as a startup error rather than a runtime 500 the first
    time somebody saves an SSO configuration.
    """
    _get_fernet()


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
