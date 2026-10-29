"""Companion link v1 cryptography (the firmware's docs/COMPANION_LINK.md)."""

import base64
import binascii
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text, length=None):
    """Strict standard base64; ValueError for anything else, or for the wrong length."""
    try:
        data = base64.b64decode(text, validate=True) if isinstance(text, str) else None
    except binascii.Error:
        data = None
    if data is None or (length is not None and len(data) != length):
        raise ValueError("invalid base64 field")
    return data


def new_key():
    return ec.generate_private_key(CURVE)


def load_key(scalar):
    return ec.derive_private_key(int.from_bytes(scalar, "big"), CURVE)


def scalar(key):
    return key.private_numbers().private_value.to_bytes(32, "big")


def public_point(key):
    """65-byte uncompressed P-256 point."""
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_point(raw):
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError("not an uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)


def sha256(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def hkdf(ikm, salt, info):
    return HKDF(hashes.SHA256(), 32, salt, info).derive(ikm)


def mac(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def commitment(companion_key):
    """What the first pair request carries instead of the key, so the key is fixed before the controller's is known."""
    return sha256(b"obbw-companion-commit-v1", companion_key)


def sas(companion_key, controller_key):
    """Six-digit verification code the user types in Admin → Companion."""
    value = int.from_bytes(sha256(b"obbw-companion-sas-v1", companion_key, controller_key)[:4], "big")
    return f"{value % 1000000:06d}"


def pairing_secret(key, companion_key, controller_key):
    shared = key.exchange(ec.ECDH(), load_point(controller_key))
    return hkdf(shared, sha256(companion_key, controller_key), b"obbw-companion-pair-v1")


def session_key(secret, companion_nonce, controller_nonce):
    return hkdf(secret, companion_nonce + controller_nonce, b"obbw-link-v1")


def credentials_key(secret):
    return hkdf(secret, b"", b"obbw-creds-v1")


def decrypt_credentials(secret, generation, iv, ciphertext):
    return AESGCM(credentials_key(secret)).decrypt(iv, ciphertext, f"obbw-creds|{generation}".encode())


def relay_key(secret, challenge, nonce):
    """Kr: the key of one relay session (the controller's challenge, the companion's nonce)."""
    return hkdf(secret, challenge + nonce, b"obbw-relay-v1")


def relay_body_key(key):
    """Kb: seals relayed bodies, headers and responses (relay protocol 2)."""
    return hkdf(key, b"", b"obbw-relay-body-v2")


def relay_nonce(direction, context, counter):
    """12 bytes: the direction, the context, two zeros, the counter little-endian."""
    return direction + bytes((context, 0, 0)) + counter.to_bytes(8, "little")


def relay_seal(body_key, context, counter, plaintext):
    """AES-256-GCM under Kb; the 16-byte tag rides with the bytes."""
    return AESGCM(body_key).encrypt(relay_nonce(b"c", context, counter), plaintext, None)


def relay_open(body_key, counter, sealed):
    """A sealed response (context 3, controller to companion)."""
    return AESGCM(body_key).decrypt(relay_nonce(b"f", 3, counter), sealed, None)


def relay_tag(key, method, uri, counter, address, screen, session):
    """The relayed request's MAC: 32 lowercase hex digits over the canonical string
    (relay protocol 2: the session field is the sealed value exactly as sent)."""
    canonical = f"obbw-relay-v2\n{method}\n{uri}\n{counter}\n{address}\n{screen}\n{session}\n"
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()[:32]
