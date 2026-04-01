"""Cryptographic primitives for CSAE: hashing, signing, verification."""

import hashlib
import json
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDSA,
    SECP256R1,
)
from cryptography.exceptions import InvalidSignature


def content_hash(data: str) -> str:
    """Compute SHA-256 hash of content. Returns hex string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical_json(obj: dict) -> str:
    """Produce deterministic JSON for hashing. Keys sorted, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(obj: dict) -> str:
    """Hash a dict by converting to canonical JSON first."""
    return content_hash(canonical_json(obj))


def chain_hash(current_hash: str, previous_hash: Optional[str]) -> str:
    """Compute a chain hash linking current content to previous."""
    combined = f"{previous_hash or 'null'}:{current_hash}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def generate_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDSA P-256 key pair for signing attestations."""
    private_key = ec.generate_private_key(SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: EllipticCurvePrivateKey, data: str) -> str:
    """Sign data with ECDSA P-256. Returns hex-encoded signature."""
    signature = private_key.sign(
        data.encode("utf-8"),
        ECDSA(hashes.SHA256()),
    )
    return signature.hex()


def verify(public_key: EllipticCurvePublicKey, data: str, signature_hex: str) -> bool:
    """Verify an ECDSA P-256 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            data.encode("utf-8"),
            ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def export_public_key(public_key: EllipticCurvePublicKey) -> str:
    """Export public key as PEM string."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def import_public_key(pem: str) -> EllipticCurvePublicKey:
    """Import public key from PEM string."""
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def export_private_key(private_key: EllipticCurvePrivateKey) -> str:
    """Export private key as PEM string (no encryption)."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def import_private_key(pem: str) -> EllipticCurvePrivateKey:
    """Import private key from PEM string."""
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
