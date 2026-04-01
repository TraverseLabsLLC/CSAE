"""CSAE: Context State Attestation Envelope (Layer 0).

Verifiable context transfer between AI agents across trust boundaries.

This open-source library provides the Layer 0 attestation primitive:
signed, hash-chained, verifiable context transfer with provenance tracking.

    from csae import create_attestation, verify_attestation, generate_keypair

Advanced features (full envelope with six-component integrity sealing,
transformation propagation history, authority attenuation, and degradation
policies) are available under commercial license from Traverse Labs LLC.
See https://traverselabs.ai for details.
"""

__version__ = "0.1.0"

# Crypto
from .crypto import generate_keypair, export_public_key, import_public_key

# Types
from .types import (
    AgentIdentity,
    SourceType,
    TransformationType,
    ContentType,
    Permission,
    UncertaintyType,
)

# Layer 0: Attestation Primitive
from .attestation import (
    Attestation,
    create_attestation,
    verify_attestation,
)

# Layer 1: Provenance Chains
from .provenance import ProvenanceChain, ProvenanceNode

__all__ = [
    # Crypto
    "generate_keypair",
    "export_public_key",
    "import_public_key",
    # Types
    "AgentIdentity",
    "SourceType",
    "TransformationType",
    "ContentType",
    "Permission",
    "UncertaintyType",
    # Layer 0
    "Attestation",
    "create_attestation",
    "verify_attestation",
    # Layer 1
    "ProvenanceChain",
    "ProvenanceNode",
]
