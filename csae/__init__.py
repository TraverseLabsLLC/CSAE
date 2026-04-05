"""CSAE: Context State Attestation Envelope (Layer 0).

Verifiable context transfer between AI agents across trust boundaries.

    from csae import create_attestation, verify_attestation, generate_keypair

MCP middleware (drop-in attestation for MCP tool calls):

    from csae.middleware import MCPAttestor

Audit logging (tamper-evident log with regulatory context):

    from csae.audit import AuditLog, Regulation

Advanced features (full envelope with six-component integrity sealing,
transformation propagation history, authority attenuation, and degradation
policies) are available under commercial license from Traverse Labs LLC.
See https://traverselabs.ai for details.
"""

__version__ = "0.2.0"

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
