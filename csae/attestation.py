"""Layer 0: Attestation Primitive.

The irreducible core of verifiable agent context transfer.
Three fields: content, provenance hash, cryptographic attestation.

Any agent can produce it. Any agent can verify it. Transport-agnostic.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid
import json

from .crypto import content_hash, canonical_json, chain_hash, sign, verify
from .types import AgentIdentity

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)


class Attestation(BaseModel):
    """The attestation primitive: content + provenance hash + signature.

    This is the simplest possible unit of verifiable context transfer.
    """
    model_config = {"arbitrary_types_allowed": True}

    attestation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: Dict[str, Any]
    content_hash: str = ""
    provenance_hash: str = ""
    previous_attestation_hash: Optional[str] = None
    chain_hash: str = ""
    signer_agent: AgentIdentity
    signature: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def _signable_payload(self) -> str:
        """The canonical string that gets signed."""
        payload = {
            "attestation_id": self.attestation_id,
            "content_hash": self.content_hash,
            "provenance_hash": self.provenance_hash,
            "chain_hash": self.chain_hash,
            "signer_agent": self.signer_agent.agent_id,
            "created_at": self.created_at.isoformat(),
        }
        return canonical_json(payload)

    def to_dict(self) -> dict:
        """Serialize to a transport-ready dict."""
        return {
            "attestation_id": self.attestation_id,
            "content": self.content,
            "content_hash": self.content_hash,
            "provenance_hash": self.provenance_hash,
            "previous_attestation_hash": self.previous_attestation_hash,
            "chain_hash": self.chain_hash,
            "signer_agent": self.signer_agent.to_dict(),
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


def create_attestation(
    content: Dict[str, Any],
    provenance_hash: str,
    signer_agent: AgentIdentity,
    private_key: EllipticCurvePrivateKey,
    previous_attestation_hash: Optional[str] = None,
) -> Attestation:
    """Create a signed attestation primitive.

    Args:
        content: The context payload (any structured data).
        provenance_hash: Hash of the provenance chain for this content.
        signer_agent: Identity of the signing agent.
        private_key: Agent's ECDSA private key.
        previous_attestation_hash: Hash of the prior attestation in the chain
            (None for first attestation).

    Returns:
        A signed Attestation object.
    """
    c_hash = content_hash(canonical_json(content))
    ch = chain_hash(c_hash, previous_attestation_hash)

    attestation = Attestation(
        content=content,
        content_hash=c_hash,
        provenance_hash=provenance_hash,
        previous_attestation_hash=previous_attestation_hash,
        chain_hash=ch,
        signer_agent=signer_agent,
    )

    attestation.signature = sign(private_key, attestation._signable_payload())
    return attestation


def verify_attestation(
    attestation: Attestation,
    public_key: EllipticCurvePublicKey,
) -> bool:
    """Verify an attestation's integrity and signature.

    Checks:
        1. Content hash matches actual content.
        2. Chain hash is correctly computed.
        3. Signature is valid.

    Returns:
        True if all checks pass, False otherwise.
    """
    # Verify content hash
    expected_content_hash = content_hash(canonical_json(attestation.content))
    if expected_content_hash != attestation.content_hash:
        return False

    # Verify chain hash
    expected_chain_hash = chain_hash(
        attestation.content_hash,
        attestation.previous_attestation_hash,
    )
    if expected_chain_hash != attestation.chain_hash:
        return False

    # Verify signature
    return verify(public_key, attestation._signable_payload(), attestation.signature)
