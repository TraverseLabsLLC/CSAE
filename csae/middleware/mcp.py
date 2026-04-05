"""MCP Middleware: drop-in CSAE attestation for MCP tool calls.

Wraps MCP server tool responses with cryptographic attestations so any
downstream agent can verify provenance and integrity. Maintains hash
chains automatically across multi-step workflows.

Usage:

    from csae.middleware import MCPAttestor

    attestor = MCPAttestor(agent_id="mcp-server-001", vendor="your-org")

    # After your MCP tool produces a result:
    attested = attestor.attest("get_patient_record", raw_result)

    # Downstream agent verifies:
    ok = MCPAttestor.verify(attested, attestor.public_key_pem)

    # Chain across multiple tool calls:
    step1 = attestor.attest("fetch_labs", labs_result)
    step2 = attestor.attest("analyze_labs", analysis, previous=step1)

Satisfies EU AI Act Art. 12/25, HIPAA attribution, FINRA chain reconstruction.
"""

import json
from typing import Any, Dict, Optional

from ..attestation import Attestation, create_attestation, verify_attestation
from ..crypto import (
    generate_keypair,
    export_public_key,
    import_public_key,
    export_private_key,
    import_private_key,
)
from ..provenance import ProvenanceChain
from ..types import AgentIdentity, SourceType


class AttestedResponse:
    """An MCP tool response wrapped with a CSAE attestation.

    Attributes:
        result: The original tool output.
        attestation: The CSAE Attestation object.
        chain_hash: Hash for linking subsequent attestations.
        public_key_pem: PEM-encoded public key for verification.
    """

    def __init__(
        self,
        result: Dict[str, Any],
        attestation: Attestation,
        public_key_pem: str,
    ):
        self.result = result
        self.attestation = attestation
        self.chain_hash = attestation.chain_hash
        self.public_key_pem = public_key_pem

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a transport-ready dict for wire transmission."""
        return {
            "result": self.result,
            "csae_attestation": self.attestation.to_dict(),
            "csae_chain_hash": self.chain_hash,
            "csae_public_key_pem": self.public_key_pem,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class MCPAttestor:
    """Drop-in attestation for MCP servers and tool providers.

    Handles key generation, provenance tracking, and hash chaining
    automatically. One attestor per MCP server instance.

    Args:
        agent_id: Unique identifier for this MCP server.
        agent_name: Human-readable name (optional).
        vendor: Organization operating this server.
        model_id: Model or service version identifier (optional).
        organization_id: Organization context (optional).
        private_key_pem: Pre-existing private key PEM string. If None,
            a new ECDSA P-256 key pair is generated.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str = "",
        vendor: str = "",
        model_id: str = "",
        organization_id: str = "",
        private_key_pem: Optional[str] = None,
    ):
        self.agent = AgentIdentity(
            agent_id=agent_id,
            agent_name=agent_name,
            vendor=vendor,
            model_id=model_id,
            organization_id=organization_id,
        )

        if private_key_pem:
            self._private_key = import_private_key(private_key_pem)
            self._public_key = self._private_key.public_key()
        else:
            self._private_key, self._public_key = generate_keypair()

        self._last_chain_hash: Optional[str] = None

    @property
    def public_key_pem(self) -> str:
        """PEM-encoded public key for sharing with verifiers."""
        return export_public_key(self._public_key)

    @property
    def private_key_pem(self) -> str:
        """PEM-encoded private key for backup/restore."""
        return export_private_key(self._private_key)

    def attest(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        source_type: SourceType = SourceType.EXTERNAL_API,
        previous: Optional[AttestedResponse] = None,
        auto_chain: bool = True,
    ) -> AttestedResponse:
        """Wrap an MCP tool response with a CSAE attestation.

        Args:
            tool_name: Name of the MCP tool that produced the result.
            tool_result: The raw tool output dict.
            source_type: How the content originated.
            previous: A prior AttestedResponse to chain from. If provided,
                this attestation links cryptographically to the previous one.
            auto_chain: If True and no explicit previous is given, automatically
                chain to the last attestation this attestor produced. Set False
                for independent attestations.

        Returns:
            An AttestedResponse containing the result, attestation, and
            chain hash for linking subsequent calls.
        """
        chain = ProvenanceChain()
        chain.add_root(
            source_type=source_type,
            content=json.dumps(tool_result, sort_keys=True, default=str),
        )

        previous_hash = None
        if previous is not None:
            previous_hash = previous.chain_hash
        elif auto_chain and self._last_chain_hash is not None:
            previous_hash = self._last_chain_hash

        attestation = create_attestation(
            content={"tool": tool_name, "result": tool_result},
            provenance_hash=chain.chain_hash,
            signer_agent=self.agent,
            private_key=self._private_key,
            previous_attestation_hash=previous_hash,
        )

        response = AttestedResponse(
            result=tool_result,
            attestation=attestation,
            public_key_pem=self.public_key_pem,
        )

        if auto_chain:
            self._last_chain_hash = attestation.chain_hash

        return response

    def reset_chain(self) -> None:
        """Reset the auto-chain state. Next attestation starts a new chain."""
        self._last_chain_hash = None

    @staticmethod
    def verify(
        attested: AttestedResponse | Dict[str, Any],
        public_key_pem: Optional[str] = None,
    ) -> bool:
        """Verify an attested MCP response.

        Checks content integrity, chain hash, and cryptographic signature.

        Args:
            attested: An AttestedResponse object or a dict from to_dict().
            public_key_pem: PEM-encoded public key. Required if attested is
                a dict. If attested is an AttestedResponse, uses the embedded
                key unless this parameter overrides it.

        Returns:
            True if all integrity checks pass.

        Raises:
            ValueError: If no public key is available.
        """
        if isinstance(attested, AttestedResponse):
            pem = public_key_pem or attested.public_key_pem
            attestation = attested.attestation
        elif isinstance(attested, dict):
            if "csae_attestation" not in attested:
                raise ValueError("Dict has no 'csae_attestation' key.")
            pem = public_key_pem or attested.get("csae_public_key_pem")
            attestation = Attestation(**attested["csae_attestation"])
        else:
            raise TypeError(f"Expected AttestedResponse or dict, got {type(attested)}")

        if not pem:
            raise ValueError(
                "No public key available. Pass public_key_pem explicitly."
            )

        public_key = import_public_key(pem)
        return verify_attestation(attestation, public_key)

    @staticmethod
    def verify_chain(
        responses: list,
        public_key_pem: str,
    ) -> bool:
        """Verify a sequence of attested responses form a valid chain.

        Checks that each response's previous_attestation_hash matches
        the prior response's chain_hash, and that all signatures are valid.

        Args:
            responses: List of AttestedResponse objects or dicts, in order.
            public_key_pem: PEM-encoded public key of the signer.

        Returns:
            True if all attestations are valid and properly chained.
        """
        if not responses:
            return True

        for i, resp in enumerate(responses):
            if not MCPAttestor.verify(resp, public_key_pem):
                return False

            if i > 0:
                if isinstance(resp, AttestedResponse):
                    prev_hash = resp.attestation.previous_attestation_hash
                else:
                    prev_hash = resp["csae_attestation"].get(
                        "previous_attestation_hash"
                    )

                if isinstance(responses[i - 1], AttestedResponse):
                    expected = responses[i - 1].chain_hash
                else:
                    expected = responses[i - 1].get("csae_chain_hash")

                if prev_hash != expected:
                    return False

        return True
