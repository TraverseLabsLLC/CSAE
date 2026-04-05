"""
CSAE MCP Middleware Example
============================
Wrap MCP tool responses with CSAE attestations so downstream agents
can verify provenance and integrity of any transferred context.

Satisfies EU AI Act Art. 12/25, HIPAA, FINRA chain reconstruction.
"""

import json
from csae import (
    create_attestation,
    verify_attestation,
    generate_keypair,
    AgentIdentity,
    ProvenanceChain,
    SourceType,
)

private_key_a, public_key_a = generate_keypair()
private_key_b, public_key_b = generate_keypair()

agent_a = AgentIdentity(
    agent_id="mcp-retrieval-001",
    agent_name="Data Retrieval MCP Server",
    vendor="your-org",
    model_id="retrieval-service-v1",
)

agent_b = AgentIdentity(
    agent_id="clinical-summarizer-001",
    agent_name="Clinical Summarizer Agent",
    vendor="anthropic",
    model_id="claude-sonnet-4-20250514",
)


def attest_mcp_response(tool_name, tool_result, agent, private_key,
                         source_type=SourceType.EXTERNAL_API,
                         previous_attestation_hash=None):
    chain = ProvenanceChain()
    chain.add_root(source_type=source_type,
                   content=json.dumps(tool_result, sort_keys=True))
    attestation = create_attestation(
        content={"tool": tool_name, "result": tool_result},
        provenance_hash=chain.chain_hash,
        signer_agent=agent,
        private_key=private_key,
        previous_attestation_hash=previous_attestation_hash,
    )
    return {
        "result": tool_result,
        "csae_attestation": attestation.to_dict(),
        "csae_chain_hash": attestation.chain_hash,
    }


def verify_mcp_response(attested_response, public_key):
    from csae import Attestation
    if "csae_attestation" not in attested_response:
        raise ValueError("No CSAE attestation present.")
    attestation = Attestation(**attested_response["csae_attestation"])
    return verify_attestation(attestation, public_key)


def run_demo():
    print("=== CSAE MCP Middleware Demo ===")

    raw_record = {
        "patient_id": "P-10042",
        "chief_complaint": "Chest pain, onset 2 hours ago",
        "vitals": {"bp": "142/88", "hr": 98, "spo2": 97},
    }

    attested_a = attest_mcp_response("get_patient_record", raw_record,
                                      agent_a, private_key_a)
    print(f"Step 1: Attested. Hash: {attested_a['csae_chain_hash'][:24]}...")

    assert verify_mcp_response(attested_a, public_key_a)
    print("Step 2: Verified.")

    from csae import Attestation
    att_a = Attestation(**attested_a["csae_attestation"])
    summary = {"assessment": "Possible ACS", "acuity": "high"}
    attested_b = attest_mcp_response("clinical_assessment", summary,
                                      agent_b, private_key_b,
                                      SourceType.AGENT_INFERENCE,
                                      att_a.chain_hash)
    print(f"Step 3: Agent B chained. Hash: {attested_b['csae_chain_hash'][:24]}...")

    att_b = Attestation(**attested_b["csae_attestation"])
    ok = verify_mcp_response(attested_b, public_key_b)
    linked = att_b.previous_attestation_hash == att_a.chain_hash
    print(f"Step 4: Valid={ok}, Linked={linked}, Chain OK={ok and linked}")

    tampered = {**attested_b, "result": {**attested_b["result"], "acuity": "low"}}
    print(f"Step 5: Tamper detected: {not verify_mcp_response(tampered, public_key_b)}")
    print("=== Done. Full envelope features: brett@traverselabs.ai ===")


if __name__ == "__main__":
    run_demo()
