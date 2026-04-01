"""Example: Two-agent context transfer with verification.

Agent A (Anthropic) produces an observation and signs it.
Agent B (OpenAI) receives, verifies, processes, and signs its output
with a chain link back to Agent A.

Any third party can verify the full chain.
"""

from csae import (
    generate_keypair,
    AgentIdentity,
    SourceType,
    TransformationType,
    create_attestation,
    verify_attestation,
    ProvenanceChain,
)


def main():
    # Set up two agents with key pairs
    agent_a = AgentIdentity(
        agent_id="triage-001",
        agent_name="Triage Agent",
        vendor="anthropic",
        model_id="claude-sonnet-4-20250514",
        organization_id="hospital-north",
    )
    key_a_priv, key_a_pub = generate_keypair()

    agent_b = AgentIdentity(
        agent_id="diag-001",
        agent_name="Diagnostic Agent",
        vendor="openai",
        model_id="gpt-4o",
        organization_id="hospital-south",
    )
    key_b_priv, key_b_pub = generate_keypair()

    # Agent A builds provenance and creates attestation
    prov_a = ProvenanceChain()
    root = prov_a.add_root(
        source_type=SourceType.HUMAN_UTTERANCE,
        content="Patient reports chest pain radiating to left arm",
        source_human_id="patient-jane-doe",
    )
    summary = prov_a.add_transformation(
        parent_ids=[root.node_id],
        transformation=TransformationType.INFERENCE,
        content="Suspected acute coronary syndrome",
        source_agent=agent_a,
        parameters={"model": "claude-sonnet-4-20250514", "temperature": 0.1},
    )

    att_a = create_attestation(
        content={
            "type": "belief",
            "assertion": "Suspected acute coronary syndrome",
            "basis": "Patient-reported symptom pattern",
            "urgency": "high",
        },
        provenance_hash=prov_a.chain_hash,
        signer_agent=agent_a,
        private_key=key_a_priv,
    )

    print("=== Agent A: Triage ===")
    print(f"  Content hash: {att_a.content_hash[:24]}...")
    print(f"  Provenance: {prov_a.depth} transformation(s), {prov_a.agent_count} agent(s)")
    print(f"  Chain hash: {att_a.chain_hash[:24]}...")
    print(f"  Signature valid: {verify_attestation(att_a, key_a_pub)}")
    print()

    # Agent B receives, verifies, and creates a chained attestation
    print("=== Agent B: Diagnostic ===")
    verified = verify_attestation(att_a, key_a_pub)
    print(f"  Verified Agent A's attestation: {verified}")

    if not verified:
        print("  REJECTED: integrity check failed")
        return

    # Agent B builds its own provenance extending Agent A's chain
    prov_b = ProvenanceChain()
    received = prov_b.add_root(
        source_type=SourceType.ANOTHER_ENVELOPE,
        content="Suspected acute coronary syndrome",
        source_agent=agent_a,
    )
    analysis = prov_b.add_transformation(
        parent_ids=[received.node_id],
        transformation=TransformationType.INFERENCE,
        content="ECG confirms ST-elevation. Recommend catheterization.",
        source_agent=agent_b,
        parameters={"model": "gpt-4o"},
    )

    att_b = create_attestation(
        content={
            "type": "key_decision",
            "decision": "Immediate cardiac catheterization",
            "basis": "ECG-confirmed ST-elevation from triage assessment",
        },
        provenance_hash=prov_b.chain_hash,
        signer_agent=agent_b,
        private_key=key_b_priv,
        previous_attestation_hash=att_a.chain_hash,  # chain link
    )

    print(f"  Content hash: {att_b.content_hash[:24]}...")
    print(f"  Chain link to Agent A: {att_b.previous_attestation_hash[:24]}...")
    print(f"  Signature valid: {verify_attestation(att_b, key_b_pub)}")
    print()

    # Demonstrate tamper detection
    print("=== Tamper Detection ===")
    att_b.content["decision"] = "No treatment needed"
    tampered = verify_attestation(att_b, key_b_pub)
    print(f"  After modifying content: {'PASSED' if tampered else 'FAILED (tampering detected)'}")

    # Restore and verify chain integrity
    att_b.content["decision"] = "Immediate cardiac catheterization"
    print()

    # Auditor can verify the full chain
    print("=== Auditor Verification ===")
    print(f"  Agent A attestation valid: {verify_attestation(att_a, key_a_pub)}")
    print(f"  Agent B attestation valid: {verify_attestation(att_b, key_b_pub)}")
    print(f"  Chain link intact: {att_b.previous_attestation_hash == att_a.chain_hash}")
    print(f"  Cross-vendor provenance: {prov_b.agent_count} agents from different orgs")
    print()
    print("Full chain of custody verified across two vendors.")


if __name__ == "__main__":
    main()
