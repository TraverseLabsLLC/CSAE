"""
CSAE MCP Middleware Demo
========================
Two-agent workflow with attestation, chain verification, and tamper detection.

Run:
    python examples/mcp_middleware.py

Satisfies EU AI Act Art. 12/25, HIPAA attribution, FINRA chain reconstruction.
"""

from csae.middleware import MCPAttestor
from csae.audit import AuditLog, Regulation

# Two MCP servers in different organizations
server_a = MCPAttestor(
    agent_id="mcp-retrieval-001",
    agent_name="Data Retrieval MCP Server",
    vendor="hospital-records-inc",
)

server_b = MCPAttestor(
    agent_id="clinical-summarizer-001",
    agent_name="Clinical Summarizer Agent",
    vendor="ai-diagnostics-co",
)

# Audit log (persists to ./csae_audit/)
audit = AuditLog()


def run_demo():
    print("=== CSAE MCP Middleware Demo ===\n")

    # Step 1: Server A retrieves a patient record and attests it
    raw_record = {
        "patient_id": "P-10042",
        "chief_complaint": "Chest pain, onset 2 hours ago",
        "vitals": {"bp": "142/88", "hr": 98, "spo2": 97},
    }

    step1 = server_a.attest("get_patient_record", raw_record)
    audit.record(step1, regulations=[Regulation.HIPAA, Regulation.EU_AI_ACT_ART12])
    print(f"1. Server A attested patient record")
    print(f"   Chain hash: {step1.chain_hash[:32]}...")
    print(f"   Verified:   {MCPAttestor.verify(step1)}")

    # Step 2: Server B receives, verifies, then produces its own attested output
    incoming_valid = MCPAttestor.verify(step1, server_a.public_key_pem)
    print(f"\n2. Server B verified incoming: {incoming_valid}")

    analysis = {"assessment": "Possible ACS", "acuity": "high", "recommend": "ECG stat"}
    step2 = server_b.attest(
        "clinical_assessment",
        analysis,
        previous=step1,
        auto_chain=False,
    )
    audit.record(step2, regulations=[Regulation.HIPAA, Regulation.EU_AI_ACT_ART25])
    print(f"   Server B attested analysis")
    print(f"   Chain hash: {step2.chain_hash[:32]}...")
    print(f"   Linked to A: {step2.attestation.previous_attestation_hash == step1.chain_hash}")

    # Step 3: Verify the full chain
    chain_valid = MCPAttestor.verify(step2, server_b.public_key_pem)
    print(f"\n3. Full chain verification: {chain_valid}")

    # Step 4: Tamper detection
    print(f"\n4. Tamper detection:")
    step2.attestation.content["result"]["acuity"] = "low"  # attacker modifies severity
    tamper_detected = not MCPAttestor.verify(step2)
    print(f"   Modified acuity from 'high' to 'low'")
    print(f"   Tamper detected: {tamper_detected}")

    # Step 5: Audit log integrity
    print(f"\n5. Audit log:")
    print(f"   Entries:        {audit.count}")
    print(f"   Chain intact:   {audit.verify_integrity()}")
    hipaa = audit.query(regulation=Regulation.HIPAA)
    print(f"   HIPAA entries:  {len(hipaa)}")

    print("\n=== Demo complete ===")
    print("Full envelope features (degradation, authority, confidence):")
    print("  https://traverselabs.ai")


if __name__ == "__main__":
    run_demo()
