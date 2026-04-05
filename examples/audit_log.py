"""
Audit Log Example
=================
Demonstrates tamper-evident audit logging with regulatory context markers.
This is what you hand to an auditor.

Run:
    python examples/audit_log.py
"""

from csae.middleware import MCPAttestor
from csae.audit import AuditLog, Regulation

# Set up
attestor = MCPAttestor(agent_id="ehr-agent-001", vendor="health-ai-co")
audit = AuditLog(path="./example_audit")

# Simulate a multi-step clinical workflow
steps = [
    ("get_patient_record", {"patient_id": "P-10042", "complaint": "Chest pain"}),
    ("fetch_labs", {"wbc": 11.2, "troponin": 0.04, "bnp": 280}),
    ("clinical_assessment", {"assessment": "Possible ACS", "acuity": "high"}),
    ("order_placed", {"order": "ECG stat", "priority": "urgent"}),
]

print("Recording attested workflow to audit log...\n")

for tool_name, result in steps:
    resp = attestor.attest(tool_name, result)
    audit.record(
        resp,
        regulations=[Regulation.HIPAA, Regulation.EU_AI_ACT_ART12],
        metadata={"environment": "production", "session": "sess-20260405-001"},
    )
    print(f"  Recorded: {tool_name}")

# Query
print(f"\nTotal entries: {audit.count}")
print(f"Chain intact:  {audit.verify_integrity()}")

hipaa = audit.query(regulation=Regulation.HIPAA)
print(f"HIPAA entries: {len(hipaa)}")

# Export for auditor
export_path = audit.export_json("./example_audit/audit_export.json")
print(f"\nExported to: {export_path}")
print("Hand this file to your auditor.")
