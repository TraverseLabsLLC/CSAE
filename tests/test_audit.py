"""Tests for the CSAE audit log."""

import json
import os
import tempfile
import pytest

from csae.audit import AuditLog, AuditEntry, Regulation
from csae.middleware.mcp import MCPAttestor


@pytest.fixture
def tmp_audit_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def audit_log(tmp_audit_dir):
    return AuditLog(path=tmp_audit_dir)


@pytest.fixture
def attestor():
    return MCPAttestor(agent_id="audit-test-001", vendor="test-org")


class TestAuditLog:
    def test_record_attested_response(self, audit_log, attestor):
        resp = attestor.attest("get_patient_record", {"patient": "P-001"})
        entry = audit_log.record(resp, regulations=[Regulation.HIPAA])

        assert entry.entry_hash != ""
        assert entry.tool_name == "get_patient_record"
        assert "hipaa" in entry.regulations
        assert audit_log.count == 1

    def test_record_attestation_object(self, audit_log, attestor):
        resp = attestor.attest("fetch_labs", {"wbc": 11.2})
        entry = audit_log.record(resp.attestation, tool_name="fetch_labs")

        assert audit_log.count == 1
        assert entry.tool_name == "fetch_labs"

    def test_record_dict(self, audit_log, attestor):
        resp = attestor.attest("tool", {"data": 1})
        entry = audit_log.record(
            resp.attestation.to_dict(),
            tool_name="tool",
        )
        assert audit_log.count == 1

    def test_hash_chain_integrity(self, audit_log, attestor):
        for i in range(5):
            resp = attestor.attest(f"step_{i}", {"n": i})
            audit_log.record(resp)

        assert audit_log.count == 5
        assert audit_log.verify_integrity() is True

    def test_tamper_detection(self, audit_log, attestor):
        for i in range(3):
            resp = attestor.attest(f"step_{i}", {"n": i})
            audit_log.record(resp)

        # Tamper with the middle entry
        lines = []
        with open(audit_log._log_path, "r") as f:
            lines = f.readlines()

        middle = json.loads(lines[1])
        middle["tool_name"] = "HACKED"
        lines[1] = json.dumps(middle, separators=(",", ":")) + "\n"

        with open(audit_log._log_path, "w") as f:
            f.writelines(lines)

        # Reload and verify
        fresh_log = AuditLog(path=str(audit_log._dir))
        assert fresh_log.verify_integrity() is False

    def test_deletion_detection(self, audit_log, attestor):
        for i in range(3):
            resp = attestor.attest(f"step_{i}", {"n": i})
            audit_log.record(resp)

        # Delete the middle entry
        lines = []
        with open(audit_log._log_path, "r") as f:
            lines = f.readlines()

        with open(audit_log._log_path, "w") as f:
            f.write(lines[0])
            f.write(lines[2])  # Skip middle

        fresh_log = AuditLog(path=str(audit_log._dir))
        assert fresh_log.verify_integrity() is False

    def test_query_by_tool_name(self, audit_log, attestor):
        audit_log.record(attestor.attest("fetch_labs", {"data": 1}))
        audit_log.record(attestor.attest("get_vitals", {"data": 2}))
        audit_log.record(attestor.attest("fetch_labs", {"data": 3}))

        results = audit_log.query(tool_name="fetch_labs")
        assert len(results) == 2

    def test_query_by_regulation(self, audit_log, attestor):
        audit_log.record(
            attestor.attest("tool_a", {"d": 1}),
            regulations=[Regulation.HIPAA],
        )
        audit_log.record(
            attestor.attest("tool_b", {"d": 2}),
            regulations=[Regulation.EU_AI_ACT_ART12, Regulation.EU_AI_ACT_ART25],
        )
        audit_log.record(
            attestor.attest("tool_c", {"d": 3}),
            regulations=[Regulation.HIPAA, Regulation.FINRA],
        )

        hipaa = audit_log.query(regulation=Regulation.HIPAA)
        assert len(hipaa) == 2

        eu = audit_log.query(regulation=Regulation.EU_AI_ACT_ART12)
        assert len(eu) == 1

    def test_query_by_agent_id(self, audit_log):
        att_a = MCPAttestor(agent_id="server-a", vendor="org-a")
        att_b = MCPAttestor(agent_id="server-b", vendor="org-b")

        audit_log.record(att_a.attest("tool", {"d": 1}))
        audit_log.record(att_b.attest("tool", {"d": 2}))
        audit_log.record(att_a.attest("tool", {"d": 3}))

        results = audit_log.query(agent_id="server-a")
        assert len(results) == 2

    def test_export_json(self, audit_log, attestor, tmp_audit_dir):
        for i in range(3):
            audit_log.record(
                attestor.attest(f"step_{i}", {"n": i}),
                regulations=[Regulation.FINRA],
            )

        export_path = os.path.join(tmp_audit_dir, "export.json")
        audit_log.export_json(export_path)

        with open(export_path, "r") as f:
            export = json.load(f)

        assert export["entry_count"] == 3
        assert export["chain_intact"] is True
        assert len(export["entries"]) == 3

    def test_persistence_across_instances(self, tmp_audit_dir, attestor):
        log1 = AuditLog(path=tmp_audit_dir)
        log1.record(attestor.attest("tool_a", {"d": 1}))
        log1.record(attestor.attest("tool_b", {"d": 2}))

        log2 = AuditLog(path=tmp_audit_dir)
        assert log2.count == 2
        log2.record(attestor.attest("tool_c", {"d": 3}))
        assert log2.count == 3
        assert log2.verify_integrity() is True

    def test_empty_log(self, audit_log):
        assert audit_log.count == 0
        assert audit_log.entries() == []
        assert audit_log.verify_integrity() is True

    def test_metadata(self, audit_log, attestor):
        entry = audit_log.record(
            attestor.attest("tool", {"d": 1}),
            metadata={"environment": "production", "deployment_id": "deploy-042"},
        )
        assert entry.metadata["environment"] == "production"

        entries = audit_log.entries()
        assert entries[0].metadata["deployment_id"] == "deploy-042"
