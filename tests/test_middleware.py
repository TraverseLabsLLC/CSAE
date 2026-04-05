"""Tests for the CSAE MCP middleware."""

import json
import pytest

from csae.middleware.mcp import MCPAttestor, AttestedResponse
from csae import generate_keypair, export_public_key, AgentIdentity


@pytest.fixture
def attestor():
    return MCPAttestor(
        agent_id="test-mcp-001",
        agent_name="Test MCP Server",
        vendor="test-org",
    )


@pytest.fixture
def tool_result():
    return {
        "patient_id": "P-10042",
        "chief_complaint": "Chest pain, onset 2 hours ago",
        "vitals": {"bp": "142/88", "hr": 98, "spo2": 97},
    }


class TestMCPAttestor:
    def test_attest_produces_valid_response(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)

        assert isinstance(resp, AttestedResponse)
        assert resp.result == tool_result
        assert resp.chain_hash != ""
        assert resp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_verify_attested_response(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        assert MCPAttestor.verify(resp) is True

    def test_verify_with_explicit_key(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        assert MCPAttestor.verify(resp, attestor.public_key_pem) is True

    def test_verify_dict_form(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        resp_dict = resp.to_dict()
        assert MCPAttestor.verify(resp_dict) is True

    def test_tampered_content_detected(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        resp.attestation.content["result"]["chief_complaint"] = "Headache"
        assert MCPAttestor.verify(resp) is False

    def test_wrong_key_rejected(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        _, wrong_pub = generate_keypair()
        wrong_pem = export_public_key(wrong_pub)
        assert MCPAttestor.verify(resp, wrong_pem) is False

    def test_auto_chaining(self, attestor):
        step1 = attestor.attest("fetch_labs", {"test": "CBC", "wbc": 11.2})
        step2 = attestor.attest("analyze_labs", {"assessment": "elevated WBC"})

        assert step2.attestation.previous_attestation_hash == step1.chain_hash
        assert MCPAttestor.verify(step1) is True
        assert MCPAttestor.verify(step2) is True

    def test_explicit_chaining(self, attestor):
        step1 = attestor.attest("fetch_labs", {"test": "CBC"}, auto_chain=False)
        step2 = attestor.attest(
            "analyze_labs",
            {"assessment": "normal"},
            previous=step1,
            auto_chain=False,
        )

        assert step2.attestation.previous_attestation_hash == step1.chain_hash

    def test_reset_chain(self, attestor):
        step1 = attestor.attest("tool_a", {"data": 1})
        attestor.reset_chain()
        step2 = attestor.attest("tool_b", {"data": 2})

        assert step2.attestation.previous_attestation_hash is None

    def test_verify_chain(self, attestor):
        steps = [
            attestor.attest("step1", {"n": 1}),
            attestor.attest("step2", {"n": 2}),
            attestor.attest("step3", {"n": 3}),
        ]

        assert MCPAttestor.verify_chain(steps, attestor.public_key_pem) is True

    def test_verify_chain_detects_reorder(self, attestor):
        steps = [
            attestor.attest("step1", {"n": 1}),
            attestor.attest("step2", {"n": 2}),
            attestor.attest("step3", {"n": 3}),
        ]

        # Swap steps 1 and 2
        reordered = [steps[0], steps[2], steps[1]]
        assert MCPAttestor.verify_chain(reordered, attestor.public_key_pem) is False

    def test_serialization_roundtrip(self, attestor, tool_result):
        resp = attestor.attest("get_patient_record", tool_result)
        json_str = resp.to_json()
        parsed = json.loads(json_str)

        assert parsed["result"] == tool_result
        assert "csae_attestation" in parsed
        assert "csae_chain_hash" in parsed
        assert "csae_public_key_pem" in parsed

    def test_key_persistence(self):
        att1 = MCPAttestor(agent_id="persist-test", vendor="test")
        pem = att1.private_key_pem

        att2 = MCPAttestor(
            agent_id="persist-test",
            vendor="test",
            private_key_pem=pem,
        )

        resp = att1.attest("tool", {"data": "test"})
        assert MCPAttestor.verify(resp, att2.public_key_pem) is True

    def test_no_key_raises(self, attestor, tool_result):
        resp = attestor.attest("tool", tool_result)
        resp_dict = resp.to_dict()
        del resp_dict["csae_public_key_pem"]

        with pytest.raises(ValueError, match="No public key"):
            MCPAttestor.verify(resp_dict)

    def test_cross_attestor_verification(self, tool_result):
        server_a = MCPAttestor(agent_id="server-a", vendor="org-a")
        server_b = MCPAttestor(agent_id="server-b", vendor="org-b")

        resp_a = server_a.attest("fetch", tool_result)
        resp_b = server_b.attest(
            "process",
            {"derived": True},
            previous=resp_a,
            auto_chain=False,
        )

        assert MCPAttestor.verify(resp_a, server_a.public_key_pem) is True
        assert MCPAttestor.verify(resp_b, server_b.public_key_pem) is True
        assert resp_b.attestation.previous_attestation_hash == resp_a.chain_hash

        # Cross-key fails
        assert MCPAttestor.verify(resp_a, server_b.public_key_pem) is False
