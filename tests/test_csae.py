"""Tests for the CSAE Layer 0 open-source library."""

import pytest
from csae import (
    generate_keypair,
    export_public_key,
    import_public_key,
    AgentIdentity,
    SourceType,
    TransformationType,
    ContentType,
    create_attestation,
    verify_attestation,
    ProvenanceChain,
    ProvenanceNode,
)


@pytest.fixture
def agent_a():
    return AgentIdentity(
        agent_id="agent-a",
        agent_name="Triage Agent",
        vendor="anthropic",
        model_id="claude-sonnet-4-20250514",
        organization_id="hospital-x",
    )


@pytest.fixture
def agent_b():
    return AgentIdentity(
        agent_id="agent-b",
        agent_name="Diagnostic Agent",
        vendor="openai",
        model_id="gpt-4o",
        organization_id="hospital-y",
    )


@pytest.fixture
def keys_a():
    return generate_keypair()


@pytest.fixture
def keys_b():
    return generate_keypair()


class TestAttestation:
    def test_create_and_verify(self, agent_a, keys_a):
        private_key, public_key = keys_a
        content = {"observation": "Patient reports chest pain", "severity": "high"}

        att = create_attestation(
            content=content,
            provenance_hash="abc123",
            signer_agent=agent_a,
            private_key=private_key,
        )

        assert att.content_hash != ""
        assert att.chain_hash != ""
        assert att.signature != ""
        assert verify_attestation(att, public_key) is True

    def test_tampered_content_fails(self, agent_a, keys_a):
        private_key, public_key = keys_a
        att = create_attestation(
            content={"data": "original"},
            provenance_hash="abc",
            signer_agent=agent_a,
            private_key=private_key,
        )

        att.content["data"] = "modified"
        assert verify_attestation(att, public_key) is False

    def test_wrong_key_fails(self, agent_a, keys_a, keys_b):
        private_key_a, _ = keys_a
        _, public_key_b = keys_b

        att = create_attestation(
            content={"data": "test"},
            provenance_hash="abc",
            signer_agent=agent_a,
            private_key=private_key_a,
        )

        assert verify_attestation(att, public_key_b) is False

    def test_chain_linking(self, agent_a, agent_b, keys_a, keys_b):
        priv_a, pub_a = keys_a
        priv_b, pub_b = keys_b

        att1 = create_attestation(
            content={"step": 1, "data": "original observation"},
            provenance_hash="root-hash",
            signer_agent=agent_a,
            private_key=priv_a,
        )

        att2 = create_attestation(
            content={"step": 2, "data": "derived analysis"},
            provenance_hash="derived-hash",
            signer_agent=agent_b,
            private_key=priv_b,
            previous_attestation_hash=att1.chain_hash,
        )

        assert att2.previous_attestation_hash == att1.chain_hash
        assert verify_attestation(att1, pub_a) is True
        assert verify_attestation(att2, pub_b) is True

    def test_serialization(self, agent_a, keys_a):
        private_key, _ = keys_a
        att = create_attestation(
            content={"test": True},
            provenance_hash="hash",
            signer_agent=agent_a,
            private_key=private_key,
        )

        d = att.to_dict()
        assert isinstance(d, dict)
        assert d["content"] == {"test": True}

        j = att.to_json()
        assert isinstance(j, str)


class TestProvenance:
    def test_chain_construction(self, agent_a, agent_b):
        chain = ProvenanceChain()

        root = chain.add_root(
            source_type=SourceType.DOCUMENT,
            content="Raw clinical report text",
            source_human_id="dr-smith-001",
        )

        derived = chain.add_transformation(
            parent_ids=[root.node_id],
            transformation=TransformationType.SUMMARIZATION,
            content="Patient presents with acute chest pain",
            source_agent=agent_a,
            parameters={"model": "claude-sonnet-4-20250514"},
        )

        assert len(chain.nodes) == 2
        assert len(chain.root_nodes) == 1
        assert chain.leaf_node.node_id == derived.node_id
        assert chain.depth == 1
        assert chain.chain_hash != ""

    def test_dag_with_multiple_roots(self, agent_a):
        chain = ProvenanceChain()
        r1 = chain.add_root(SourceType.DOCUMENT, "Doc 1")
        r2 = chain.add_root(SourceType.HUMAN_UTTERANCE, "Patient statement")

        merged = chain.add_transformation(
            parent_ids=[r1.node_id, r2.node_id],
            transformation=TransformationType.AGGREGATION,
            content="Combined assessment",
            source_agent=agent_a,
        )

        assert len(chain.root_nodes) == 2
        assert len(merged.parent_node_ids) == 2

    def test_cross_vendor_provenance(self, agent_a, agent_b):
        chain = ProvenanceChain()
        root = chain.add_root(SourceType.DOCUMENT, "Original content")

        step1 = chain.add_transformation(
            parent_ids=[root.node_id],
            transformation=TransformationType.SUMMARIZATION,
            content="Agent A summary",
            source_agent=agent_a,
        )

        step2 = chain.add_transformation(
            parent_ids=[step1.node_id],
            transformation=TransformationType.INFERENCE,
            content="Agent B analysis",
            source_agent=agent_b,
        )

        assert chain.agent_count == 2
        assert chain.depth == 2


class TestKeyManagement:
    def test_export_import_roundtrip(self):
        private_key, public_key = generate_keypair()
        pem = export_public_key(public_key)
        restored = import_public_key(pem)

        from csae.crypto import sign, verify
        data = "test payload"
        sig = sign(private_key, data)
        assert verify(restored, data, sig) is True
