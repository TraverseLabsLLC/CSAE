# CSAE: Context State Attestation Envelope

Verifiable context transfer between AI agents across trust boundaries.

When AI agents from different vendors collaborate in regulated environments, there is no standard way to verify where context came from, whether it was altered, or what the recipient is allowed to do with it. CSAE provides a protocol for tamper-evident, provenance-tracked context transfer.

This library implements the **Layer 0 attestation primitive**: the irreducible core of verifiable agent context transfer. Three fields: content, provenance hash, cryptographic signature. Any agent can produce it. Any agent can verify it. Transport-agnostic.

## Install

```bash
pip install csae
```

Or install from source:

```bash
pip install git+https://github.com/traverselabs/csae.git
```

## Quick Start

```python
from csae import create_attestation, verify_attestation, generate_keypair, AgentIdentity

# Each agent has a key pair
private_key, public_key = generate_keypair()

agent = AgentIdentity(
    agent_id="triage-001",
    agent_name="Triage Agent",
    vendor="anthropic",
    model_id="claude-sonnet-4-20250514",
)

# Create a signed attestation
attestation = create_attestation(
    content={"observation": "Patient reports chest pain", "severity": "high"},
    provenance_hash="sha256:abc123",
    signer_agent=agent,
    private_key=private_key,
)

# Anyone with the public key can verify
assert verify_attestation(attestation, public_key) is True

# Tampering is detectable
attestation.content["severity"] = "low"
assert verify_attestation(attestation, public_key) is False
```

## Chain Attestations Across Agents

Each attestation links to the previous one, creating a tamper-evident chain across vendor boundaries.

```python
# Agent A creates the first attestation
att_a = create_attestation(
    content={"data": "original observation"},
    provenance_hash="root-hash",
    signer_agent=agent_a,
    private_key=key_a,
)

# Agent B chains its attestation to Agent A's
att_b = create_attestation(
    content={"data": "derived analysis"},
    provenance_hash="derived-hash",
    signer_agent=agent_b,
    private_key=key_b,
    previous_attestation_hash=att_a.chain_hash,
)

# The chain is verifiable by any third party
assert att_b.previous_attestation_hash == att_a.chain_hash
assert verify_attestation(att_a, pub_key_a) is True
assert verify_attestation(att_b, pub_key_b) is True
```

## Provenance Chains

Track where content came from and what happened to it through the agent chain.

```python
from csae import ProvenanceChain, SourceType, TransformationType

chain = ProvenanceChain()

# Record the original source
root = chain.add_root(
    source_type=SourceType.HUMAN_UTTERANCE,
    content="Patient reports chest pain",
    source_human_id="patient-001",
)

# Record each transformation
summary = chain.add_transformation(
    parent_ids=[root.node_id],
    transformation=TransformationType.SUMMARIZATION,
    content="Acute chest pain presentation",
    source_agent=agent_a,
    parameters={"model": "claude-sonnet-4-20250514"},
)

# Use the chain hash in your attestation
att = create_attestation(
    content={"summary": "Acute chest pain presentation"},
    provenance_hash=chain.chain_hash,
    signer_agent=agent_a,
    private_key=private_key,
)
```

## How It Works

1. **Agent A** processes content and computes a SHA-256 hash of the output.
2. **Agent A** signs the content hash (plus a chain link to any prior attestation) with its ECDSA P-256 private key.
3. **Agent A** transmits the signed attestation to Agent B (over any transport: MCP, A2A, HTTP, etc.).
4. **Agent B** verifies the signature using Agent A's public key. If valid, the content is guaranteed unmodified.
5. **Agent B** creates its own attestation chained to Agent A's, extending the tamper-evident chain.
6. **Any auditor** can verify the full chain using only the attestations and public keys. No access to any vendor's internal systems is required.

## Transport Agnostic

CSAE works over any transport. The library handles construction, signing, and verification. You handle the transport.

```python
# Serialize for transport
json_str = attestation.to_json()
payload = attestation.to_dict()

# Send over your preferred transport: HTTP, MCP, A2A, WebSocket, etc.
```

## Architecture

CSAE is designed as a four-layer protocol stack. This library implements the foundational layers:

**Layer 0: Attestation Primitive** (this library). Content + provenance hash + cryptographic signature. The irreducible core.

**Layer 1: Typed Provenance Chains** (this library). Full DAG with source types, transformation types, and per-node content hashes.

**Layer 2: Transformation Metadata and Authority Controls.** Available in the commercial SDK.

**Layer 3: Full CSAE Envelope.** Six coupled components with integrity seal, degradation policies, and regulatory compliance features. Available in the commercial SDK.

## Advanced Features

For regulated deployments requiring full envelope integrity sealing, transformation propagation tracking, authority attenuation, and degradation under token constraints, Traverse Labs offers a commercial SDK. Contact brett@traverselabs.ai for details.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About

Built by [Traverse Labs LLC](https://traverselabs.ai).

Questions and feedback: brett@traverselabs.ai
