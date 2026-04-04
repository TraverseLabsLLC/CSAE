# CSAE: Context State Attestation Envelope

Verifiable context transfer between AI agents across trust boundaries.

When AI agents from different vendors collaborate in regulated environments, there is no standard way to verify where context came from, whether it was altered, or what the recipient is allowed to do with it. CSAE provides a protocol for tamper-evident, provenance-tracked context transfer.

This library implements the **Layer 0 attestation primitive**: the irreducible core of verifiable agent context transfer. Three fields: content, provenance hash, cryptographic signature. Any agent can produce it. Any agent can verify it. Transport-agnostic.

## Why Now

These are enacted laws with enforcement dates, not proposed legislation:

| Regulation | Requirement | CSAE Component | Effective |
|---|---|---|---|
| EU AI Act Art. 12 | Tamper-evident logging | Integrity Seal | **Aug 2026** |
| EU AI Act Art. 25 | Value chain traceability | Provenance Chains | **Aug 2026** |
| HIPAA | Individual attribution in AI workflows | Authority + Provenance | **May 2026** |
| FINRA 17a-3/4 | Full chain reconstruction | All components | Now |
| CA SB-942 | Machine-readable provenance | Provenance Chains | Jan 2026 |
| Colorado AI Act | Impact assessments | All components | Jun 2026 |

CSAE was submitted as a candidate reference implementation to the [NIST NCCoE concept paper on AI agent identity and authorization](https://www.nccoe.nist.gov/ai/agentic-ai) (February 2026). The NIST AI Agent Standards Initiative launched the same month; CSAE addresses the data flow tracking gap that existing standards do not cover.

## Install

```bash
pip install git+https://github.com/traverselabsllc/csae.git
```

PyPI package coming soon. Track progress in [#1](https://github.com/traverselabsllc/csae/issues).

## Quick Start

```python
from csae import create_attestation, verify_attestation, generate_keypair, AgentIdentity

private_key, public_key = generate_keypair()

agent = AgentIdentity(
    agent_id="triage-001",
    agent_name="Triage Agent",
    vendor="anthropic",
    model_id="claude-sonnet-4-20250514",
)

attestation = create_attestation(
    content={"observation": "Patient reports chest pain", "severity": "high"},
    provenance_hash="sha256:abc123",
    signer_agent=agent,
    private_key=private_key,
)

assert verify_attestation(attestation, public_key) is True

# Tampering is detectable
attestation.content["severity"] = "low"
assert verify_attestation(attestation, public_key) is False
```

## MCP Integration

CSAE is transport-agnostic and works alongside MCP. Wrap any MCP tool response with a CSAE attestation before passing context to the next agent:

```python
from csae import create_attestation, AgentIdentity, generate_keypair, ProvenanceChain, SourceType

private_key, public_key = generate_keypair()
mcp_agent = AgentIdentity(agent_id="mcp-server-001", agent_name="Data Retrieval MCP Server", vendor="your-org")

def attest_mcp_response(tool_name: str, tool_result: dict) -> dict:
    chain = ProvenanceChain()
    chain.add_root(source_type=SourceType.EXTERNAL_API, content=str(tool_result))
    attestation = create_attestation(
        content={"tool": tool_name, "result": tool_result},
        provenance_hash=chain.chain_hash,
        signer_agent=mcp_agent,
        private_key=private_key,
    )
    return {"result": tool_result, "csae_attestation": attestation.to_dict(), "csae_chain_hash": attestation.chain_hash}
```

See [`examples/mcp_middleware.py`](examples/mcp_middleware.py) for a full working example with two-agent chain verification and tamper detection.

## Chain Attestations Across Agents

```python
att_a = create_attestation(content={"data": "original"}, provenance_hash="root", signer_agent=agent_a, private_key=key_a)
att_b = create_attestation(content={"data": "derived"}, provenance_hash="derived", signer_agent=agent_b, private_key=key_b, previous_attestation_hash=att_a.chain_hash)

assert att_b.previous_attestation_hash == att_a.chain_hash
assert verify_attestation(att_a, pub_key_a) is True
assert verify_attestation(att_b, pub_key_b) is True
```

## Provenance Chains

```python
from csae import ProvenanceChain, SourceType, TransformationType

chain = ProvenanceChain()
root = chain.add_root(source_type=SourceType.HUMAN_UTTERANCE, content="Patient reports chest pain", source_human_id="patient-001")
summary = chain.add_transformation(parent_ids=[root.node_id], transformation=TransformationType.SUMMARIZATION, content="Acute chest pain presentation", source_agent=agent_a)
att = create_attestation(content={"summary": "Acute chest pain presentation"}, provenance_hash=chain.chain_hash, signer_agent=agent_a, private_key=private_key)
```

## How It Works

1. **Agent A** processes content and computes a SHA-256 hash of the output.
2. 2. **Agent A** signs the hash (plus a chain link to any prior attestation) with its ECDSA P-256 private key.
   3. 3. **Agent A** transmits the signed attestation to Agent B over any transport: MCP, A2A, HTTP, etc.
      4. 4. **Agent B** verifies the signature. If valid, the content is guaranteed unmodified.
         5. 5. **Agent B** creates its own attestation chained to Agent A's.
            6. 6. **Any auditor** can verify the full chain using only attestations and public keys -- no access to vendor internals required.
              
               7. ## Architecture
              
               8. **Layer 0: Attestation Primitive** (this library). Content + provenance hash + cryptographic signature. The irreducible core.
              
               9. **Layer 1: Typed Provenance Chains** (this library). Full DAG with source types, transformation types, and per-node content hashes.
              
               10. **Layer 2: Transformation Metadata and Authority Controls.** Available in the commercial SDK.
              
               11. **Layer 3: Full CSAE Envelope.** Six coupled components with integrity seal, degradation policies, and regulatory compliance features. Available in the commercial SDK.
              
               12. ## Advanced Features
              
               13. For regulated deployments requiring full envelope integrity sealing, transformation propagation tracking, authority attenuation, and degradation under token constraints, Traverse Labs offers a commercial SDK. Contact brett@traverselabs.ai for details.
              
               14. ## License
              
               15. Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
              
               16. ## About
              
               17. Built by [Traverse Labs LLC](https://traverselabs.ai). Questions and feedback: brett@traverselabs.ai
