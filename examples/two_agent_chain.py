"""
Two-Agent Chain Example
=======================
Minimal example: two agents from different vendors pass context with
cryptographic proof of integrity. Seven lines of meaningful code.

Run:
    python examples/two_agent_chain.py
"""

from csae.middleware import MCPAttestor

agent_a = MCPAttestor(agent_id="triage-001", vendor="anthropic")
agent_b = MCPAttestor(agent_id="diagnostics-001", vendor="openai")

# Agent A produces attested output
step1 = agent_a.attest("triage", {"observation": "Chest pain", "severity": "high"})

# Agent B receives, verifies, then produces its own attested output chained to A
assert MCPAttestor.verify(step1, agent_a.public_key_pem)
step2 = agent_b.attest("diagnose", {"assessment": "Possible ACS"}, previous=step1, auto_chain=False)

# Anyone can verify the full chain with only public keys
assert MCPAttestor.verify(step1, agent_a.public_key_pem)
assert MCPAttestor.verify(step2, agent_b.public_key_pem)
assert step2.attestation.previous_attestation_hash == step1.chain_hash

# Tamper detection
step1.attestation.content["severity"] = "low"
assert not MCPAttestor.verify(step1, agent_a.public_key_pem)

print("Two-agent chain: verified, linked, tamper-proof.")
