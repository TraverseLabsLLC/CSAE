"""Audit logging for CSAE attestations.

Persists attestations to a tamper-evident audit log with regulatory context
markers. This is what auditors inspect, not the raw attestation objects.

Usage:

    from csae.audit import AuditLog, Regulation

    log = AuditLog("./audit")

    # Log an attestation with regulatory context
    log.record(attested_response, regulations=[Regulation.EU_AI_ACT_ART12])

    # Query the log
    entries = log.query(tool_name="get_patient_record")
    entries = log.query(regulation=Regulation.HIPAA)
    entries = log.query(after="2026-04-01T00:00:00Z")

    # Verify log integrity (no entries modified or removed)
    ok = log.verify_integrity()

    # Export for auditor
    log.export_json("audit_export.json")
"""

import json
import hashlib
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Regulation(str, Enum):
    """Regulatory frameworks that CSAE attestations can satisfy."""
    EU_AI_ACT_ART12 = "eu_ai_act_art12"       # Tamper-evident logging
    EU_AI_ACT_ART25 = "eu_ai_act_art25"       # Value chain traceability
    HIPAA = "hipaa"                             # Individual attribution
    FINRA = "finra"                             # Full chain reconstruction
    GDPR_ART20 = "gdpr_art20"                  # Data portability
    CA_SB942 = "ca_sb942"                       # Machine-readable provenance
    CO_AI_ACT = "co_ai_act"                     # Impact assessments
    SOC2 = "soc2"                               # Service org controls
    ISO_42001 = "iso_42001"                     # AI management systems


class AuditEntry:
    """A single entry in the audit log."""

    def __init__(
        self,
        attestation_dict: Dict[str, Any],
        tool_name: str = "",
        regulations: Optional[List[Regulation]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.attestation = attestation_dict
        self.tool_name = tool_name
        self.regulations = [r.value for r in (regulations or [])]
        self.metadata = metadata or {}
        self.entry_hash = ""
        self.previous_entry_hash = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "regulations": self.regulations,
            "metadata": self.metadata,
            "attestation": self.attestation,
            "entry_hash": self.entry_hash,
            "previous_entry_hash": self.previous_entry_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        entry = cls(
            attestation_dict=data["attestation"],
            tool_name=data.get("tool_name", ""),
        )
        entry.timestamp = data["timestamp"]
        entry.regulations = data.get("regulations", [])
        entry.metadata = data.get("metadata", {})
        entry.entry_hash = data.get("entry_hash", "")
        entry.previous_entry_hash = data.get("previous_entry_hash", "")
        return entry


def _hash_entry(entry_dict: Dict[str, Any], previous_hash: str) -> str:
    """Compute a tamper-evident hash for an audit entry."""
    hashable = {
        "timestamp": entry_dict["timestamp"],
        "tool_name": entry_dict["tool_name"],
        "regulations": entry_dict["regulations"],
        "attestation_chain_hash": entry_dict["attestation"].get("chain_hash", ""),
        "attestation_content_hash": entry_dict["attestation"].get("content_hash", ""),
        "previous_entry_hash": previous_hash,
    }
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """File-backed, tamper-evident audit log for CSAE attestations.

    Each entry is hash-chained to the previous entry. Tampering with or
    removing any entry breaks the chain and is detectable via verify_integrity().

    Args:
        path: Directory to store audit log files. Created if it doesn't exist.
        log_file: Name of the log file within the directory.
    """

    def __init__(self, path: str = "./csae_audit", log_file: str = "audit.jsonl"):
        self._dir = Path(path)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._dir / log_file
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        """Load the hash of the last entry in the log, or empty string if new."""
        if not self._log_path.exists():
            return ""
        last_line = ""
        with open(self._log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return ""
        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", "")
        except json.JSONDecodeError:
            return ""

    def record(
        self,
        attested_response,
        tool_name: str = "",
        regulations: Optional[List[Regulation]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Record an attested response to the audit log.

        Args:
            attested_response: An AttestedResponse object, an Attestation object,
                or a dict containing attestation data.
            tool_name: Name of the tool that produced the result.
                Auto-extracted from attestation content if not provided.
            regulations: List of regulations this attestation satisfies.
            metadata: Additional context (deployment ID, environment, etc).

        Returns:
            The AuditEntry that was recorded.
        """
        # Extract attestation dict from various input types
        if hasattr(attested_response, "attestation"):
            att_dict = attested_response.attestation.to_dict()
            if not tool_name:
                tool_name = attested_response.attestation.content.get("tool", "")
        elif hasattr(attested_response, "to_dict"):
            att_dict = attested_response.to_dict()
            if not tool_name:
                tool_name = att_dict.get("content", {}).get("tool", "")
        elif isinstance(attested_response, dict):
            att_dict = attested_response
            if not tool_name:
                tool_name = att_dict.get("content", {}).get("tool", "")
        else:
            raise TypeError(
                f"Expected AttestedResponse, Attestation, or dict; got {type(attested_response)}"
            )

        entry = AuditEntry(
            attestation_dict=att_dict,
            tool_name=tool_name,
            regulations=regulations,
            metadata=metadata,
        )

        entry.previous_entry_hash = self._last_hash
        entry_dict = entry.to_dict()
        entry.entry_hash = _hash_entry(entry_dict, self._last_hash)
        entry_dict["entry_hash"] = entry.entry_hash

        with open(self._log_path, "a") as f:
            f.write(json.dumps(entry_dict, separators=(",", ":")) + "\n")

        self._last_hash = entry.entry_hash
        return entry

    def entries(self) -> List[AuditEntry]:
        """Load all entries from the log."""
        if not self._log_path.exists():
            return []
        results = []
        with open(self._log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(AuditEntry.from_dict(json.loads(line)))
        return results

    def query(
        self,
        tool_name: Optional[str] = None,
        regulation: Optional[Regulation] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Query the audit log with filters.

        Args:
            tool_name: Filter by tool name (exact match).
            regulation: Filter by regulatory framework.
            after: ISO timestamp; return entries after this time.
            before: ISO timestamp; return entries before this time.
            agent_id: Filter by signer agent ID.

        Returns:
            List of matching AuditEntry objects.
        """
        results = []
        for entry in self.entries():
            if tool_name and entry.tool_name != tool_name:
                continue
            if regulation and regulation.value not in entry.regulations:
                continue
            if after and entry.timestamp < after:
                continue
            if before and entry.timestamp > before:
                continue
            if agent_id:
                signer = entry.attestation.get("signer_agent", {})
                if signer.get("agent_id") != agent_id:
                    continue
            results.append(entry)
        return results

    def verify_integrity(self) -> bool:
        """Verify the full audit log hash chain is intact.

        Recomputes every entry hash and checks it matches the recorded hash
        and links correctly to the previous entry.

        Returns:
            True if the entire log is intact. False if any entry has been
            modified, removed, or reordered.
        """
        prev_hash = ""
        for entry in self.entries():
            entry_dict = entry.to_dict()
            expected = _hash_entry(entry_dict, prev_hash)
            if expected != entry.entry_hash:
                return False
            if entry.previous_entry_hash != prev_hash:
                return False
            prev_hash = entry.entry_hash
        return True

    def export_json(self, output_path: str) -> str:
        """Export the full audit log as a JSON file for auditor review.

        Args:
            output_path: Path to write the export file.

        Returns:
            The output path.
        """
        all_entries = self.entries()
        export = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(all_entries),
            "chain_intact": self.verify_integrity(),
            "entries": [e.to_dict() for e in all_entries],
        }
        with open(output_path, "w") as f:
            json.dump(export, f, indent=2)
        return output_path

    @property
    def count(self) -> int:
        """Number of entries in the log."""
        if not self._log_path.exists():
            return 0
        count = 0
        with open(self._log_path, "r") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
