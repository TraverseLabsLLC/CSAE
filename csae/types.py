"""Core types, enums, and base models for CSAE."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class SourceType(str, Enum):
    """How the content originated."""
    HUMAN_UTTERANCE = "human_utterance"
    DOCUMENT = "document"
    AGENT_INFERENCE = "agent_inference"
    AGENT_OBSERVATION = "agent_observation"
    EXTERNAL_API = "external_api"
    DATABASE_QUERY = "database_query"
    ANOTHER_ENVELOPE = "another_envelope"
    SYSTEM_EVENT = "system_event"


class TransformationType(str, Enum):
    """What processing was applied to produce the content."""
    VERBATIM = "verbatim"
    SUMMARIZATION = "summarization"
    INFERENCE = "inference"
    CROSS_MODEL_TRANSLATION = "cross_model_translation"
    EXTRACTION = "extraction"
    AGGREGATION = "aggregation"
    REDACTION = "redaction"
    FILTERING = "filtering"


class ContentCategory(str, Enum):
    """Top-level categories for the content type ontology."""
    OBSERVATION = "observation"
    BELIEF = "belief"
    DECISION = "decision"
    ACTION = "action"
    ANALYSIS = "analysis"
    QUESTION = "question"
    COMPLIANCE = "compliance"


class ContentType(str, Enum):
    """Typed ontology for AI agent reasoning state (30+ types)."""
    # Observations
    OBSERVATION = "observation"
    TRANSCRIPT_SEGMENT = "transcript_segment"
    PARTICIPANT_ACTION = "participant_action"
    SYSTEM_EVENT = "system_event"
    DOCUMENT_EXTRACT = "document_extract"
    # Beliefs
    BELIEF = "belief"
    FACT = "fact"
    ASSUMPTION = "assumption"
    INFERENCE = "inference"
    # Decisions
    KEY_DECISION = "key_decision"
    REJECTED_ALTERNATIVE = "rejected_alternative"
    PENDING_DECISION = "pending_decision"
    # Actions
    ACTION_ITEM = "action_item"
    COMMITMENT = "commitment"
    DEADLINE = "deadline"
    DELEGATION = "delegation"
    # Analysis
    SUMMARY = "summary"
    SENTIMENT = "sentiment"
    TOPIC = "topic"
    RELATIONSHIP = "relationship"
    PATTERN = "pattern"
    # Questions
    OPEN_QUESTION = "open_question"
    CLARIFICATION_NEEDED = "clarification_needed"
    DISAGREEMENT = "disagreement"
    # Compliance
    COMPLIANCE_RECORD = "compliance_record"
    CONSENT_RECORD = "consent_record"
    AUDIT_MARKER = "audit_marker"
    CAPABILITY_LIMITATION = "capability_limitation"


class Permission(str, Enum):
    """Operations that may be performed on content."""
    READ = "read"
    SUMMARIZE = "summarize"
    FORWARD_RAW = "forward_raw"
    FORWARD_SUMMARY = "forward_summary"
    DERIVE = "derive"
    QUOTE = "quote"
    REDACT = "redact"
    AGGREGATE = "aggregate"


class UncertaintyType(str, Enum):
    """Classification of uncertainty source."""
    EPISTEMIC = "epistemic"
    ALEATORIC = "aleatoric"
    MODEL_UNCERTAINTY = "model_uncertainty"
    TEMPORAL = "temporal"
    AGGREGATION = "aggregation"
    TRANSLATION = "translation"


class AgentIdentity(BaseModel):
    """Identity of an AI agent."""
    agent_id: str
    agent_name: str = ""
    agent_type: str = ""
    vendor: str = ""
    model_id: str = ""
    organization_id: str = ""
    config_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return self.model_dump(exclude_none=True)
