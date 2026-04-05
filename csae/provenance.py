"""Provenance chain: DAG of transformation nodes tracking content lineage."""

from typing import Optional, List, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid

from .types import SourceType, TransformationType, AgentIdentity
from .crypto import content_hash


class ProvenanceNode(BaseModel):
    """A single node in the provenance DAG."""
    node_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_type: SourceType
    source_agent: Optional[AgentIdentity] = None
    source_human_id: Optional[str] = None
    transformation: TransformationType = TransformationType.VERBATIM
    transformation_parameters: Dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    parent_node_ids: List[str] = Field(default_factory=list)
    content_at_node: Optional[str] = None
    node_hash: str = ""

    def model_post_init(self, __context):
        """Compute node hash after initialization."""
        if not self.node_hash and self.content_at_node is not None:
            self.node_hash = content_hash(self.content_at_node)

    def compute_hash(self) -> str:
        """Recompute and return the node hash from current content."""
        if self.content_at_node is not None:
            self.node_hash = content_hash(self.content_at_node)
        return self.node_hash


class ProvenanceChain(BaseModel):
    """A directed acyclic graph of provenance nodes for a single context item."""
    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nodes: List[ProvenanceNode] = Field(default_factory=list)

    @property
    def root_nodes(self) -> List[ProvenanceNode]:
        """Nodes with no parents (original sources)."""
        return [n for n in self.nodes if not n.parent_node_ids]

    @property
    def leaf_node(self) -> Optional[ProvenanceNode]:
        """The most recent node (current state). Returns last node added."""
        return self.nodes[-1] if self.nodes else None

    @property
    def depth(self) -> int:
        """Maximum depth of the DAG."""
        if not self.nodes:
            return 0
        node_map = {n.node_id: n for n in self.nodes}
        depths = {}
        def get_depth(nid):
            if nid in depths:
                return depths[nid]
            node = node_map.get(nid)
            if not node or not node.parent_node_ids:
                depths[nid] = 0
                return 0
            d = 1 + max(get_depth(pid) for pid in node.parent_node_ids)
            depths[nid] = d
            return d
        return max(get_depth(n.node_id) for n in self.nodes)

    @property
    def agent_count(self) -> int:
        """Number of distinct agents in the chain."""
        agents = set()
        for n in self.nodes:
            if n.source_agent:
                agents.add(n.source_agent.agent_id)
        return len(agents)

    @property
    def chain_hash(self) -> str:
        """Hash of all node hashes in order."""
        combined = ":".join(n.node_hash for n in self.nodes if n.node_hash)
        return content_hash(combined) if combined else ""

    def add_node(self, node: ProvenanceNode) -> "ProvenanceChain":
        """Add a node to the chain. Returns self for chaining."""
        self.nodes.append(node)
        return self

    def add_root(
        self,
        source_type: SourceType,
        content: str,
        source_agent: Optional[AgentIdentity] = None,
        source_human_id: Optional[str] = None,
    ) -> ProvenanceNode:
        """Add a root node (original source) to the chain."""
        node = ProvenanceNode(
            source_type=source_type,
            source_agent=source_agent,
            source_human_id=source_human_id,
            transformation=TransformationType.VERBATIM,
            content_at_node=content,
        )
        self.nodes.append(node)
        return node

    def add_transformation(
        self,
        parent_ids: List[str],
        transformation: TransformationType,
        content: str,
        source_agent: Optional[AgentIdentity] = None,
        parameters: Optional[Dict] = None,
    ) -> ProvenanceNode:
        """Add a transformation node derived from parent nodes."""
        node = ProvenanceNode(
            source_type=SourceType.AGENT_INFERENCE,
            source_agent=source_agent,
            transformation=transformation,
            transformation_parameters=parameters or {},
            parent_node_ids=parent_ids,
            content_at_node=content,
        )
        self.nodes.append(node)
        return node
