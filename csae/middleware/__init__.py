"""CSAE middleware: drop-in attestation for agent frameworks."""

from .mcp import MCPAttestor

__all__ = ["MCPAttestor"]
