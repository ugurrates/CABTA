"""Adapters for external security tools without native MCP support."""

from .sandbox_adapter import (
    SandboxAdapter,
    CAPEv2Adapter,
    HybridAnalysisAdapter,
    ANYRUNAdapter,
)

__all__ = [
    "SandboxAdapter",
    "CAPEv2Adapter",
    "HybridAnalysisAdapter",
    "ANYRUNAdapter",
]
