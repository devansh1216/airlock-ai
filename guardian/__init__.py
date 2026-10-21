"""
Airlock AI Guardian Security Package

Core privacy & security middleware components:
- SensitiveDataDetector: Hybrid Regex + spaCy NER with false-positive suppression
- SecurityPolicy: Granular ALLOW / SANITIZE / BLOCK enforcement
- PrivacyVault: In-memory reversible surrogate tokenization
- GeminiClient: Async LLM gateway with streaming and sandbox support
"""

from guardian.detector import Detection, SensitiveDataDetector, SuppressedEntity
from guardian.llm import GeminiClient
from guardian.policy import PolicyDecision, PolicyResult, SecurityPolicy
from guardian.vault import PrivacyVault, VaultEntry

__all__ = [
    "SensitiveDataDetector",
    "Detection",
    "SuppressedEntity",
    "SecurityPolicy",
    "PolicyDecision",
    "PolicyResult",
    "PrivacyVault",
    "VaultEntry",
    "GeminiClient",
]
