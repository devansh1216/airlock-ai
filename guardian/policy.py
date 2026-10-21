"""
Airlock AI - Security Policy Engine

This module decides how Airlock AI handles detected sensitive information:
    - ALLOW: Pass through to cloud AI without modification
    - SANITIZE: Replace with local surrogate tokens, restore locally after LLM responds
    - BLOCK: Reject the request immediately (e.g. for hard credentials / AWS keys)

The policy can be dynamically updated at runtime via the API/Frontend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from guardian.detector import Detection


class PolicyDecision(str, Enum):
    """Possible security decisions."""
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


@dataclass
class PolicyResult:
    """Result returned by the security policy engine."""
    decision: PolicyDecision
    reason: str
    detections: List[Detection]
    blocked_types: List[str]
    sanitized_types: List[str] = field(default_factory=list)
    allowed_types: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """Return True when the request is permitted to proceed."""
        return self.decision != PolicyDecision.BLOCK

    @property
    def requires_sanitization(self) -> bool:
        """Return True when sensitive information must be replaced with surrogate tokens."""
        return self.decision == PolicyDecision.SANITIZE

    def to_dict(self) -> dict:
        """Convert the result to a JSON-friendly dictionary."""
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "allowed": self.allowed,
            "requires_sanitization": self.requires_sanitization,
            "blocked_types": self.blocked_types,
            "sanitized_types": self.sanitized_types,
            "allowed_types": self.allowed_types,
            "detections": [d.to_dict() for d in self.detections],
        }


class SecurityPolicy:
    """
    Configurable security policy engine.
    """

    DEFAULT_BLOCKED_TYPES: Set[str] = {
        "AWS_ACCESS_KEY",
        "API_KEY",
    }

    DEFAULT_SANITIZE_TYPES: Set[str] = {
        "PERSON",
        "EMAIL",
        "PHONE",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "NATIONAL_ID",
        "ORGANIZATION",
        "LOCATION",
        "UUID",
    }

    DEFAULT_ALLOW_TYPES: Set[str] = {
        "URL",
    }

    ALL_KNOWN_TYPES: List[str] = [
        "PERSON",
        "EMAIL",
        "PHONE",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "NATIONAL_ID",
        "ORGANIZATION",
        "LOCATION",
        "API_KEY",
        "AWS_ACCESS_KEY",
        "URL",
        "UUID",
    ]

    def __init__(
        self,
        blocked_types: Optional[Set[str]] = None,
        sanitize_types: Optional[Set[str]] = None,
        allow_types: Optional[Set[str]] = None,
    ):
        self.blocked_types: Set[str] = (
            set(blocked_types) if blocked_types is not None else set(self.DEFAULT_BLOCKED_TYPES)
        )
        self.sanitize_types: Set[str] = (
            set(sanitize_types) if sanitize_types is not None else set(self.DEFAULT_SANITIZE_TYPES)
        )
        self.allow_types: Set[str] = (
            set(allow_types) if allow_types is not None else set(self.DEFAULT_ALLOW_TYPES)
        )

    def update_rules(
        self,
        blocked: Optional[List[str]] = None,
        sanitize: Optional[List[str]] = None,
        allow: Optional[List[str]] = None,
    ) -> None:
        """Update active policy rules at runtime."""
        if blocked is not None:
            self.blocked_types = {t.upper().strip() for t in blocked if t.strip()}
        if sanitize is not None:
            self.sanitize_types = {t.upper().strip() for t in sanitize if t.strip()}
        if allow is not None:
            self.allow_types = {t.upper().strip() for t in allow if t.strip()}

    def get_config(self) -> Dict[str, dict]:
        """Return the current rule configuration for each known type."""
        config = {}
        for t in self.ALL_KNOWN_TYPES:
            if t in self.blocked_types:
                mode = "BLOCK"
            elif t in self.allow_types:
                mode = "ALLOW"
            else:
                mode = "SANITIZE"
            config[t] = {
                "type": t,
                "action": mode,
            }
        return config

    def evaluate(self, detections: List[Detection]) -> PolicyResult:
        """
        Evaluate a list of detections against the active policy.
        """
        if not detections:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reason="No sensitive information detected in prompt.",
                detections=[],
                blocked_types=[],
            )

        detected_types = {d.data_type.upper() for d in detections}

        # Check for any blocked types
        blocked = sorted(detected_types.intersection(self.blocked_types))
        if blocked:
            return PolicyResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Prompt contains strictly blocked credential/secret types ({', '.join(blocked)}). "
                    f"Airlock AI blocked transmission to prevent credential leakage."
                ),
                detections=detections,
                blocked_types=blocked,
            )

        # Check for types requiring sanitization
        sanitizable = sorted(detected_types.intersection(self.sanitize_types))
        allowed = sorted(detected_types.intersection(self.allow_types))

        # Filter out detections that are explicitly allowed so they are not replaced
        active_detections = [
            d for d in detections if d.data_type.upper() not in self.allow_types
        ]

        if active_detections:
            return PolicyResult(
                decision=PolicyDecision.SANITIZE,
                reason=(
                    f"Detected sensitive entities ({', '.join(sanitizable)}). "
                    f"Airlock AI will sanitize these with surrogate tokens before transmission."
                ),
                detections=active_detections,
                blocked_types=[],
                sanitized_types=sanitizable,
                allowed_types=allowed,
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="All detected entities match policy ALLOW rules. Prompt sent safely.",
            detections=[],
            blocked_types=[],
            allowed_types=allowed,
        )

    def check(self, detections: List[Detection]) -> bool:
        """Convenience check: True if permitted to proceed."""
        return self.evaluate(detections).allowed
