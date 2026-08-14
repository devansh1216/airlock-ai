"""
Airlock AI - Security Policy

This module decides how Airlock AI should handle a prompt
after sensitive information has been detected.

The policy layer does NOT:
    - call Gemini
    - access the internet
    - modify the user's prompt
    - store sensitive information

Its responsibility is simply to make a security decision.

Possible decisions:

    ALLOW
        No sensitive information was detected.

    SANITIZE
        Sensitive information was detected, but the prompt
        can safely continue after local redaction.

    BLOCK
        The request contains information that Airlock should
        not send to the external LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from guardian.detector import Detection


# ============================================================
# Policy Decisions
# ============================================================

class PolicyDecision(str, Enum):
    """
    Possible security decisions.
    """

    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


# ============================================================
# Policy Result
# ============================================================

@dataclass
class PolicyResult:
    """
    Result returned by the security policy engine.
    """

    decision: PolicyDecision
    reason: str
    detections: List[Detection]
    blocked_types: List[str]

    @property
    def allowed(self) -> bool:
        """
        Return True when the request can continue.
        """

        return self.decision != PolicyDecision.BLOCK

    @property
    def requires_sanitization(self) -> bool:
        """
        Return True when sensitive information was detected
        and the prompt should be sanitized.
        """

        return self.decision == PolicyDecision.SANITIZE

    def to_dict(self) -> dict:
        """
        Convert the result to a JSON-friendly dictionary.
        """

        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "allowed": self.allowed,
            "requires_sanitization": self.requires_sanitization,
            "blocked_types": self.blocked_types,
            "detections": [
                detection.to_dict()
                for detection in self.detections
            ],
        }


# ============================================================
# Security Policy
# ============================================================

class SecurityPolicy:
    """
    Airlock AI security policy engine.

    By default, Airlock sanitizes detected PII instead of
    blocking the user's request.

    Only explicitly blocked data types cause a BLOCK decision.

    This makes the system useful for normal business tasks
    such as:

        "Write an email to John Doe at john@example.com."

    The prompt becomes:

        "Write an email to <PERSON_1> at <EMAIL_1>."

    and continues to Gemini.
    """

    DEFAULT_BLOCKED_TYPES = {
        "AWS_ACCESS_KEY",
    }

    DEFAULT_SANITIZE_TYPES = {
        "PERSON",
        "EMAIL",
        "PHONE",
        "CREDIT_CARD",
        "IP_ADDRESS",
        "URL",
        "UUID",
        "API_KEY",
        "AWS_ACCESS_KEY",
        "ORGANIZATION",
        "LOCATION",
    }

    def __init__(
        self,
        blocked_types: Optional[set[str]] = None,
        sanitize_types: Optional[set[str]] = None,
    ):
        """
        Initialize the security policy.

        Parameters
        ----------
        blocked_types:
            Types that should immediately block a request.

        sanitize_types:
            Types that should be replaced with secure tokens.
        """

        self.blocked_types = (
            set(blocked_types)
            if blocked_types is not None
            else set(self.DEFAULT_BLOCKED_TYPES)
        )

        self.sanitize_types = (
            set(sanitize_types)
            if sanitize_types is not None
            else set(self.DEFAULT_SANITIZE_TYPES)
        )

    # ========================================================
    # Evaluate Prompt
    # ========================================================

    def evaluate(
        self,
        detections: List[Detection],
    ) -> PolicyResult:
        """
        Evaluate a list of detections.

        Decision logic:

            No detections
                → ALLOW

            Blocked sensitive type detected
                → BLOCK

            Other sensitive information detected
                → SANITIZE
        """

        if not detections:

            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reason="No sensitive information detected.",
                detections=[],
                blocked_types=[],
            )

        detected_types = {
            detection.data_type.upper()
            for detection in detections
        }

        blocked = sorted(
            detected_types.intersection(
                self.blocked_types
            )
        )

        if blocked:

            return PolicyResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    "The prompt contains sensitive data types "
                    "that Airlock policy does not allow to be "
                    "sent to the external AI service."
                ),
                detections=detections,
                blocked_types=blocked,
            )

        sanitizable = detected_types.intersection(
            self.sanitize_types
        )

        if sanitizable:

            return PolicyResult(
                decision=PolicyDecision.SANITIZE,
                reason=(
                    "Sensitive information was detected and "
                    "will be replaced with local surrogate "
                    "tokens before the prompt is sent."
                ),
                detections=detections,
                blocked_types=[],
            )

        # If an unknown detection type appears, the safest
        # default is to sanitize rather than expose it.
        return PolicyResult(
            decision=PolicyDecision.SANITIZE,
            reason=(
                "Sensitive information was detected. "
                "Airlock will sanitize it before transmission."
            ),
            detections=detections,
            blocked_types=[],
        )

    # ========================================================
    # Convenience Method
    # ========================================================

    def check(
        self,
        detections: List[Detection],
    ) -> bool:
        """
        Simple security check.

        Returns:

            True
                Request may continue.

            False
                Request must be blocked.
        """

        result = self.evaluate(detections)

        return result.allowed