"""
Airlock AI - Sensitive Data Detector

This module detects sensitive information locally using:
    1. Regular Expressions
    2. spaCy Named Entity Recognition

IMPORTANT:
    This module never sends user data to an external service.

The detector identifies sensitive values and returns their:
    - type
    - original value
    - start position
    - end position

Token generation and local storage are handled by vault.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

import spacy


# ============================================================
# Detection Result
# ============================================================

@dataclass
class Detection:
    """
    Represents one piece of sensitive information detected
    inside the user's prompt.
    """

    data_type: str
    value: str
    start: int
    end: int
    source: str = "regex"

    def to_dict(self) -> dict:
        """Convert the detection to a JSON-friendly dictionary."""
        return {
            "type": self.data_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "source": self.source,
        }


# ============================================================
# Sensitive Data Detector
# ============================================================

class SensitiveDataDetector:
    """
    Detects sensitive information locally using Regex and spaCy.

    Supported Regex detections:
        - Email addresses
        - Phone numbers
        - Credit/debit card numbers
        - IPv4 addresses
        - URLs
        - API keys / secrets
        - UUIDs

    Supported spaCy detections:
        - PERSON
        - ORGANIZATION
        - GPE / LOCATION
    """

    def __init__(self, model_name: str = "en_core_web_sm"):
        """
        Load the spaCy model.

        The model runs completely locally.
        """

        try:
            self.nlp = spacy.load(model_name)
        except OSError as exc:
            raise RuntimeError(
                f"spaCy model '{model_name}' is not installed.\n"
                f"Run:\n"
                f"python -m spacy download {model_name}"
            ) from exc

        self.regex_patterns = self._build_regex_patterns()

    # ========================================================
    # Regex Patterns
    # ========================================================

    def _build_regex_patterns(self) -> dict:
        """
        Create all Regex patterns used by Airlock AI.
        """

        return {

            # ------------------------------------------------
            # Email
            # ------------------------------------------------
            "EMAIL": re.compile(
                r"\b[A-Za-z0-9._%+-]+@"
                r"[A-Za-z0-9.-]+\."
                r"[A-Za-z]{2,}\b"
            ),

            # ------------------------------------------------
            # Phone
            #
            # Supports examples such as:
            # +91 9876543210
            # +91-9876543210
            # 9876543210
            # +1 415 555 2671
            # ------------------------------------------------
            "PHONE": re.compile(
                r"(?<!\d)"
                r"(?:\+\d{1,3}[\s.-]?)?"
                r"(?:\(?\d{2,4}\)?[\s.-]?)?"
                r"\d{3,4}[\s.-]?\d{3,4}"
                r"(?!\d)"
            ),

            # ------------------------------------------------
            # Credit / Debit Card
            #
            # Supports:
            # 4111 1111 1111 1111
            # 4111-1111-1111-1111
            # 4111111111111111
            # ------------------------------------------------
            "CREDIT_CARD": re.compile(
                r"(?<!\d)"
                r"(?:\d{4}[-\s]?){3}\d{4}"
                r"(?!\d)"
            ),

            # ------------------------------------------------
            # IPv4 Address
            # ------------------------------------------------
            "IP_ADDRESS": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|"
                r"1\d\d|[1-9]?\d)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|"
                r"1\d\d|[1-9]?\d)\b"
            ),

            # ------------------------------------------------
            # URL
            # ------------------------------------------------
            "URL": re.compile(
                r"\b(?:https?://|www\.)"
                r"[^\s<>\"]+",
                re.IGNORECASE,
            ),

            # ------------------------------------------------
            # UUID
            # ------------------------------------------------
            "UUID": re.compile(
                r"\b[0-9a-fA-F]{8}-"
                r"[0-9a-fA-F]{4}-"
                r"[1-5][0-9a-fA-F]{3}-"
                r"[89abAB][0-9a-fA-F]{3}-"
                r"[0-9a-fA-F]{12}\b"
            ),

            # ------------------------------------------------
            # Common API keys / secrets
            #
            # This intentionally focuses on common recognizable
            # key formats instead of trying to classify every
            # possible password.
            # ------------------------------------------------
            "API_KEY": re.compile(
                r"\b(?:"
                r"sk-[A-Za-z0-9_-]{16,}"
                r"|"
                r"AIza[A-Za-z0-9_-]{20,}"
                r"|"
                r"ghp_[A-Za-z0-9]{20,}"
                r"|"
                r"glpat-[A-Za-z0-9_-]{20,}"
                r"|"
                r"xox[baprs]-[A-Za-z0-9-]{10,}"
                r")\b"
            ),

            # ------------------------------------------------
            # AWS Access Key ID
            # ------------------------------------------------
            "AWS_ACCESS_KEY": re.compile(
                r"\bAKIA[0-9A-Z]{16}\b"
            ),
        }

    # ========================================================
    # Regex Detection
    # ========================================================

    def _detect_with_regex(self, text: str) -> List[Detection]:
        """
        Detect sensitive information using Regex.
        """

        detections: List[Detection] = []

        for data_type, pattern in self.regex_patterns.items():

            for match in pattern.finditer(text):

                value = match.group(0)

                # Avoid detecting extremely short phone-like
                # values accidentally.
                if data_type == "PHONE":
                    digits_only = re.sub(r"\D", "", value)

                    if len(digits_only) < 7:
                        continue

                detections.append(
                    Detection(
                        data_type=data_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                        source="regex",
                    )
                )

        return detections

    # ========================================================
    # spaCy Detection
    # ========================================================

    def _detect_with_spacy(self, text: str) -> List[Detection]:
        """
        Detect people and organizations using spaCy NER.
        """

        detections: List[Detection] = []

        doc = self.nlp(text)

        # Entities we consider sensitive enough to protect.
        sensitive_labels = {
            "PERSON": "PERSON",
            "ORG": "ORGANIZATION",
            "GPE": "LOCATION",
            "LOC": "LOCATION",
        }

        for entity in doc.ents:

            if entity.label_ not in sensitive_labels:
                continue

            value = entity.text.strip()

            if not value:
                continue

            detections.append(
                Detection(
                    data_type=sensitive_labels[entity.label_],
                    value=value,
                    start=entity.start_char,
                    end=entity.end_char,
                    source="spacy",
                )
            )

        return detections

    # ========================================================
    # Overlap Handling
    # ========================================================

    @staticmethod
    def _remove_overlapping_detections(
        detections: List[Detection],
    ) -> List[Detection]:
        """
        Remove overlapping detections.

        Example:

            john@example.com

        should be detected as EMAIL rather than being
        accidentally treated as multiple overlapping entities.
        """

        if not detections:
            return []

        # Prefer the longer detection when two detections
        # overlap.
        detections = sorted(
            detections,
            key=lambda item: (
                item.start,
                -(item.end - item.start),
            ),
        )

        accepted: List[Detection] = []

        for current in detections:

            overlaps = False

            for existing in accepted:

                if (
                    current.start < existing.end
                    and current.end > existing.start
                ):
                    overlaps = True
                    break

            if not overlaps:
                accepted.append(current)

        # Return them in their original text order.
        accepted.sort(key=lambda item: item.start)

        return accepted

    # ========================================================
    # Public Detection Method
    # ========================================================

    def detect(self, text: str) -> List[Detection]:
        """
        Detect all supported sensitive information.

        Parameters
        ----------
        text:
            User's original prompt.

        Returns
        -------
        List[Detection]
            Sensitive values detected in the prompt.
        """

        if not isinstance(text, str):
            raise TypeError("text must be a string")

        if not text.strip():
            return []

        regex_detections = self._detect_with_regex(text)

        spacy_detections = self._detect_with_spacy(text)

        all_detections = regex_detections + spacy_detections

        return self._remove_overlapping_detections(
            all_detections
        )

    # ========================================================
    # Redaction
    # ========================================================

    def redact(
        self,
        text: str,
        token_generator,
    ) -> tuple[str, List[Detection]]:
        """
        Detect sensitive information and replace each value
        with a token.

        token_generator must be a callable that accepts:

            data_type
            original_value

        and returns a token such as:

            <PERSON_1>
            <EMAIL_1>

        The actual token generation will be implemented in
        vault.py.

        Returns
        -------
        tuple[str, List[Detection]]

        Example:

            Original:
                Email John at john@example.com

            Redacted:
                Email <PERSON_1> at <EMAIL_1>
        """

        detections = self.detect(text)

        if not detections:
            return text, []

        redacted_parts = []

        cursor = 0

        for detection in detections:

            # Add normal text before the sensitive value.
            redacted_parts.append(
                text[cursor:detection.start]
            )

            # Generate a secure surrogate token.
            token = token_generator(
                detection.data_type,
                detection.value,
            )

            redacted_parts.append(token)

            cursor = detection.end

        # Add remaining text.
        redacted_parts.append(text[cursor:])

        redacted_text = "".join(redacted_parts)

        return redacted_text, detections

    # ========================================================
    # Simple Statistics
    # ========================================================

    @staticmethod
    def count_by_type(
        detections: List[Detection],
    ) -> dict:
        """
        Count detected sensitive values by type.

        Example:

            {
                "PERSON": 1,
                "EMAIL": 2,
                "PHONE": 1
            }
        """

        counts = {}

        for detection in detections:

            counts[detection.data_type] = (
                counts.get(detection.data_type, 0) + 1
            )

        return counts