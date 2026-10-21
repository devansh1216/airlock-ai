"""
Airlock AI - High-Precision Sensitive Data Detector

This module detects sensitive information locally using:
    1. Regular Expressions (Emails, Phones, Cards, IPs, Secrets, National IDs)
    2. spaCy Named Entity Recognition (Persons, Organizations, Locations)
    3. Context-Aware False-Positive Suppression (eliminates false positives like
       "Flask" or "Python" falsely classified as GPE/Location or Person)
    4. Structural Checksum Validation (Luhn algorithm for Credit Cards)
    5. Custom Runtime Allowlists and Regex Patterns

IMPORTANT:
    This module runs 100% locally. No user text or entity metadata
    leaves the local machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

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
    confidence: float = 1.0

    def to_dict(self) -> dict:
        """Convert the detection to a JSON-friendly dictionary."""
        return {
            "type": self.data_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "source": self.source,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class SuppressedEntity:
    """
    Represents an entity flagged by raw NER but filtered out
    by the false-positive mitigation engine.
    """

    value: str
    raw_type: str
    source: str
    reason: str

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "raw_type": self.raw_type,
            "source": self.source,
            "reason": self.reason,
        }


# ============================================================
# Luhn Algorithm Check for Credit Cards
# ============================================================

def is_luhn_valid(number_str: str) -> bool:
    """
    Validate credit/debit card numbers using the standard Luhn algorithm.
    Prevents random 16-digit order IDs or numbers from being treated as cards.
    """
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ============================================================
# Sensitive Data Detector
# ============================================================

class SensitiveDataDetector:
    """
    High-precision sensitive data detector combining Regex, spaCy NER,
    and rule-based false-positive suppression.
    """

    # --------------------------------------------------------
    # Curated Tech & Common Vocabulary Allowlist
    # Prevents spaCy from misclassifying frameworks/languages as
    # Locations (GPE), Organizations, or Persons.
    # --------------------------------------------------------
    TECH_ALLOWLIST: Set[str] = {
        # Python ecosystem
        "flask", "fastapi", "django", "python", "py", "pip", "pytest", "numpy",
        "pandas", "spacy", "scikit-learn", "torch", "pytorch", "tensorflow", "keras",
        "uvicorn", "gunicorn", "celery", "pydantic", "sqlalchemy", "starlette", "jinja",

        # JavaScript / Web ecosystem
        "javascript", "typescript", "node", "nodejs", "npm", "yarn", "pnpm", "react",
        "vue", "angular", "svelte", "nextjs", "express", "tailwind", "bootstrap",
        "html", "css", "sass", "webpack", "vite", "deno", "bun",

        # Languages & Systems
        "java", "c", "c++", "c#", "rust", "golang", "go", "ruby", "php", "swift",
        "kotlin", "scala", "dart", "bash", "powershell", "zsh", "sql", "nosql",

        # Databases & Infrastructure
        "postgresql", "postgres", "mysql", "mongodb", "sqlite", "redis", "elasticsearch",
        "docker", "kubernetes", "k8s", "linux", "ubuntu", "debian", "alpine",
        "windows", "macos", "nginx", "apache", "kafka", "rabbitmq", "grafana",

        # Cloud & Protocols
        "aws", "azure", "gcp", "cloudflare", "vercel", "heroku", "github", "gitlab",
        "rest", "graphql", "grpc", "http", "https", "tcp", "udp", "ssh", "json",
        "yaml", "xml", "csv", "jwt", "oauth", "api", "sdk", "cli", "ide",

        # AI & Model Names
        "gemini", "openai", "claude", "anthropic", "chatgpt", "gpt", "llama",
        "mistral", "airlock", "airlock ai",
    }

    # Common English words/days/months that are capitalized at sentence start
    # or headers and often falsely tagged by statistical NER.
    COMMON_WORDS_ALLOWLIST: Set[str] = {
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
        "january", "february", "march", "april", "may", "june", "july", "august",
        "september", "october", "november", "december",
        "hello", "hi", "hey", "dear", "sincerely", "regards", "best regards", "thanks",
        "thank you", "please", "summary", "error", "warning", "bug", "issue", "test",
        "feature", "task", "project", "code", "question", "answer", "documentation",
        "english", "spanish", "french", "german", "hindi", "japanese", "chinese",
    }

    def __init__(
        self,
        model_name: str = "en_core_web_sm",
        custom_allowlist: Optional[Set[str]] = None,
    ):
        """
        Initialize the detector with spaCy and regex patterns.
        """
        try:
            self.nlp = spacy.load(model_name)
        except OSError as exc:
            raise RuntimeError(
                f"spaCy model '{model_name}' is not installed.\n"
                f"Run: pip install en_core_web_sm"
            ) from exc

        self.regex_patterns = self._build_regex_patterns()
        self.custom_allowlist: Set[str] = {
            w.strip().lower() for w in (custom_allowlist or set()) if w.strip()
        }
        self.custom_regex_patterns: Dict[str, re.Pattern] = {}

    # ========================================================
    # Regex Patterns
    # ========================================================

    def _build_regex_patterns(self) -> Dict[str, re.Pattern]:
        """
        Build compiled regex patterns for structured PII.
        """
        return {
            # Email
            "EMAIL": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                re.IGNORECASE,
            ),

            # Phone numbers (Indian, US/CA, International E.164)
            "PHONE": re.compile(
                r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?!\d)"
            ),

            # Credit/Debit Card (Validated further with Luhn check)
            "CREDIT_CARD": re.compile(
                r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}(?!\d)"
            ),

            # IPv4 Address
            "IP_ADDRESS": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
            ),

            # URLs
            "URL": re.compile(
                r"\b(?:https?://|ftps?://|www\.)[^\s<>\"]+",
                re.IGNORECASE,
            ),

            # UUIDs
            "UUID": re.compile(
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
            ),

            # API Keys, Tokens & Secrets (OpenAI, GitHub, Google, Slack, Anthropic, JWT)
            "API_KEY": re.compile(
                r"\b(?:"
                r"sk-proj-[A-Za-z0-9_-]{20,}|"
                r"sk-[A-Za-z0-9_-]{20,}|"
                r"AIzaSy[A-Za-z0-9_-]{33}|"
                r"ghp_[A-Za-z0-9]{36}|"
                r"gho_[A-Za-z0-9]{36}|"
                r"glpat-[A-Za-z0-9_-]{20,}|"
                r"xox[baprs]-[A-Za-z0-9-]{10,}|"
                r"sk-ant-[A-Za-z0-9_-]{20,}|"
                r"Bearer\s+[A-Za-z0-9\._-]{20,}|"
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                r")\b"
            ),

            # AWS Access Key ID
            "AWS_ACCESS_KEY": re.compile(
                r"\bAKIA[0-9A-Z]{16}\b"
            ),

            # National Identification Numbers (US SSN or Indian Aadhaar format)
            "NATIONAL_ID": re.compile(
                r"\b(?:\d{3}-\d{2}-\d{4}|\d{4}\s\d{4}\s\d{4})\b"
            ),
        }

    # ========================================================
    # Custom Rules Management
    # ========================================================

    def add_allowlist_term(self, term: str) -> None:
        """Add a term to the runtime allowlist (never redacted)."""
        if term and isinstance(term, str):
            self.custom_allowlist.add(term.strip().lower())

    def remove_allowlist_term(self, term: str) -> None:
        """Remove a term from the runtime allowlist."""
        self.custom_allowlist.discard(term.strip().lower())

    def add_custom_pattern(self, name: str, pattern: str) -> None:
        """Add a custom regex detection pattern."""
        self.custom_regex_patterns[name.upper()] = re.compile(pattern)

    # ========================================================
    # False-Positive Verification
    # ========================================================

    def _is_false_positive(
        self,
        value: str,
        data_type: str,
        context_doc,
        start_char: int,
        end_char: int,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify whether an entity detected by raw NER is a false positive.
        Returns (is_false_positive, reason).
        """
        val_lower = value.strip().lower()

        # 1. Custom allowlist check
        if val_lower in self.custom_allowlist:
            return True, f"Term '{value}' is in user-configured allowlist"

        # 2. Technology / framework allowlist (SOLVES "Flask as LOCATION" issue!)
        if val_lower in self.TECH_ALLOWLIST:
            return True, f"Technology/framework term '{value}' suppressed from {data_type} redaction"

        # 3. Common English words / days / months
        if val_lower in self.COMMON_WORDS_ALLOWLIST:
            return True, f"Common word/calendar term '{value}' suppressed from {data_type} redaction"

        # 4. PERSON specific heuristic validation
        if data_type == "PERSON":
            words = value.strip().split()
            # If it's a single word with no title and in lower case or standard dictionary word
            if len(words) == 1:
                # Check preceding token in spaCy doc for honorifics (Dr., Mr., Ms., etc.)
                span = context_doc.char_span(start_char, end_char)
                has_honorific = False
                if span and span.start > 0:
                    prev_token = context_doc[span.start - 1].text.lower().rstrip(".")
                    if prev_token in {"mr", "mrs", "ms", "miss", "dr", "prof", "shri", "smt"}:
                        has_honorific = True

                # If single word without honorific and under 3 letters
                if not has_honorific and len(value) <= 2:
                    return True, f"Single short word '{value}' lacks Person confidence"

        # 5. LOCATION specific validation
        if data_type == "LOCATION":
            # If it's all lowercase in prompt and matches common noun
            if value.islower() and val_lower in {"home", "office", "desk", "room", "floor", "server", "cloud"}:
                return True, f"Generic location noun '{value}' suppressed"

        return False, None

    # ========================================================
    # Regex Detection
    # ========================================================

    def _detect_with_regex(self, text: str) -> List[Detection]:
        """Detect structured sensitive data using Regex."""
        detections: List[Detection] = []

        # Standard patterns
        for data_type, pattern in self.regex_patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)

                # Special filter for PHONE to avoid short numeric noise
                if data_type == "PHONE":
                    digits_only = re.sub(r"\D", "", value)
                    if len(digits_only) < 7 or len(digits_only) > 15:
                        continue

                # Special filter for CREDIT_CARD: check with Luhn algorithm
                if data_type == "CREDIT_CARD":
                    if not is_luhn_valid(value):
                        # Not a valid credit card number; ignore false positive
                        continue

                # Confidence assignment
                confidence = 0.99 if data_type in {"EMAIL", "AWS_ACCESS_KEY", "UUID"} else 0.92

                detections.append(
                    Detection(
                        data_type=data_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                        source="regex",
                        confidence=confidence,
                    )
                )

        # Custom user patterns
        for data_type, pattern in self.custom_regex_patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                detections.append(
                    Detection(
                        data_type=data_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                        source="custom_regex",
                        confidence=0.95,
                    )
                )

        return detections

    # ========================================================
    # spaCy Detection with False-Positive Filtering
    # ========================================================

    def _detect_with_spacy(
        self, text: str
    ) -> Tuple[List[Detection], List[SuppressedEntity]]:
        """
        Detect people, organizations, and locations using spaCy NER,
        while filtering out false positives.
        """
        detections: List[Detection] = []
        suppressed: List[SuppressedEntity] = []

        doc = self.nlp(text)

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

            target_type = sensitive_labels[entity.label_]

            # Validate against false positives
            is_fp, reason = self._is_false_positive(
                value=value,
                data_type=target_type,
                context_doc=doc,
                start_char=entity.start_char,
                end_char=entity.end_char,
            )

            if is_fp:
                suppressed.append(
                    SuppressedEntity(
                        value=value,
                        raw_type=target_type,
                        source="spacy",
                        reason=reason or "Suppressed by false-positive heuristics",
                    )
                )
                continue

            # Confidence estimate
            confidence = 0.90 if target_type == "PERSON" else 0.85

            detections.append(
                Detection(
                    data_type=target_type,
                    value=value,
                    start=entity.start_char,
                    end=entity.end_char,
                    source="spacy",
                    confidence=confidence,
                )
            )

        return detections, suppressed

    # ========================================================
    # Overlap Resolution
    # ========================================================

    @staticmethod
    def _remove_overlapping_detections(
        detections: List[Detection],
    ) -> List[Detection]:
        """
        Deduplicate and resolve overlapping detections.
        Prefers longer matches and regex over NER for structured formats.
        """
        if not detections:
            return []

        # Sort: earlier start first; if start is equal, longer match first.
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
                if current.start < existing.end and current.end > existing.start:
                    overlaps = True
                    break

            if not overlaps:
                accepted.append(current)

        accepted.sort(key=lambda item: item.start)
        return accepted

    # ========================================================
    # Public API
    # ========================================================

    def detect(self, text: str) -> List[Detection]:
        """
        Detect sensitive information and return active detections.
        """
        if not isinstance(text, str) or not text.strip():
            return []

        regex_detections = self._detect_with_regex(text)
        spacy_detections, _ = self._detect_with_spacy(text)

        all_detections = regex_detections + spacy_detections
        return self._remove_overlapping_detections(all_detections)

    def detect_with_audit(
        self, text: str
    ) -> Tuple[List[Detection], List[SuppressedEntity]]:
        """
        Detect sensitive information and return BOTH accepted detections
        and suppressed false-positive entities (for inspection in the studio).
        """
        if not isinstance(text, str) or not text.strip():
            return [], []

        regex_detections = self._detect_with_regex(text)
        spacy_detections, suppressed = self._detect_with_spacy(text)

        all_detections = regex_detections + spacy_detections
        accepted = self._remove_overlapping_detections(all_detections)

        return accepted, suppressed

    def redact(
        self,
        text: str,
        token_generator: Callable[[str, str], str],
    ) -> Tuple[str, List[Detection]]:
        """
        Detect sensitive information and replace each value with a surrogate token.
        """
        detections = self.detect(text)
        if not detections:
            return text, []

        redacted_parts = []
        cursor = 0

        for detection in detections:
            redacted_parts.append(text[cursor:detection.start])
            token = token_generator(detection.data_type, detection.value)
            redacted_parts.append(token)
            cursor = detection.end

        redacted_parts.append(text[cursor:])
        redacted_text = "".join(redacted_parts)

        return redacted_text, detections

    @staticmethod
    def count_by_type(detections: List[Detection]) -> Dict[str, int]:
        """Count detected sensitive values by type."""
        counts: Dict[str, int] = {}
        for d in detections:
            counts[d.data_type] = counts.get(d.data_type, 0) + 1
        return counts
