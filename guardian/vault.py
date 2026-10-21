"""
Airlock AI - In-Memory Cryptographic Privacy Vault

The PrivacyVault maintains a localized, in-memory reversible mapping
between sensitive values and safe surrogate tokens.

Example:
    Original:   Rahul Sharma
    Token:      <PERSON_1>
    Vault:      <PERSON_1> <-> Rahul Sharma

IMPORTANT SECURITY PROPERTIES:
    1. Zero External Leakage: Vault data is strictly local to the Airlock process.
    2. Zero Persistence: Vault entries can be zeroized immediately after request completion.
    3. Reversible: The cloud model only interacts with <TYPE_INDEX>; final output
       is reconstructed locally in milliseconds.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def mask_sensitive_value(val: str, data_type: str) -> str:
    """
    Produce a safe masked preview for local inspection in the UI
    without exposing full sensitive data.
    """
    if not val:
        return ""
    val_clean = val.strip()
    if data_type == "EMAIL" and "@" in val_clean:
        user, domain = val_clean.split("@", 1)
        masked_user = user[0] + "***" if len(user) > 1 else "***"
        return f"{masked_user}@{domain}"
    if data_type in {"PHONE", "CREDIT_CARD", "NATIONAL_ID"}:
        digits = re.sub(r"\D", "", val_clean)
        last4 = digits[-4:] if len(digits) >= 4 else digits
        return f"***-***-{last4}"
    if len(val_clean) <= 3:
        return val_clean[0] + "***"
    return f"{val_clean[:2]}***{val_clean[-1]}"


@dataclass
class VaultEntry:
    """Represents one protected value inside the Privacy Vault."""
    token: str
    data_type: str
    original_value: str
    created_at: float = field(default_factory=time.time)

    def to_safe_dict(self) -> dict:
        """Safe representation for UI inspection without exposing full secrets."""
        return {
            "token": self.token,
            "type": self.data_type,
            "masked_value": mask_sensitive_value(self.original_value, self.data_type),
            "created_at": round(self.created_at, 2),
            "char_length": len(self.original_value),
        }


class PrivacyVault:
    """
    In-Memory Reversible Token Vault.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id: str = session_id or f"vault-{int(time.time()*1000)}"
        self._token_to_entry: Dict[str, VaultEntry] = {}
        self._value_to_token: Dict[Tuple[str, str], str] = {}
        self._counters: Dict[str, int] = {}
        self.created_at: float = time.time()

    @staticmethod
    def _normalize_type(data_type: str) -> str:
        if not isinstance(data_type, str):
            raise TypeError("data_type must be a string")
        normalized = data_type.strip().upper()
        if not normalized:
            raise ValueError("data_type cannot be empty")
        return normalized

    def _generate_token(self, data_type: str) -> str:
        counter = self._counters.get(data_type, 0) + 1
        self._counters[data_type] = counter
        return f"<{data_type}_{counter}>"

    def store(self, data_type: str, original_value: str) -> str:
        """
        Store a sensitive value and return its surrogate token.
        Reuses existing token if same value was already encountered.
        """
        data_type = self._normalize_type(data_type)
        if not isinstance(original_value, str):
            raise TypeError("original_value must be a string")
        if not original_value:
            raise ValueError("original_value cannot be empty")

        lookup_key = (data_type, original_value)
        existing_token = self._value_to_token.get(lookup_key)
        if existing_token:
            return existing_token

        token = self._generate_token(data_type)
        entry = VaultEntry(
            token=token,
            data_type=data_type,
            original_value=original_value,
        )

        self._token_to_entry[token] = entry
        self._value_to_token[lookup_key] = token
        return token

    def restore(self, token: str) -> Optional[str]:
        """Convert a single token back to the original value."""
        entry = self._token_to_entry.get(token)
        return entry.original_value if entry else None

    def rehydrate(self, text: str) -> str:
        """
        Replace all known surrogate tokens with original values.
        Sorts by token length descending to prevent partial token replacement collisions.
        """
        if not isinstance(text, str) or not text:
            return text

        result = text
        entries = sorted(
            self._token_to_entry.values(),
            key=lambda e: len(e.token),
            reverse=True,
        )

        for entry in entries:
            # Direct string replace of token
            result = result.replace(entry.token, entry.original_value)

        return result

    def get_safe_entries(self) -> List[dict]:
        """Return safe vault entries for UI inspection."""
        return [entry.to_safe_dict() for entry in self._token_to_entry.values()]

    def size(self) -> int:
        """Number of unique protected values."""
        return len(self._token_to_entry)

    def clear(self) -> None:
        """Zero out vault contents from memory."""
        self._token_to_entry.clear()
        self._value_to_token.clear()
        self._counters.clear()

    def __repr__(self) -> str:
        return f"PrivacyVault(session='{self.session_id}', entries={self.size()})"
