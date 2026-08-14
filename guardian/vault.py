"""
Airlock AI - Local Privacy Vault

The PrivacyVault maintains a local mapping between
sensitive values and safe surrogate tokens.

Example:

    Original value:
        John Doe

    Token:
        <PERSON_1>

    Vault:
        <PERSON_1> -> John Doe

The vault is local to the Airlock process.

IMPORTANT:
    This module never sends vault data to Gemini or any
    other external service.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional


# ============================================================
# Vault Entry
# ============================================================

@dataclass
class VaultEntry:
    """
    Represents one protected value stored in the vault.
    """

    token: str
    data_type: str
    original_value: str

    def to_dict(self) -> dict:
        """
        Return a safe representation of the vault entry.

        The original value is intentionally NOT included.

        This prevents accidental exposure if vault metadata
        is returned to the frontend.
        """

        return {
            "token": self.token,
            "type": self.data_type,
        }


# ============================================================
# Privacy Vault
# ============================================================

class PrivacyVault:
    """
    Local reversible token vault.

    Example:

        vault = PrivacyVault()

        token = vault.store(
            "PERSON",
            "John Doe"
        )

        print(token)

        # <PERSON_1>

        print(vault.restore(token))

        # John Doe
    """

    def __init__(self):
        """
        Initialize an empty vault.
        """

        # token -> VaultEntry
        self._token_to_entry: Dict[str, VaultEntry] = {}

        # (data_type, original_value) -> token
        #
        # This prevents the same value from receiving multiple
        # tokens within the same request.
        self._value_to_token: Dict[tuple, str] = {}

        # Counters used to generate tokens.
        #
        # Example:
        #
        # PERSON -> 1
        # PERSON -> 2
        # EMAIL  -> 1
        self._counters: Dict[str, int] = {}

    # ========================================================
    # Token Normalization
    # ========================================================

    @staticmethod
    def _normalize_type(data_type: str) -> str:
        """
        Normalize the sensitive-data type.

        Example:

            "person" -> "PERSON"
            "email"  -> "EMAIL"
        """

        if not isinstance(data_type, str):
            raise TypeError("data_type must be a string")

        normalized = data_type.strip().upper()

        if not normalized:
            raise ValueError("data_type cannot be empty")

        return normalized

    # ========================================================
    # Generate Token
    # ========================================================

    def _generate_token(self, data_type: str) -> str:
        """
        Generate a unique token.

        Example:

            <PERSON_1>
            <PERSON_2>
            <EMAIL_1>
        """

        counter = self._counters.get(data_type, 0) + 1

        self._counters[data_type] = counter

        return f"<{data_type}_{counter}>"

    # ========================================================
    # Store Sensitive Value
    # ========================================================

    def store(
        self,
        data_type: str,
        original_value: str,
    ) -> str:
        """
        Store a sensitive value and return its token.

        If the exact same value has already been stored for
        the same data type, the existing token is returned.

        Example:

            vault.store("PERSON", "John Doe")

            -> <PERSON_1>
        """

        data_type = self._normalize_type(data_type)

        if not isinstance(original_value, str):
            raise TypeError("original_value must be a string")

        if not original_value:
            raise ValueError("original_value cannot be empty")

        lookup_key = (
            data_type,
            original_value,
        )

        # Reuse an existing token when the same value appears
        # multiple times in the prompt.
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

    # ========================================================
    # Retrieve Original Value
    # ========================================================

    def restore(self, token: str) -> Optional[str]:
        """
        Convert a token back to the original sensitive value.

        Example:

            vault.restore("<PERSON_1>")

            -> "John Doe"

        Returns None if the token is unknown.
        """

        entry = self._token_to_entry.get(token)

        if entry is None:
            return None

        return entry.original_value

    # ========================================================
    # Restore Entire Text
    # ========================================================

    def rehydrate(self, text: str) -> str:
        """
        Replace all known tokens in a text with their original
        sensitive values.

        Example:

            Input:
                "Dear <PERSON_1>, contact <EMAIL_1>."

            Output:
                "Dear John Doe, contact john@example.com."
        """

        if not isinstance(text, str):
            raise TypeError("text must be a string")

        if not text:
            return text

        result = text

        # Replace longer tokens first. This prevents accidental
        # partial replacement if token formats ever become
        # more complex.
        entries = sorted(
            self._token_to_entry.values(),
            key=lambda entry: len(entry.token),
            reverse=True,
        )

        for entry in entries:

            result = result.replace(
                entry.token,
                entry.original_value,
            )

        return result

    # ========================================================
    # Check Token
    # ========================================================

    def contains_token(self, token: str) -> bool:
        """
        Return True if the token exists in the vault.
        """

        return token in self._token_to_entry

    # ========================================================
    # Get Entry
    # ========================================================

    def get_entry(self, token: str) -> Optional[VaultEntry]:
        """
        Return the VaultEntry for a token.

        Returns None if the token does not exist.
        """

        return self._token_to_entry.get(token)

    # ========================================================
    # Safe Metadata
    # ========================================================

    def get_safe_entries(self) -> list:
        """
        Return vault metadata without exposing original values.

        This is safe to send to the frontend for demonstration
        purposes.

        Example:

            [
                {
                    "token": "<PERSON_1>",
                    "type": "PERSON"
                },
                {
                    "token": "<EMAIL_1>",
                    "type": "EMAIL"
                }
            ]
        """

        return [
            entry.to_dict()
            for entry in self._token_to_entry.values()
        ]

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        """
        Return the number of unique protected values.
        """

        return len(self._token_to_entry)

    # ========================================================
    # Clear
    # ========================================================

    def clear(self) -> None:
        """
        Completely clear the vault.

        This should normally be called when a request/session
        has finished if the vault is being used per request.
        """

        self._token_to_entry.clear()
        self._value_to_token.clear()
        self._counters.clear()

    # ========================================================
    # Debug Representation
    # ========================================================

    def __repr__(self) -> str:
        """
        Return a safe representation.

        IMPORTANT:
            Original sensitive values are intentionally not
            printed.
        """

        return (
            f"PrivacyVault("
            f"entries={self.size()}"
            f")"
        )