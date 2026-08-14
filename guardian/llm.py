"""
Airlock AI - Gemini LLM Client

This module is responsible for communicating with Gemini.

IMPORTANT SECURITY RULE:

Only the SANITIZED prompt should ever reach this module.

Example:

    User prompt:
        Write an email to John Doe at john@example.com.

    Safe prompt sent here:
        Write an email to <PERSON_1> at <EMAIL_1>.

The real sensitive values must remain inside Airlock's
local PrivacyVault.

Gemini model:
    gemini-3.5-flash-lite
"""

from __future__ import annotations

import os
from typing import Optional

from dotenv import load_dotenv
from google import genai


# ============================================================
# Load Environment Variables
# ============================================================

load_dotenv()


# ============================================================
# Configuration
# ============================================================

DEFAULT_MODEL = "gemini-3.5-flash-lite"


# ============================================================
# Gemini Client
# ============================================================

class GeminiClient:
    """
    Local wrapper around Google's Gemini API.

    The client accepts ONLY sanitized prompts from the
    Airlock pipeline.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """
        Initialize Gemini client.

        API key priority:

            1. Explicit api_key argument
            2. GEMINI_API_KEY environment variable

        Model priority:

            1. Explicit model argument
            2. GEMINI_MODEL environment variable
            3. gemini-3.5-flash-lite
        """

        self.api_key = (
            api_key
            or os.getenv("GEMINI_API_KEY")
        )

        self.model = (
            model
            or os.getenv(
                "GEMINI_MODEL",
                DEFAULT_MODEL,
            )
        )

        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is not configured. "
                "Add your Gemini API key to the .env file."
            )

        self.client = genai.Client(
            api_key=self.api_key
        )

    # ========================================================
    # Generate Response
    # ========================================================

    def generate(
        self,
        sanitized_prompt: str,
    ) -> str:
        """
        Send a sanitized prompt to Gemini.

        IMPORTANT:

        This method assumes that sensitive information has
        already been removed from the prompt.

        Parameters
        ----------
        sanitized_prompt:
            Prompt containing only safe surrogate tokens.

        Returns
        -------
        str
            Gemini's text response.
        """

        if not isinstance(sanitized_prompt, str):
            raise TypeError(
                "sanitized_prompt must be a string"
            )

        if not sanitized_prompt.strip():
            raise ValueError(
                "sanitized_prompt cannot be empty"
            )

        response = self.client.models.generate_content(
            model=self.model,
            contents=sanitized_prompt,
        )

        text = getattr(response, "text", None)

        if not text:
            raise RuntimeError(
                "Gemini returned an empty response."
            )

        return text.strip()

    # ========================================================
    # Model Information
    # ========================================================

    def get_model(self) -> str:
        """
        Return the currently configured Gemini model.
        """

        return self.model

    # ========================================================
    # Connection Test
    # ========================================================

    def test_connection(self) -> str:
        """
        Perform a small Gemini API test.

        This method is useful during development.

        It sends a completely non-sensitive prompt.
        """

        return self.generate(
            "Reply with exactly: AIRLOCK_GEMINI_OK"
        )

    # ========================================================
    # Safe Representation
    # ========================================================

    def __repr__(self) -> str:
        """
        Never expose the API key in logs.
        """

        return (
            f"GeminiClient("
            f"model='{self.model}'"
            f")"
        )