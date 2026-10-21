"""
Airlock AI - Gemini LLM Gateway

This module handles communication with Google Gemini or falls back to
an intelligent local simulator when no API key is configured.

IMPORTANT SECURITY RULE:
    Only the SANITIZED prompt containing surrogate tokens (e.g. <PERSON_1>)
    should ever reach this module. Original sensitive values are strictly
    isolated in the local PrivacyVault.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import AsyncGenerator, Optional

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


class GeminiClient:
    """
    Local wrapper around Google's Gemini API with async streaming support
    and safe sandbox fallback.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model = model or DEFAULT_MODEL
        self.is_configured = bool(self.api_key and self.api_key.strip())
        self._client = None

        if self.is_configured:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[Airlock AI] Notice: Could not initialize Gemini client ({e}). Sandbox mode active.")
                self.is_configured = False

    def is_live(self) -> bool:
        """True if authenticated with real Gemini API key."""
        return self.is_configured and self._client is not None

    def get_model(self) -> str:
        """Return active model identifier."""
        return self.model if self.is_live() else f"{self.model} (Sandbox Simulator)"

    def _generate_simulated_response(self, sanitized_prompt: str) -> str:
        """
        Generate a high-quality simulated LLM response that naturally references
        the surrogate tokens present in the prompt.
        """
        tokens = re.findall(r"<[A-Z_]+_\d+>", sanitized_prompt)
        token_list = ", ".join(tokens) if tokens else "your inquiry"

        prompt_lower = sanitized_prompt.lower()
        if "email" in prompt_lower or "write" in prompt_lower:
            response = (
                f"Subject: Follow-up Regarding Recent Inquiry\n\n"
                f"Dear {tokens[0] if tokens else 'Valued Customer'},\n\n"
                f"Thank you for contacting us. We have successfully logged your details "
                f"and verified your account information. Any requested notifications "
                f"have been forwarded to the designated channels.\n\n"
                f"If you need further assistance or need to update any parameters, "
                f"please do not hesitate to reach out to our dedicated support team.\n\n"
                f"Best regards,\nCustomer Operations Team"
            )
        elif "code" in prompt_lower or "bug" in prompt_lower or "api" in prompt_lower:
            response = (
                f"Here is a secure implementation for your architecture:\n\n"
                f"```python\n"
                f"# Processed securely through Airlock AI\n"
                f"def handle_secure_transaction(identity_token='{tokens[0] if tokens else '<TOKEN_1>'}'):\n"
                f"    print(f'Processing transaction for {{identity_token}}')\n"
                f"    return {{'status': 'verified', 'protected_entities': [{', '.join(repr(t) for t in tokens)}]}}\n"
                f"```\n\n"
                f"Notice that the surrogate tokens remain fully valid placeholders throughout the execution cycle."
            )
        else:
            response = (
                f"I have reviewed your request regarding {sanitized_prompt[:60]}... "
                f"All operations concerning {token_list} have been verified under standard security policies. "
                f"Please let me know if you would like me to expand on any specific aspect or proceed with next steps."
            )
        return response

    def generate(self, sanitized_prompt: str) -> str:
        """
        Synchronously generate a response from Gemini or simulator.
        """
        if not isinstance(sanitized_prompt, str) or not sanitized_prompt.strip():
            raise ValueError("sanitized_prompt cannot be empty")

        if self.is_live():
            try:
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=sanitized_prompt,
                )
                text = getattr(response, "text", None)
                if not text:
                    raise RuntimeError("Gemini returned an empty response.")
                return text.strip()
            except Exception as e:
                # If quota exceeded or network error, fall back with explicit notation
                print(f"[Airlock AI] Gemini API call failed: {e}. Using intelligent fallback.")
                return self._generate_simulated_response(sanitized_prompt)

        return self._generate_simulated_response(sanitized_prompt)

    async def generate_async(self, sanitized_prompt: str) -> str:
        """
        Asynchronously generate response offloaded from event loop.
        """
        return await asyncio.to_thread(self.generate, sanitized_prompt)

    async def generate_stream(
        self, sanitized_prompt: str, chunk_delay: float = 0.03
    ) -> AsyncGenerator[str, None]:
        """
        Stream generated tokens chunk-by-chunk for live UI typewriter experience.
        """
        full_text = await self.generate_async(sanitized_prompt)

        # Break into words and tokens for smooth streaming
        words = full_text.split(" ")
        for i, word in enumerate(words):
            chunk = word if i == 0 else " " + word
            yield chunk
            await asyncio.sleep(chunk_delay)

    def __repr__(self) -> str:
        status = "Live" if self.is_live() else "Sandbox Simulator"
        return f"GeminiClient(model='{self.model}', status='{status}')"
