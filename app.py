"""
Airlock AI - Main Flask Application

Airlock AI is a local privacy proxy for cloud-based AI.

Pipeline:

    User Prompt
        ↓
    Sensitive Data Detection
        ↓
    Security Policy
        ↓
    Local Tokenization
        ↓
    Sanitized Prompt
        ↓
    Gemini
        ↓
    Gemini Response
        ↓
    Local Rehydration
        ↓
    Final Response

IMPORTANT SECURITY PRINCIPLE:

The original user prompt is NEVER sent directly to Gemini.

Only the sanitized prompt containing surrogate tokens
is sent to the external AI service.
"""

from __future__ import annotations

import os
import time
from typing import Any

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from guardian.detector import SensitiveDataDetector
from guardian.llm import GeminiClient
from guardian.policy import PolicyDecision, SecurityPolicy
from guardian.vault import PrivacyVault


# ============================================================
# Environment
# ============================================================

load_dotenv()


# ============================================================
# Flask Application
# ============================================================

app = Flask(__name__)


# ============================================================
# Core Airlock Components
# ============================================================

detector = SensitiveDataDetector()

policy = SecurityPolicy()

gemini = None


def get_gemini_client() -> GeminiClient:
    """
    Lazily create the Gemini client.

    This means the Flask application can still start even if
    the API key has not been configured yet.

    The actual request will return a useful configuration error.
    """

    global gemini

    if gemini is None:
        gemini = GeminiClient()

    return gemini


# ============================================================
# Health Check
# ============================================================

@app.get("/api/v1/health")
def health() -> Any:
    """
    Health-check endpoint.

    Returns basic information about the Airlock server.
    """

    return jsonify(
        {
            "status": "ok",
            "service": "Airlock AI",
            "version": "1.0.0",
            "privacy_engine": "local",
            "llm_configured": bool(
                os.getenv("GEMINI_API_KEY")
            ),
        }
    )


# ============================================================
# Home Page
# ============================================================

@app.get("/")
def index() -> Any:
    """
    Serve the Airlock AI frontend.
    """

    return render_template("index.html")


# ============================================================
# Secure Chat Endpoint
# ============================================================

@app.post("/api/v1/secure-chat")
def secure_chat() -> Any:
    """
    Main Airlock AI endpoint.

    Expected request:

        {
            "prompt": "Write an email to John Doe..."
        }

    Response contains:

        original prompt
        sanitized prompt
        detected information
        policy decision
        Gemini response
        final rehydrated response
    """

    request_start = time.perf_counter()

    # --------------------------------------------------------
    # 1. Validate JSON
    # --------------------------------------------------------

    if not request.is_json:

        return jsonify(
            {
                "success": False,
                "error": "Request must contain JSON.",
            }
        ), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify(
            {
                "success": False,
                "error": "Invalid JSON body.",
            }
        ), 400

    # --------------------------------------------------------
    # 2. Extract Prompt
    # --------------------------------------------------------

    original_prompt = data.get("prompt")

    if not isinstance(original_prompt, str):

        return jsonify(
            {
                "success": False,
                "error": (
                    "The 'prompt' field must be a string."
                ),
            }
        ), 400

    original_prompt = original_prompt.strip()

    if not original_prompt:

        return jsonify(
            {
                "success": False,
                "error": "Prompt cannot be empty.",
            }
        ), 400

    # --------------------------------------------------------
    # 3. Create a request-local vault
    # --------------------------------------------------------

    #
    # VERY IMPORTANT:
    #
    # We create a NEW vault for every request.
    #
    # This prevents information from one user's request
    # accidentally being available during another request.
    #

    vault = PrivacyVault()

    try:

        # ----------------------------------------------------
        # 4. Detect sensitive information
        # ----------------------------------------------------

        detections = detector.detect(
            original_prompt
        )

        # ----------------------------------------------------
        # 5. Evaluate security policy
        # ----------------------------------------------------

        policy_result = policy.evaluate(
            detections
        )

        # ----------------------------------------------------
        # 6. Block if policy requires it
        # ----------------------------------------------------

        if policy_result.decision == PolicyDecision.BLOCK:

            return jsonify(
                {
                    "success": False,
                    "blocked": True,
                    "policy": policy_result.to_dict(),
                    "message": (
                        "This request was blocked by "
                        "Airlock's security policy."
                    ),
                }
            ), 403

        # ----------------------------------------------------
        # 7. Sanitize the prompt
        # ----------------------------------------------------

        def generate_token(
            data_type: str,
            original_value: str,
        ) -> str:
            """
            Store the original value locally and return its
            surrogate token.
            """

            return vault.store(
                data_type=data_type,
                original_value=original_value,
            )

        sanitized_prompt, _ = detector.redact(
            original_prompt,
            token_generator=generate_token,
        )

        # ----------------------------------------------------
        # 8. Safety check
        # ----------------------------------------------------

        #
        # The following check is extremely important.
        #
        # Before sending anything to Gemini, verify that
        # every detected sensitive value has disappeared
        # from the outbound prompt.
        #

        outbound_prompt = sanitized_prompt

        for detection in detections:

            if detection.value in outbound_prompt:

                return jsonify(
                    {
                        "success": False,
                        "blocked": True,
                        "error": (
                            "Airlock safety check failed. "
                            "Sensitive information remained "
                            "in the outbound prompt."
                        ),
                    }
                ), 500

        # ----------------------------------------------------
        # 9. Call Gemini
        # ----------------------------------------------------

        gemini_client = get_gemini_client()

        gemini_response = gemini_client.generate(
            sanitized_prompt=outbound_prompt
        )

        # ----------------------------------------------------
        # 10. Rehydrate Gemini response locally
        # ----------------------------------------------------

        final_response = vault.rehydrate(
            gemini_response
        )

        # ----------------------------------------------------
        # 11. Calculate processing time
        # ----------------------------------------------------

        elapsed_ms = round(
            (time.perf_counter() - request_start) * 1000,
            2,
        )

        # ----------------------------------------------------
        # 12. Return result
        # ----------------------------------------------------

        return jsonify(
            {
                "success": True,
                "blocked": False,

                # Original prompt is returned only to the
                # local frontend. It is NEVER sent to Gemini.
                "original_prompt": original_prompt,

                # This is the exact prompt that was sent to
                # Gemini.
                "sanitized_prompt": outbound_prompt,

                # Information detected locally.
                "detections": [
                    detection.to_dict()
                    for detection in detections
                ],

                # Safe vault metadata only.
                "protected_items": (
                    vault.get_safe_entries()
                ),

                # Security decision.
                "policy": policy_result.to_dict(),

                # Gemini's answer containing tokens.
                "llm_response": gemini_response,

                # Final answer after local restoration.
                "final_response": final_response,

                "metadata": {
                    "model": gemini_client.get_model(),
                    "protected_count": vault.size(),
                    "processing_time_ms": elapsed_ms,
                },
            }
        )

    except ValueError as exc:

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 500

    except RuntimeError as exc:

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 502

    except Exception as exc:

        app.logger.exception(
            "Unexpected Airlock error"
        )

        return jsonify(
            {
                "success": False,
                "error": (
                    "An unexpected server error occurred."
                ),
                "details": str(exc),
            }
        ), 500

    finally:

        # ----------------------------------------------------
        # 13. Clear the local vault
        # ----------------------------------------------------

        #
        # The vault is request-local.
        #
        # Once the response has been generated, there is no
        # reason to keep the original sensitive values in
        # memory.
        #

        vault.clear()


# ============================================================
# Error Handlers
# ============================================================

@app.errorhandler(404)
def not_found(error: Any) -> Any:
    """
    Handle unknown routes.
    """

    return jsonify(
        {
            "success": False,
            "error": "Endpoint not found.",
        }
    ), 404


@app.errorhandler(405)
def method_not_allowed(error: Any) -> Any:
    """
    Handle unsupported HTTP methods.
    """

    return jsonify(
        {
            "success": False,
            "error": "HTTP method not allowed.",
        }
    ), 405


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":

    host = os.getenv(
        "AIRLOCK_HOST",
        "127.0.0.1",
    )

    port = int(
        os.getenv(
            "AIRLOCK_PORT",
            "5000",
        )
    )

    debug = (
        os.getenv(
            "AIRLOCK_DEBUG",
            "false",
        ).lower()
        == "true"
    )

    print()
    print("=" * 60)
    print("              AIRLOCK AI")
    print("        Privacy Proxy & LLM Guard")
    print("=" * 60)
    print()
    print(f"Server : http://{host}:{port}")
    print(
        "Health : "
        f"http://{host}:{port}/api/v1/health"
    )
    print(
        "Chat   : "
        f"http://{host}:{port}/api/v1/secure-chat"
    )
    print()
    print(
        "Privacy Engine : LOCAL"
    )
    print(
        "Gemini Model   : "
        f"{os.getenv('GEMINI_MODEL', 'gemini-3.5-flash-lite')}"
    )
    print(
        "Gemini API Key : "
        + (
            "CONFIGURED"
            if os.getenv("GEMINI_API_KEY")
            else "NOT CONFIGURED"
        )
    )
    print()
    print("=" * 60)
    print()

    app.run(
        host=host,
        port=port,
        debug=debug,
    )