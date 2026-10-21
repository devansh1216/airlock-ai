"""
Airlock AI - Comprehensive Automated Test Suite

Tests all core Guardian modules and FastAPI endpoints:
1. False-Positive Mitigation (e.g. verifying 'Flask' is NOT classified as a location)
2. Luhn Algorithm Validation for Credit Cards
3. Sensitive Data Detector (Regex + spaCy NER)
4. Security Policy Engine (ALLOW / SANITIZE / BLOCK)
5. Local In-Memory Privacy Vault & Rehydration
6. Live FastAPI REST API Endpoints
"""

import sys
import unittest
import requests

from guardian.detector import SensitiveDataDetector, is_luhn_valid
from guardian.policy import PolicyDecision, SecurityPolicy
from guardian.vault import PrivacyVault


class TestDetectorUnit(unittest.TestCase):
    """Unit tests for SensitiveDataDetector and false-positive suppression."""

    @classmethod
    def setUpClass(cls):
        cls.detector = SensitiveDataDetector()

    def test_false_positive_flask_suppression(self):
        """Verify that 'Flask' is suppressed and NOT classified as a LOCATION."""
        text = "I developed a backend in Flask and FastAPI for Rahul Sharma (rahul@gmail.com)."
        accepted, suppressed = self.detector.detect_with_audit(text)

        suppressed_values = [s.value for s in suppressed]
        accepted_values = [a.value for a in accepted]

        # 'Flask' should be suppressed
        self.assertIn("Flask", suppressed_values, "Flask must be caught as a suppressed tech term")
        # 'Rahul Sharma' and 'rahul@gmail.com' should be accepted
        self.assertIn("Rahul Sharma", accepted_values)
        self.assertIn("rahul@gmail.com", accepted_values)

    def test_luhn_credit_card_validation(self):
        """Verify Luhn algorithm separates real card numbers from random digits."""
        # Standard test card (Visa checksum valid)
        self.assertTrue(is_luhn_valid("4532-0150-1234-5671"))
        # Random non-card 16-digit order ID
        self.assertFalse(is_luhn_valid("1234-5678-9012-3456"))

    def test_structured_pii_detection(self):
        """Verify email, phone, and AWS key detection."""
        text = "Contact Alice at alice@company.org or +91-9876543210. Key: AKIAIOSFODNN7EXAMPLE."
        detections = self.detector.detect(text)
        types = {d.data_type for d in detections}

        self.assertIn("EMAIL", types)
        self.assertIn("PHONE", types)
        self.assertIn("AWS_ACCESS_KEY", types)


class TestPolicyUnit(unittest.TestCase):
    """Unit tests for SecurityPolicy decisions."""

    def setUp(self):
        self.detector = SensitiveDataDetector()
        self.policy = SecurityPolicy()

    def test_credential_block_decision(self):
        """AWS keys must be strictly BLOCKED by default policy."""
        detections = self.detector.detect("System error with key AKIAIOSFODNN7EXAMPLE.")
        result = self.policy.evaluate(detections)
        self.assertEqual(result.decision, PolicyDecision.BLOCK)
        self.assertFalse(result.allowed)
        self.assertIn("AWS_ACCESS_KEY", result.blocked_types)

    def test_pii_sanitize_decision(self):
        """Normal PII must be SANITIZED by default policy."""
        detections = self.detector.detect("Email Rahul Sharma at rahul@gmail.com.")
        result = self.policy.evaluate(detections)
        self.assertEqual(result.decision, PolicyDecision.SANITIZE)
        self.assertTrue(result.allowed)
        self.assertTrue(result.requires_sanitization)


class TestVaultUnit(unittest.TestCase):
    """Unit tests for PrivacyVault tokenization and rehydration."""

    def test_store_and_rehydrate(self):
        """Tokens must be generated and rehydrated with exact fidelity."""
        vault = PrivacyVault()
        t1 = vault.store("PERSON", "Rahul Sharma")
        t2 = vault.store("EMAIL", "rahul@gmail.com")

        self.assertEqual(t1, "<PERSON_1>")
        self.assertEqual(t2, "<EMAIL_1>")

        mock_llm_response = f"Hello {t1}, confirmation sent to {t2}."
        restored = vault.rehydrate(mock_llm_response)

        self.assertEqual(restored, "Hello Rahul Sharma, confirmation sent to rahul@gmail.com.")

        # Test clear
        vault.clear()
        self.assertEqual(vault.size(), 0)


class TestFastAPIRoutes(unittest.TestCase):
    """Integration tests against live FastAPI server."""

    BASE_URL = "http://127.0.0.1:8000"

    def test_health_endpoint(self):
        res = requests.get(f"{self.BASE_URL}/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["service"], "Airlock AI")
        self.assertEqual(data["version"], "2.0.0")

    def test_detect_endpoint(self):
        res = requests.post(
            f"{self.BASE_URL}/api/v1/detect",
            json={"text": "I built a REST API in Flask for Rahul Sharma."}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        suppressed = [s["value"] for s in data["suppressed_false_positives"]]
        self.assertIn("Flask", suppressed)

    def test_secure_chat_endpoint(self):
        res = requests.post(
            f"{self.BASE_URL}/api/v1/secure-chat",
            json={"prompt": "Write an email to Rahul Sharma at rahul@gmail.com."}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("<PERSON_1>", data["sanitized_prompt"])
        self.assertIn("Rahul Sharma", data["final_response"])

    def test_secure_chat_credential_blocking(self):
        res = requests.post(
            f"{self.BASE_URL}/api/v1/secure-chat",
            json={"prompt": "Check AWS key AKIAIOSFODNN7EXAMPLE for user admin."}
        )
        self.assertEqual(res.status_code, 403)
        data = res.json()
        self.assertTrue(data["blocked"])

    def test_frontend_routes(self):
        res = requests.get(f"{self.BASE_URL}/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Airlock AI", res.text)
        self.assertIn("tabGateway", res.text)


if __name__ == "__main__":
    unittest.main()
