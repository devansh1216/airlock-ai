# 🛡️ Airlock AI — Privacy Proxy & Security Gateway for Cloud LLMs

**Airlock AI** is an enterprise-grade, privacy-preserving middleware proxy built with **FastAPI**, **spaCy**, **Regex**, and **Google Gemini**. It intercepts prompts before they leave the user's local perimeter, detects and sanitizes sensitive Personally Identifiable Information (PII) using in-memory surrogate tokens, dispatches the sanitized payload to cloud LLMs, and seamlessly restores the original values locally in the returned response.

---

## ⚡ Architecture & Zero-Leakage Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        USER LOCAL ENVIRONMENT                          │
│                                                                        │
│   1. Raw Prompt ("Email Rahul Sharma at rahul@gmail.com...")           │
│         │                                                              │
│         ▼                                                              │
│   2. Sensitive Data Detector (Regex + spaCy NER + FP Mitigation)       │
│         │                                                              │
│         ▼                                                              │
│   3. Security Policy Engine (ALLOW / SANITIZE / BLOCK)                 │
│         │                                                              │
│         ▼                                                              │
│   4. In-Memory Privacy Vault (<PERSON_1>, <EMAIL_1> generated)         │
│         │                                                              │
│         ▼                                                              │
│   5. Strict Outbound Safety Check (0.0% raw PII verified)              │
└─────────┼──────────────────────────────────────────────────────────────┘
          │
          │ Outbound Sanitized Prompt ("Email <PERSON_1> at <EMAIL_1>...")
          ▼
┌──────────────────────────────────┐
│     EXTERNAL CLOUD LLM           │
│     (Google Gemini API)          │
│                                  │
│  Operates ONLY on tokens.        │
│  Zero exposure to user secrets.  │
└─────────┬────────────────────────┘
          │
          │ Tokenized Response ("Confirmation sent to <EMAIL_1> for <PERSON_1>.")
          ▼
┌────────────────────────────────────────────────────────────────────────┐
│   6. Inbound Local Vault Rehydration                                   │
│      (<PERSON_1> ➔ Rahul Sharma, <EMAIL_1> ➔ rahul@gmail.com)          │
│         │                                                              │
│         ▼                                                              │
│   7. Final Restored Output Delivered to Client                         │
│   8. Request-Scoped Vault Memory Zeroized                              │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Improvements & FastAPI Migration

### 1. High-Performance FastAPI Backend
- **Asynchronous Execution (`async`/`await`)**: CPU-bound spaCy model inferences are offloaded with `asyncio.to_thread` while network I/O to Gemini executes non-blockingly.
- **Real-Time Streaming (Server-Sent Events)**: `/api/v1/secure-chat/stream` yields stage events (`scan`, `policy`, `sanitized`, `llm_chunk`, `rehydrate`) for real-time typewriter responses and pipeline visualization.
- **Pydantic v2 Strict Contracts**: Endpoints are strictly validated with typed models, providing self-documenting APIs and defensive error handling.
- **FastAPI Lifespan Context**: Pre-warms the spaCy model and regex patterns during server boot.
- **Interactive OpenAPI Documentation**: Built-in Swagger UI at `http://127.0.0.1:8000/docs` and ReDoc at `http://127.0.0.1:8000/redoc`.

### 2. False-Positive Mitigation Engine
- **Technical & Dev Vocabulary Allowlist**: Eliminates statistical NER errors where framework names like **Flask**, **FastAPI**, **Python**, **Docker**, **Linux**, or **AWS** were incorrectly classified as Locations (`GPE`/`LOC`), Organizations, or Persons.
- **Luhn Algorithm Check**: Validates credit card candidates against standard checksum algorithms to prevent random 16-digit order numbers from being mistakenly redacted.
- **Honorific & Multi-Word Verification**: Requires title honorifics (`Dr.`, `Mr.`, `Ms.`) or multi-word titles for high-confidence Person detection.
- **Custom Corporate Allowlist**: Dynamically register domain terms or brand names that should never be redacted.

### 3. Traversing Multi-Page Console (Enterprise Dark Mode)
The frontend was redesigned to look like an ultra-slick cybersecurity devtool (inspired by Cloudflare Zero Trust, Datadog, and Linear) without generic "AI-generated" tropes:
- **1. 🛰️ Proxy Gateway (`#gateway`)**: Live execution studio with dual diff views (Outbound Sanitized vs Inbound Rehydrated), latency meters, preset benchmarks, and pipeline flow tracking.
- **2. 🔬 Detection Engine (`#detector`)**: Sandbox for analyzing text, inspecting verified entities, and examining suppressed false positives with clear rationale.
- **3. 🛡️ Policy Matrix (`#policy`)**: Interactive 3-way toggle controls (`ALLOW`, `SANITIZE`, `BLOCK`) per data category, custom allowlists, and live backend synchronization.
- **4. 🔐 Privacy Vault (`#vault`)**: Live view of active surrogate tokens with masked previews, entropy lengths, and immediate memory zeroization controls.
- **5. 📊 SOC Audit & Telemetry (`#telemetry`)**: Security Operations Center dashboard tracking total throughput, shielded PII count, latency averages, and JSON audit log export.
- **6. ⚡ API & Docs (`#docs`)**: Drop-in cURL snippets, Python SDK wrapper, and interactive endpoint catalog.

---

## 🛠️ Quickstart

### 1. Requirements
Ensure Python 3.10+ is installed:
```bash
pip install -r requirements.txt
```

*(Optional) Configure your Gemini API key in `.env`:*
```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```
*Note: If no API key is provided, Airlock automatically runs in a local **Sandbox Simulator Mode**, allowing full end-to-end testing of detection, tokenization, and rehydration without any paid credentials.*

### 2. Start the Server
```bash
python app.py
```
Or with Uvicorn directly:
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser at:
- **Web Console**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`

### 3. Run Automated Tests
```bash
python test_airlock.py
```

---

## 📡 Core API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/secure-chat` | Full privacy proxy pipeline (JSON) |
| `POST` | `/api/v1/secure-chat/stream` | Real-time Server-Sent Events (SSE) streaming pipeline |
| `POST` | `/api/v1/detect` | Standalone entity detection & false-positive analysis |
| `GET` | `/api/v1/policy` | Get active security policy matrix & allowlist |
| `PUT` | `/api/v1/policy` | Dynamically update policy rules and allowlist |
| `GET` | `/api/v1/vault/active` | Inspect in-memory surrogate token sessions |
| `DELETE` | `/api/v1/vault/purge` | Immediate memory zeroization / flush |
| `GET` | `/api/v1/telemetry` | Real-time throughput and privacy metrics |
| `GET` | `/api/v1/health` | System health and LLM gateway status |

---

## 📂 Project Structure

```
Airlock AI/
├── app.py                  # FastAPI application with routes, SSE, and lifespan
├── requirements.txt        # FastAPI, Uvicorn, spaCy, Pydantic, google-genai
├── test_airlock.py         # Automated test suite (11 unit & integration tests)
├── README.md               # Architecture and documentation
├── guardian/               # Isolated security and privacy modules
│   ├── __init__.py         # Package exports
│   ├── detector.py         # Regex + spaCy NER + False-Positive Mitigation
│   ├── policy.py           # ALLOW / SANITIZE / BLOCK rules engine
│   ├── vault.py            # In-memory cryptographic token vault & rehydration
│   └── llm.py              # Async Gemini client with streaming & simulator fallback
├── static/
│   ├── style.css           # Enterprise cybersecurity dark-mode design system
│   └── main.js             # SPA traversing router, SSE reader, policy sync
└── templates/
    └── index.html          # Semantic HTML5 dashboard with 6 traversing views
```
