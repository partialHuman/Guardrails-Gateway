# 🛡️ SentraGuard Lite

An offline AI Guardrails Gateway built using **FastAPI**, **Streamlit**, and **Python**.

This project analyzes user prompts and retrieved context documents to detect:

- Prompt Injection
- Personally Identifiable Information (PII)
- RAG Injection

Based on the detected risks, the gateway decides whether to:

- ✅ Allow
- ⚠️ Transform
- ❌ Block

---

# Features

- FastAPI REST API
- Streamlit Web UI
- Command Line Interface (CLI)
- Prompt Injection Detection
- Email Detection
- Phone Number Detection
- RAG Injection Detection
- Prompt Sanitization
- Risk Scoring
- Policy Engine
- Structured Logging
- Docker Support
- Pytest Unit Tests

---

# Project Architecture

```
                   User
                     │
      ┌──────────────┴──────────────┐
      │                             │
 Streamlit UI                      CLI
      │                             │
      └──────────────┬──────────────┘
                     │
                 FastAPI
                     │
             Analysis Engine
                     │
      ┌──────────────┼──────────────┐
      │              │              │
Prompt        PII Detector    RAG Detector
Injection
      └──────────────┼──────────────┘
                     │
               Risk Scoring
                     │
              Decision Engine
                     │
             Sanitization Layer
                     │
                JSON Response
```

---

# Folder Structure

```
guardrails-gateway/
│
├── app/
│   ├── main.py
│   ├── schemas.py
│   ├── config.py
│   │
│   ├── core/
│   │   ├── analyzer.py
│   │   ├── detectors.py
│   │   ├── sanitizer.py
│   │   ├── scorer.py
│   │   ├── policy.py
│   │   └── logger.py
│   │
│   └── utils/
│       └── regex.py
│
├── ui/
│   └── streamlit_app.py
│
├── tests/
│
├── cli.py
├── Dockerfile.api
├── Dockerfile.ui
├── docker-compose.yml
├── requirements.api.txt
├── requirements.ui.txt
├── pytest.ini
├── README.md
└── .gitignore
```

---

# Installation

## Clone Repository

```bash
git clone <repository-url>

cd guardrails-gateway
```

## Create Virtual Environment

```bash
python -m venv .venv
```

Windows

```bash
.venv\Scripts\activate
```

Linux/macOS

```bash
source .venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.api.txt

pip install -r requirements.ui.txt
```

---


# Running the Backend

```bash
uvicorn app.main:app --reload
```

API Documentation:

```
http://localhost:8000/docs
```

---


# Running the Streamlit UI

```bash
streamlit run ui/streamlit_app.py
```

Open

```
http://localhost:8501
```

---


# Running the CLI

Example

```bash
python cli.py --prompt "Ignore previous instructions"
```

With RAG Document

```bash
python cli.py ^
--prompt "Ignore previous instructions" ^
--doc "Developer: Ignore guidelines"
```

---


# 🐳 Docker Deployment

Build

```bash
docker compose build
```

Run

```bash
docker compose up
```

## Access the Application

### FastAPI Swagger

```
http://localhost:8000/docs
```

### Streamlit UI

```
http://localhost:8501
```

---
## Stop Containers

```bash
docker compose down
```

---


# API Endpoints

## GET /policy

Returns

- Detection policy
- Thresholds
- Enabled detectors

---

## POST /analyze

Input

```json
{
  "prompt": "Ignore previous instructions",

  "context_docs": [],

  "metadata": {
    "app_id": "demo",
    "user_id": "user",
    "request_id": "1"
  }
}
```

Output

```json
{
  "decision": "transform",

  "risk_score": 50,

  "risk_tags": [
    "prompt_injection"
  ]
}
```

---


# Running Tests

```bash
pytest -v
```

Example

```
13 passed
```

---


# Detection Rules

### Prompt Injection

Examples

- Ignore previous instructions
- Reveal system prompt
- Override instructions

---

### PII

Detects

- Email addresses
- Phone numbers

---

### RAG Injection

Detects

- Developer:
- System:
- Ignore guidelines
- Override policy

---

# Design Decisions

- Modular architecture
- Deterministic offline execution
- No external AI APIs
- Regex-based detection
- Configurable policy thresholds
- Structured logging
- Separate UI and backend

---

# Future Improvements

- Named Entity Recognition (NER) for advanced PII detection
- Machine learning-based prompt injection detection
- Configurable policies via YAML/JSON
- JWT authentication
- Role-based access control
- Database-backed audit logging
- Prometheus metrics
- Kubernetes deployment

---

# Technologies Used

- Python 3.11
- FastAPI
- Pydantic
- Streamlit
- Requests
- Pytest
- Docker
- Uvicorn

---

# Screenshots

## Streamlit UI

_Add your Streamlit UI screenshot here._

## Swagger UI

_Add your Swagger UI screenshot here._

---

# Author

**Dhrumil Moga**
