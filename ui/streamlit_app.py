import os
import time

import requests
import streamlit as st

from ui_helpers import (
    GATE_LOCKED,
    GATE_LOGIN,
    GATE_OPEN_WARN,
    describe_http_error,
    evaluate_gate,
    format_reason_line,
    normalize_api_url,
    password_matches,
)

# Accept both "http://api:8000" and "http://api:8000/analyze" so a
# mis-set API_URL can never produce ".../analyze/analyze".
BASE_URL, API_URL = normalize_api_url(
    os.getenv("API_URL", "http://localhost:8000")
)

# Only the dedicated variable is read: a generic API_KEY in the environment
# belongs to some other service and must never be sent to the gateway.
API_KEY = os.getenv("GUARDRAILS_API_KEY", "").strip()

# The UI lends its API key to whoever can open the page, so it is locked
# unless a UI password is set (or anonymous use is explicitly allowed).
UI_PASSWORD = os.getenv("GUARDRAILS_UI_PASSWORD", "")

UI_ALLOW_ANONYMOUS = os.getenv(
    "GUARDRAILS_UI_ALLOW_ANONYMOUS", ""
).strip().lower() in ("true", "1", "yes", "on")

st.set_page_config(
    page_title="SentraGuard Lite",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentraGuard Lite")
st.caption("Offline AI Guardrails Gateway")

st.divider()

# --------------------------------------------------
# Access gate
# --------------------------------------------------

_gate = evaluate_gate(API_KEY, UI_PASSWORD, UI_ALLOW_ANONYMOUS)

if _gate == GATE_LOCKED:
    st.error(
        "This UI is locked. It holds the gateway API key, so it will not "
        "serve anonymous visitors.\n\n"
        "Set GUARDRAILS_UI_PASSWORD to require a login, or set "
        "GUARDRAILS_UI_ALLOW_ANONYMOUS=true if this instance is only "
        "reachable by you (for example bound to localhost)."
    )
    st.stop()

if _gate == GATE_OPEN_WARN:
    st.warning(
        "Anonymous access is enabled: anyone who can reach this page can "
        "use the gateway through it."
    )

if _gate == GATE_LOGIN and not st.session_state.get("ui_authenticated"):
    entered = st.text_input("UI password", type="password")

    if st.button("Log in"):
        if password_matches(entered, UI_PASSWORD):
            st.session_state["ui_authenticated"] = True
            st.rerun()
        else:
            time.sleep(1)  # slow down guessing
            st.error("Incorrect password.")

    st.stop()

# --------------------------------------------------
# Metadata
# --------------------------------------------------

st.subheader("Metadata")

col1, col2, col3 = st.columns(3)

with col1:
    app_id = st.text_input(
        "App ID",
        value="chatbot-prod"
    )

with col2:
    user_id = st.text_input(
        "User ID",
        value="user-001"
    )

with col3:
    request_id = st.text_input(
        "Request ID",
        value="req-001"
    )

st.divider()

# --------------------------------------------------
# Prompt
# --------------------------------------------------

prompt = st.text_area(
    "Prompt",
    height=180,
    placeholder="Enter your prompt..."
)

st.divider()

# --------------------------------------------------
# Context Documents
# --------------------------------------------------

st.subheader("Context Documents")

context_docs = []

for i in range(3):

    doc = st.text_area(
        f"Document {i+1}",
        height=120,
        key=f"doc{i}"
    )

    if doc.strip():

        context_docs.append(
            {
                "id": f"doc-{i+1}",
                "text": doc
            }
        )

st.divider()

# --------------------------------------------------
# Analyze Button
# --------------------------------------------------

if st.button("Analyze", type="primary"):

    if not prompt.strip():
        st.warning("Enter a prompt first.")
        st.stop()

    payload = {

        "prompt": prompt,

        "context_docs": context_docs,

        "metadata": {

            "app_id": app_id,

            "user_id": user_id,

            "request_id": request_id

        }

    }

    headers = {}
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    try:

        response = requests.post(
            API_URL,
            json=payload,
            headers=headers,
            timeout=30
        )

        response.raise_for_status()

        result = response.json()

        st.success("Analysis Complete")

        st.divider()

        # --------------------------
        # Decision
        # --------------------------

        decision = result["decision"]

        if decision == "allow":
            st.success("Decision: ALLOW")

        elif decision == "transform":
            st.warning("Decision: TRANSFORM")

        else:
            st.error("Decision: BLOCK")

        # --------------------------
        # Risk Score
        # --------------------------

        st.metric(
            "Risk Score",
            result["risk_score"]
        )

        # --------------------------
        # Tags
        # --------------------------

        st.subheader("Risk Tags")

        if result["risk_tags"]:

            for tag in result["risk_tags"]:
                st.badge(tag)

        else:
            st.write("No risks detected.")

        st.divider()

        # --------------------------
        # Sanitized Prompt
        # --------------------------

        st.subheader("Sanitized Prompt")

        st.code(
            result["sanitized_prompt"],
            language="text"
        )

        # --------------------------
        # Sanitized Docs
        # --------------------------

        st.subheader("Sanitized Context")

        quarantined = result.get("quarantined_doc_ids", [])

        if quarantined:
            st.error(
                "Quarantined (dropped) documents: "
                + ", ".join(quarantined)
            )

        for doc in result["sanitized_context_docs"]:

            st.markdown(f"**{doc['id']}**")

            st.code(
                doc["text"],
                language="text"
            )

        st.divider()

        # --------------------------
        # Reasons
        # --------------------------

        st.subheader("Detection Reasons")

        if result["reasons"]:

            for reason in result["reasons"]:

                st.text(format_reason_line(reason))

        else:

            st.write("No findings.")

        st.divider()

        # --------------------------
        # Raw JSON
        # --------------------------

        with st.expander("Raw JSON Response"):

            st.json(result)

    except requests.exceptions.ConnectionError:

        st.error(
            "Cannot connect to FastAPI server.\n\n"
            "Start the backend using:\n"
            "uvicorn app.main:app --reload"
        )

    except requests.exceptions.HTTPError as exc:

        status = exc.response.status_code if exc.response is not None else 0

        retry_after = (
            exc.response.headers.get("Retry-After")
            if exc.response is not None
            else None
        )

        st.error(describe_http_error(status, retry_after))

    except requests.exceptions.Timeout:

        st.error("The gateway did not answer in time.")

    except Exception as exc:

        # Type only: a traceback would expose paths and internal hostnames.
        st.error(f"Unexpected error ({type(exc).__name__}).")
