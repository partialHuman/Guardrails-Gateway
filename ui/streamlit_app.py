import streamlit as st
import requests
import json
import os

# Accept both "http://api:8000" and "http://api:8000/analyze" so a
# mis-set API_URL can never produce ".../analyze/analyze".
BASE_URL = os.getenv(
    "API_URL",
    "http://localhost:8000"
).rstrip("/")

if BASE_URL.endswith("/analyze"):
    BASE_URL = BASE_URL[: -len("/analyze")]

API_URL = f"{BASE_URL}/analyze"
API_KEY = os.getenv("GUARDRAILS_API_KEY", os.getenv("API_KEY", ""))

st.set_page_config(
    page_title="SentraGuard Lite",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SentraGuard Lite")
st.caption("Offline AI Guardrails Gateway")

st.divider()

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

                st.write(
                    f"• **{reason['tag']}** "
                    f"(`{reason.get('rule', '')}` in "
                    f"`{reason.get('source', 'prompt')}`) "
                    f"→ {reason['evidence']}"
                )

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
        if exc.response is not None and exc.response.status_code == 401:
            st.error("Authentication failed (401 Unauthorized). Check your GUARDRAILS_API_KEY.")
        else:
            st.exception(exc)

    except Exception as e:

        st.exception(e)
