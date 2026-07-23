import streamlit as st
import requests
import json

API_URL = "http://localhost:8000/analyze"

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

    payload = {

        "prompt": prompt,

        "context_docs": context_docs,

        "metadata": {

            "app_id": app_id,

            "user_id": user_id,

            "request_id": request_id

        }

    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
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
                    f"• **{reason['tag']}** → {reason['evidence']}"
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

    except Exception as e:

        st.exception(e)