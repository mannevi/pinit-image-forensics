import streamlit as st
import uuid
import os

from auth import init_db, register_user, verify_login
from real_analysis import analyze_image
from report_generator import build_pdf_report


# -------------------------
# Streamlit setup
# -------------------------
st.set_page_config(page_title="PinIT Image Forensics", layout="centered")
init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

if "page" not in st.session_state:
    st.session_state.page = "login"


# -------------------------
# Login Page
# -------------------------
def login_page():
    st.title("🔐 PinIT Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if verify_login(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid username or password")

    st.markdown("---")
    if st.button("Create New Account"):
        st.session_state.page = "register"
        st.rerun()


# -------------------------
# Registration Page
# -------------------------
def register_page():
    st.title("📝 Create PinIT Account")

    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if password != confirm:
            st.error("Passwords do not match")
        elif register_user(username, password):
            st.success("Account created successfully. Please login.")
            st.session_state.page = "login"
            st.rerun()
        else:
            st.error("Username already exists")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()


# -------------------------
# Main Application
# -------------------------
def main_app():
    st.title("📸 PinIT Image Forensics Platform")
    st.write(f"Welcome, **{st.session_state.username}**")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.page = "login"
        st.rerun()

    st.markdown("---")

    uploaded = st.file_uploader("Upload Image", type=["jpg", "jpeg", "png"])
    secure_capture = st.checkbox("Captured using PinIT Secure Capture", value=False)
    claimed_location = st.text_input("Claimed Capture Location (optional)")

    if uploaded:
        os.makedirs("uploads", exist_ok=True)
        os.makedirs("reports", exist_ok=True)

        image_path = os.path.join("uploads", uploaded.name)
        with open(image_path, "wb") as f:
            f.write(uploaded.read())

        st.image(image_path, caption="Uploaded Image", width="stretch")

        if st.button("Generate Report"):
            report_id = f"PINIT-{uuid.uuid4()}"

            # ✅ FIXED CALL (original_filename added)
            analysis = analyze_image(
                path=image_path,
                original_filename=uploaded.name,
                secure_capture_flag=secure_capture,
                claimed_location=claimed_location
            )

            # -------------------------
            # Quick Summary UI
            # -------------------------
            st.subheader("🔍 Quick Summary")
            st.write(f"**Authenticity Score:** {analysis['authenticity']['score']} / 100")
            st.write(f"**Overall Finding:** {analysis['executive_summary']['overall_finding']}")

            st.subheader("⚠️ Risk Factors")
            st.json(analysis["risk_classification"]["risk_factors"])

            # Heatmap preview
            heatmap_path = analysis["tampering"].get("heatmap_path")
            if heatmap_path and os.path.exists(heatmap_path):
                st.subheader("🔥 Tampering Heatmap")
                st.image(heatmap_path, width="stretch")

            # -------------------------
            # Generate PDF
            # -------------------------
            pdf_path = os.path.join("reports", f"{report_id}.pdf")
            build_pdf_report(analysis, pdf_path, report_id)

            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="📄 Download Forensic Report (PDF)",
                    data=f,
                    file_name=f"{report_id}.pdf",
                    mime="application/pdf"
                )


# -------------------------
# Router
# -------------------------
if not st.session_state.logged_in:
    if st.session_state.page == "register":
        register_page()
    else:
        login_page()
else:
    main_app()
