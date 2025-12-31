import streamlit as st
import uuid
import os

from auth import init_db, register_user, verify_login
from real_analysis import analyze_image
from report_generator import build_pdf_report


# ---------------------------
# INITIAL SETUP
# ---------------------------
st.set_page_config(page_title="PinIT Forensics", layout="centered")
init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None


# ---------------------------
# AUTH PAGES
# ---------------------------
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


def register_page():
    st.title("📝 Create PinIT Account")

    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if password != confirm:
            st.error("Passwords do not match")
        elif register_user(username, password):
            st.success("Account created. Please login.")
            st.session_state.page = "login"
            st.rerun()
        else:
            st.error("Username already exists")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()


# ---------------------------
# MAIN APP (AFTER LOGIN)
# ---------------------------
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
    secure_capture = st.checkbox("Captured using PinIT Secure Capture")
    claimed_location = st.text_input("Claimed Capture Location (optional)")

    if uploaded:
        os.makedirs("uploads", exist_ok=True)
        os.makedirs("reports", exist_ok=True)

        path = os.path.join("uploads", uploaded.name)
        with open(path, "wb") as f:
            f.write(uploaded.read())

        st.image(path, width="stretch")

        if st.button("Generate Report"):
            report_id = f"PINIT-{uuid.uuid4()}"

            analysis = analyze_image(
                path,
                uploaded.name,
                secure_capture,
                claimed_location
            )

            pdf_path = f"reports/{report_id}.pdf"
            build_pdf_report(analysis, pdf_path, report_id)

            with open(pdf_path, "rb") as f:
                st.download_button(
                    "Download Forensic Report",
                    f,
                    file_name=f"{report_id}.pdf"
                )


# ---------------------------
# ROUTING LOGIC
# ---------------------------
if "page" not in st.session_state:
    st.session_state.page = "login"

if not st.session_state.logged_in:
    if st.session_state.page == "register":
        register_page()
    else:
        login_page()
else:
    main_app()
