import streamlit as st
import uuid
import os

from auth import init_db, register_user, verify_login
from real_analysis import analyze_image
from report_generator import generate_report

st.set_page_config(page_title="PinIT Forensics", layout="centered")

init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_email" not in st.session_state:
    st.session_state.user_email = ""

st.title("PinIT Image Forensics Platform")

# ---------------- AUTH ----------------
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab2:
        st.subheader("Register")
        reg_email = st.text_input("Email", key="reg_email")
        reg_pass = st.text_input("Password", type="password", key="reg_pass")
        if st.button("Create Account"):
            ok, msg = register_user(reg_email, reg_pass)
            (st.success if ok else st.error)(msg)

    with tab1:
        st.subheader("Login")
        log_email = st.text_input("Email", key="log_email")
        log_pass = st.text_input("Password", type="password", key="log_pass")
        if st.button("Login"):
            ok, msg = verify_login(log_email, log_pass)
            if ok:
                st.session_state.logged_in = True
                st.session_state.user_email = log_email.strip().lower()
                st.success(msg)
            else:
                st.error(msg)

    st.stop()

# ---------------- MAIN APP ----------------
st.success(f"Logged in as {st.session_state.user_email}")

st.markdown("### Upload Image")
uploaded = st.file_uploader("Choose an image", type=["jpg", "jpeg", "png"])

st.markdown("### Optional Capture Context")
secure_capture = st.checkbox("This image was captured using PinIT Secure Capture / UUID-secured flow", value=False)

if uploaded:
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    save_path = os.path.join("uploads", uploaded.name)
    with open(save_path, "wb") as f:
        f.write(uploaded.read())

    st.image(save_path, caption="Uploaded Image", use_container_width=True)

    if st.button("Generate Real-Time Report"):
        report_id = f"PINIT-{uuid.uuid4()}"
        analysis = analyze_image(
            image_path=save_path,
            filename_for_uuid=uploaded.name,
            user_claimed_secure_capture=secure_capture
        )

        pdf_path = os.path.join("reports", f"{report_id}.pdf")
        generate_report(pdf_path, report_id, analysis)

        st.markdown("### Result")
        st.write({
            "Authenticity Score": analysis["authenticity_score"],
            "Risk Label": analysis["risk_label"],
            "Risk Color": analysis["risk_color_hex"],
            "Tampering Probability": f"{analysis['tampering_probability']}%",
            "Chain of Custody": analysis["chain_of_custody_status"]
        })

        with open(pdf_path, "rb") as f:
            st.download_button(
                "⬇️ Download PDF Report",
                f,
                file_name=f"{report_id}.pdf",
                mime="application/pdf"
            )
