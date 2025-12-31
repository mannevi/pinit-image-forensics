import streamlit as st
import uuid
import os

from real_analysis import analyze_image
from report_generator import build_pdf_report

st.set_page_config(page_title="PinIT Forensics", layout="centered")
st.title("PinIT Image Forensics Platform")

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
            st.download_button("Download Report", f, file_name=f"{report_id}.pdf")
