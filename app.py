import streamlit as st
import uuid
import os

from real_analysis import analyze_image
from report_generator import build_pdf_report

st.set_page_config(page_title="PinIT Forensics", layout="centered")
st.title("PinIT Image Forensics Platform")

uploaded = st.file_uploader("Upload Image", type=["jpg", "jpeg", "png"])
secure_capture = st.checkbox("This image was captured using PinIT Secure Capture", value=False)

if uploaded:
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    img_path = os.path.join("uploads", uploaded.name)
    with open(img_path, "wb") as f:
        f.write(uploaded.read())

    st.image(img_path, caption="Uploaded Image", width="stretch")

    if st.button("Generate Forensics Report"):
        report_id = f"PINIT-{uuid.uuid4()}"

        analysis = analyze_image(
            img_path,
            original_filename=uploaded.name,
            secure_capture_flag=secure_capture
        )

        pdf_path = os.path.join("reports", f"{report_id}.pdf")

        build_pdf_report(analysis, pdf_path, report_id)

        with open(pdf_path, "rb") as f:
            st.download_button(
                "Download PDF Report",
                f,
                file_name=f"{report_id}.pdf",
                mime="application/pdf"
            )
