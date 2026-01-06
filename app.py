import streamlit as st
import os
import uuid

from real_analysis import analyze_image
from report_generator import generate_pdf_report

st.set_page_config(page_title="PinIT Image Forensics", layout="centered")
st.title("🕵️ PinIT Image Forensics & Risk Assessment")

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

uploaded_file = st.file_uploader(
    "Upload an image", type=["jpg", "jpeg", "png"]
)

if uploaded_file:
    st.image(uploaded_file, caption="Uploaded Image", use_column_width=True)

    filename = f"{uuid.uuid4()}_{uploaded_file.name}"
    image_path = os.path.join(UPLOAD_FOLDER, filename)

    with open(image_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    with st.spinner("Analyzing image..."):
        analysis = analyze_image(image_path)

    score = analysis["authenticity_score"]

    if score >= 75:
        risk_label = "Low Fraud Risk"
    elif score >= 45:
        risk_label = "Medium Fraud Risk"
    else:
        risk_label = "High Fraud Risk"

    st.subheader("🔍 Analysis Result")
    st.metric("Authenticity Score", f"{score} / 100")
    st.metric("Risk Classification", risk_label)

    st.subheader("🧠 Explanation")
    for e in analysis["explanations"]:
        st.write("•", e)

    report_id = f"PINIT-{uuid.uuid4()}"
    pdf_path = os.path.join(REPORT_FOLDER, f"{report_id}.pdf")

    generate_pdf_report(analysis, report_id, pdf_path)

    with open(pdf_path, "rb") as pdf:
        st.download_button(
            "📄 Download PDF Report",
            data=pdf,
            file_name=f"{report_id}.pdf",
            mime="application/pdf",
        )
