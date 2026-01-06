import streamlit as st
import os
import uuid
from real_analysis import analyze_image
from report_generator import generate_pdf_report

st.set_page_config(page_title="PinIT Image Forensics")
st.title("🕵️ PinIT Image Forensics")

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

uploaded = st.file_uploader("Upload image", type=["jpg", "jpeg", "png"])

if uploaded:
    st.image(uploaded, use_column_width=True)

    path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}_{uploaded.name}")
    with open(path, "wb") as f:
        f.write(uploaded.getbuffer())

    with st.spinner("Analyzing image..."):
        result = analyze_image(path)

    score = result["authenticity_score"]

    if score >= 75:
        risk = "Low Fraud Risk"
    elif score >= 45:
        risk = "Medium Fraud Risk"
    else:
        risk = "High Fraud / Synthetic Risk"

    st.metric("Authenticity Score", f"{score} / 100")
    st.metric("Risk Classification", risk)
    st.metric("AI Risk Score", f"{result['ai']['score']} / 10")

    st.subheader("Explanation")
    for e in result["explanations"]:
        st.write("•", e)

    report_id = f"PINIT-{uuid.uuid4()}"
    pdf_path = os.path.join(REPORT_FOLDER, f"{report_id}.pdf")
    generate_pdf_report(result, report_id, pdf_path)

    with open(pdf_path, "rb") as f:
        st.download_button("📄 Download PDF Report", f, file_name=f"{report_id}.pdf")
