from flask import Flask, render_template, request, send_file
import os
import uuid

from real_analysis import analyze_image
from report_generator import generate_pdf_report

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("image")

        if not file:
            return "No file uploaded", 400

        filename = f"{uuid.uuid4()}_{file.filename}"
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(image_path)

        analysis = analyze_image(image_path)

        score = analysis["authenticity_score"]

        if score >= 75:
            risk_label = "Low Fraud Risk"
        elif score >= 45:
            risk_label = "Medium Fraud Risk"
        else:
            risk_label = "High Fraud Risk"

        analysis["risk_label"] = risk_label

        report_id = f"PINIT-{uuid.uuid4()}"
        pdf_path = os.path.join(REPORT_FOLDER, f"{report_id}.pdf")

        generate_pdf_report(
            analysis=analysis,
            report_id=report_id,
            output_path=pdf_path
        )

        return send_file(pdf_path, as_attachment=True)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
