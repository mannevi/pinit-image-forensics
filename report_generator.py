import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet


def safe(d, key, default="N/A"):
    return d[key] if key in d else default


def build_pdf_report(analysis: dict, pdf_path: str, report_id: str):
    styles = getSampleStyleSheet()
    story = []

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    story.append(Paragraph("PinIT Image Forensics & Risk Assessment Report", styles["Title"]))
    story.append(Spacer(1, 12))

    ov = analysis["image_overview"]

    overview_table = Table(
        [
            ["Field", "Value"],
            ["Image Type", safe(ov, "image_type")],
            ["File Size", f"{safe(ov, 'file_size_mb')} MB"],
            ["Resolution", safe(ov, "resolution")],
            ["Color Space", safe(ov, "color_space")],              # ✅ SAFE
            ["Compression Artifacts", safe(ov, "compression_artifacts")],  # ✅ SAFE
            ["SHA-256", analysis["file_hash"]["sha256"]],
        ],
        colWidths=[6 * cm, 10 * cm],
    )

    story.append(overview_table)
    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            f"Authenticity Score: {analysis['authenticity']['score']} / 100",
            styles["Normal"],
        )
    )

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "This report is generated using automated forensic analysis and should be reviewed by a human investigator.",
            styles["Italic"],
        )
    )

    doc.build(story)
