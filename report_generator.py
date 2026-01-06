from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def line(c, y, text):
    c.drawString(40, y, text)
    return y - 18


def generate_pdf_report(analysis, report_id, output_path):
    c = canvas.Canvas(output_path, pagesize=A4)
    width, height = A4
    y = height - 40

    y = line(c, y, "PinIT Image Forensics & Risk Assessment Report")
    y = line(c, y, f"Report ID: {report_id}")
    y = line(c, y, "-" * 80)

    # Executive Summary
    y = line(c, y, "1. Executive Summary")
    y = line(c, y, f"Overall Risk: {analysis['risk_label']}")
    y = line(c, y, f"Authenticity Score: {analysis['authenticity_score']} / 100")

    y = line(c, y, "")

    # Image Overview
    y = line(c, y, "2. Image Overview")
    y = line(c, y, f"Type: {analysis['image']['type']}")
    y = line(c, y, f"File Size: {analysis['image']['size']} bytes")

    y = line(c, y, "")

    # Metadata
    y = line(c, y, "3. Metadata Analysis")
    y = line(c, y, f"Timestamp: {analysis['exif']['datetime']}")
    y = line(c, y, f"GPS Present: {bool(analysis['exif']['gps'])}")
    y = line(c, y, f"Software: {analysis['exif']['software']}")

    y = line(c, y, "")

    # Tampering
    y = line(c, y, "4. Tampering & Manipulation Analysis")
    y = line(c, y, f"ELA Score: {analysis['tampering']['ela']}")
    y = line(c, y, f"Tampering Probability: {analysis['tampering']['probability']}%")

    y = line(c, y, "")

    # AI Detection
    y = line(c, y, "5. AI / Synthetic Content Detection")
    y = line(c, y, f"AI Detection Enabled: {analysis['ai']['enabled']}")
    y = line(c, y, f"AI Risk Score: {analysis['ai']['score']} / 10")

    y = line(c, y, "")

    # Legal
    y = line(c, y, "6. Legal Disclaimer")
    y = line(c, y, "Automated forensic analysis. Use alongside human judgment.")

    c.save()
