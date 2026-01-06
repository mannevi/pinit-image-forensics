from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def line(c, y, text):
    c.drawString(40, y, text)
    return y - 16


def generate_pdf_report(analysis, report_id, output_path):
    c = canvas.Canvas(output_path, pagesize=A4)
    y = A4[1] - 40

    y = line(c, y, "PinIT Image Forensics & Risk Assessment Report")
    y = line(c, y, f"Report ID: {report_id}")
    y = line(c, y, "-" * 80)

    y = line(c, y, "1. Executive Summary")
    y = line(c, y, f"Authenticity Score: {analysis['authenticity_score']} / 100")

    y = line(c, y, "")
    y = line(c, y, "2. Key Observations")
    for e in analysis["explanations"]:
        y = line(c, y, f"- {e}")

    y = line(c, y, "")
    y = line(c, y, "3. Tampering Analysis")
    y = line(c, y, f"ELA Score: {analysis['tampering']['ela']}")
    y = line(c, y, f"Tampering Probability: {analysis['tampering']['probability']}%")

    y = line(c, y, "")
    y = line(c, y, "4. AI Detection")
    y = line(c, y, f"AI Risk Score: {analysis['ai']['score']} / 10")

    y = line(c, y, "")
    y = line(c, y, "5. Legal Disclaimer")
    y = line(c, y, "Automated analysis. Use alongside human judgment.")

    c.save()
