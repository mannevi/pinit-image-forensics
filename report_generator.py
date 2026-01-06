from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def line(c, y, t):
    c.drawString(40, y, t)
    return y - 16


def generate_pdf_report(data, report_id, path):
    c = canvas.Canvas(path, pagesize=A4)
    y = A4[1] - 40

    y = line(c, y, "PinIT Image Forensics & Risk Assessment Report")
    y = line(c, y, f"Report ID: {report_id}")
    y = line(c, y, "-" * 80)

    y = line(c, y, f"Authenticity Score: {data['authenticity_score']} / 100")
    y = line(c, y, f"AI Risk Score: {data['ai']['score']} / 10")

    y = line(c, y, "")
    y = line(c, y, "Key Observations:")
    for e in data["explanations"]:
        y = line(c, y, f"- {e}")

    y = line(c, y, "")
    y = line(c, y, f"ELA Score: {data['tampering']['ela']}")
    y = line(c, y, f"Tampering Probability: {data['tampering']['probability']}%")

    y = line(c, y, "")
    y = line(c, y, "Legal Disclaimer")
    y = line(c, y, "Automated analysis. Use alongside human judgment.")

    c.save()
