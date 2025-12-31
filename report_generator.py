from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
import os


def line(c, y, text):
    c.drawString(2 * cm, y, text)
    return y - 14


def build_pdf_report(analysis, pdf_path, report_id):
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    y = 28 * cm

    s = analysis["scores"]
    i = analysis["image"]
    ex = analysis["exif"]
    t = analysis["tampering"]
    ai = analysis["ai"]
    ch = analysis["chain"]

    c.setFont("Helvetica-Bold", 14)
    y = line(c, y, "PinIT Image Forensics & Risk Assessment Report")

    c.setFont("Helvetica", 10)
    y = line(c, y, f"Report ID: {report_id}")
    y = line(c, y, f"Date: {analysis['generated_at']}")

    y = line(c, y, "\n1. Executive Summary")
    y = line(c, y, f"Overall Finding: {s['label']} ({s['overall']} / 100)")

    y = line(c, y, "\n2. Image Overview")
    y = line(c, y, f"Type: {i['type']}")
    y = line(c, y, f"Resolution: {i['resolution']}")
    y = line(c, y, f"File Size: {i['size_mb']} MB")
    y = line(c, y, f"SHA-256: {i['sha256']}")

    y = line(c, y, "\n3. Image Authenticity Score")
    y = line(c, y, f"{s['overall']} / 100")

    y = line(c, y, "\n4. Capture Encryption & Chain of Custody")
    y = line(c, y, f"Secure Capture: {ch['secure_capture']}")
    y = line(c, y, f"Encryption: {ch['encryption']}")
    y = line(c, y, f"Transport: {ch['tls']}")

    y = line(c, y, "\n5. Metadata Analysis Report")
    y = line(c, y, f"Device: {ex.get('make','Unknown')} {ex.get('model','')}")
    y = line(c, y, f"Timestamp: {ex.get('datetime','Unknown')}")
    y = line(c, y, f"Software: {ex.get('software','Unknown')}")
    y = line(c, y, f"GPS Present: {ex.get('gps_present', False)}")

    y = line(c, y, "\n6. Tampering & Manipulation Analysis")
    y = line(c, y, f"ELA Score: {t['ela']}")
    y = line(c, y, f"Tampering Probability: {t['probability']}%")

    y = line(c, y, "\n7. Deepfake & Synthetic Content Detection")
    y = line(c, y, f"AI Detection Enabled: {ai['enabled']}")
    y = line(c, y, f"AI Risk Score: {ai['score']}")

    y = line(c, y, "\n8. Duplicate & Reuse Image Check")
    y = line(c, y, "Not Implemented")

    y = line(c, y, "\n9. Geo & Timestamp Verification")
    if ex.get("gps_present"):
        y = line(c, y, f"GPS Coordinates: {ex['latitude']}, {ex['longitude']}")
        y = line(c, y, "Verification Source: Embedded EXIF")
        y = line(c, y, "Geo-Time Confidence: Medium–High")
    else:
        y = line(c, y, f"Claimed Location: {analysis.get('claimed_location') or 'Not Provided'}")
        y = line(c, y, "Verification Source: User Declaration")
        y = line(c, y, "Geo-Time Confidence: Not Independently Verifiable")

    y = line(c, y, "\n10. Risk Classification")
    y = line(c, y, f"Overall Risk Rating: {s['label']}")

    y = line(c, y, "\n11. PinIT Recommendation")
    y = line(c, y, "Proceed with appropriate verification based on risk level.")

    y = line(c, y, "\n12. Legal & Compliance Disclaimer")
    y = line(c, y, "Automated forensic analysis. Use alongside human judgment.")

    c.save()
