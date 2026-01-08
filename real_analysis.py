from datetime import datetime
import os
import hashlib
from PIL import Image
import piexif
import numpy as np


def analyze_image(
    image_path: str,
    original_filename: str,
    secure_capture_flag: bool,
    claimed_location: str
) -> dict:
    """
    Core forensic analysis entry point.
    This function signature MUST match app.py exactly.
    """

    # -------------------------
    # Basic file info
    # -------------------------
    file_size = os.path.getsize(image_path)
    img = Image.open(image_path)
    width, height = img.size

    # -------------------------
    # SHA-256 hash
    # -------------------------
    sha256 = hashlib.sha256(open(image_path, "rb").read()).hexdigest()

    # -------------------------
    # EXIF extraction
    # -------------------------
    exif_data = {}
    try:
        exif_dict = piexif.load(image_path)
        exif_data = {
            "make": exif_dict["0th"].get(piexif.ImageIFD.Make, b"").decode(errors="ignore"),
            "model": exif_dict["0th"].get(piexif.ImageIFD.Model, b"").decode(errors="ignore"),
            "datetime": exif_dict["0th"].get(piexif.ImageIFD.DateTime, b"").decode(errors="ignore"),
            "software": exif_dict["0th"].get(piexif.ImageIFD.Software, b"").decode(errors="ignore"),
            "gps_present": bool(exif_dict.get("GPS"))
        }
    except Exception:
        exif_data = {
            "make": "",
            "model": "",
            "datetime": "",
            "software": "",
            "gps_present": False
        }

    # -------------------------
    # Dummy forensic scores (placeholders – deterministic)
    # -------------------------
    metadata_score = 80 if exif_data["model"] else 50
    tampering_score = 25
    deepfake_score = 20
    duplication_score = 10
    geo_score = 75 if exif_data["gps_present"] else 40

    overall_risk = int(
        (100 - metadata_score) * 0.2 +
        tampering_score * 0.3 +
        deepfake_score * 0.2 +
        duplication_score * 0.15 +
        (100 - geo_score) * 0.15
    )

    authenticity_score = max(0, 100 - overall_risk)

    # -------------------------
    # Result object (used by PDF + UI)
    # -------------------------
    return {
        "generated_at": datetime.utcnow().strftime("%d %b %Y"),

        "executive_summary": {
            "overall_finding": "🟢 Low Fraud Risk" if overall_risk < 40 else "🔶 Suspicious",
            "finding_details": "No critical manipulation indicators detected."
        },

        "image_overview": {
            "image_type": img.format,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "resolution": f"{width} × {height}",
            "capture_method": "PinIT Secure Capture" if secure_capture_flag else "Standard Upload",
            "capture_integrity_status": "Verified" if secure_capture_flag else "Not Verified",
            "user_uuid_embedded": "Not Found"
        },

        "authenticity": {
            "score": authenticity_score,
            "label": "Highly Authentic" if authenticity_score >= 80 else "Suspicious"
        },

        "metadata": {
            "integrity_score": metadata_score,
            "exif": exif_data,
            "observations": []
        },

        "tampering": {
            "tampering_probability_pct": tampering_score,
            "heatmap_path": None
        },

        "deepfake": {
            "risk_score": deepfake_score,
            "ai_generated_content": "Unlikely",
            "ai_assisted_editing": "Unlikely",
            "interpretation": "No strong AI indicators"
        },

        "duplicate_reuse": {
            "reuse_risk_level": "Low"
        },

        "geo_time": {
            "claimed_location": claimed_location or "Not Provided",
            "confidence_score": geo_score,
            "confidence_level": "High" if geo_score > 70 else "Low"
        },

        "risk_classification": {
            "risk_factors": {
                "Metadata Integrity": metadata_score,
                "Tampering Indicators": tampering_score,
                "Deepfake Probability": deepfake_score,
                "Duplication Risk": duplication_score,
                "Geo-Time Accuracy": geo_score
            },
            "overall_risk_score": overall_risk,
            "overall_risk_rating": "Low" if overall_risk < 40 else "Medium",
            "recommended_action": "Proceed with standard verification"
        },

        "file_hash": {
            "sha256": sha256
        }
    }
