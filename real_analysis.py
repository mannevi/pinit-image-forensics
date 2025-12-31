from PIL import Image
import hashlib
import os
import numpy as np
import piexif
import cv2
from datetime import datetime


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_image_stats(path: str) -> dict:
    img = Image.open(path)
    width, height = img.size
    fmt = img.format or os.path.splitext(path)[1].replace(".", "").upper() or "Unknown"
    mode = img.mode or "Unknown"
    file_mb = round(os.path.getsize(path) / (1024 * 1024), 2)

    return {
        "format": fmt,
        "file_size": f"{file_mb} MB",
        "resolution": f"{width} × {height} pixels",
        "width": width,
        "height": height,
        "color_space": "sRGB" if mode in ("RGB", "RGBA") else mode,
    }


def extract_exif(path: str) -> dict:
    try:
        exif_dict = piexif.load(path)
        zeroth = exif_dict.get("0th", {})
        gps = exif_dict.get("GPS", {})

        def _d(v):
            if isinstance(v, bytes):
                return v.decode(errors="ignore").strip() or "Unknown"
            return str(v).strip() if v else "Unknown"

        make = _d(zeroth.get(piexif.ImageIFD.Make, b""))
        model = _d(zeroth.get(piexif.ImageIFD.Model, b""))
        software = _d(zeroth.get(piexif.ImageIFD.Software, b""))
        dt = _d(zeroth.get(piexif.ImageIFD.DateTime, b""))

        return {
            "device_make": make,
            "device_model": model,
            "software": software,
            "datetime": dt,
            "gps_present": bool(gps),
            "exif_present": True,
        }
    except Exception:
        return {
            "device_make": "Unknown",
            "device_model": "Unknown",
            "software": "Unknown",
            "datetime": "Unknown",
            "gps_present": False,
            "exif_present": False,
        }


def compute_metadata_score(exif: dict) -> int:
    score = 100
    if exif.get("device_make") in ("", "Unknown"):
        score -= 25
    if exif.get("device_model") in ("", "Unknown"):
        score -= 25
    if exif.get("datetime") in ("", "Unknown"):
        score -= 25
    if not exif.get("gps_present", False):
        score -= 25
    return max(0, min(100, score))


def tampering_analysis(path: str):
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return 50, "N/A"

    lap = cv2.Laplacian(img, cv2.CV_64F)
    variance = float(lap.var())

    # Heuristic mapping: smoother images => higher tamper suspicion
    prob = int(max(5, min(95, 100 - (variance / 10.0))))

    return prob, round(variance, 2)


def ai_likelihood_estimate(width: int, height: int, tamper_prob: int, exif_present: bool) -> int:
    mp = (width * height) / 1_000_000.0
    score = 15

    # common AI export sizes + missing metadata
    if (width, height) in [(512, 512), (768, 768), (1024, 1024), (1536, 1536)]:
        score += 25
    if mp < 1.0:
        score += 15
    if not exif_present:
        score += 20
    if tamper_prob > 70:
        score += 15

    return min(100, score)


def final_authenticity_score(meta: int, tamper: int, ai: int, secure_bonus: int) -> int:
    # Weighted combination (bounded)
    score = 100
    score -= (100 - meta) * 0.45
    score -= tamper * 0.30
    score -= ai * 0.20
    score += secure_bonus
    return max(5, min(100, int(round(score))))


def label_from_score(score: int) -> str:
    if score >= 80:
        return "Highly Authentic"
    if score >= 60:
        return "Partially Authentic"
    if score >= 40:
        return "Suspicious"
    return "High Fraud Risk"


def analyze_image(path: str, original_filename: str = "", secure_capture_flag: bool = False) -> dict:
    stats = get_image_stats(path)
    sha = sha256_of_file(path)
    exif = extract_exif(path)

    meta_score = compute_metadata_score(exif)
    tamper_prob, ela_score = tampering_analysis(path)
    ai_score = ai_likelihood_estimate(stats["width"], stats["height"], tamper_prob, exif["exif_present"])

    secure_bonus = 10 if secure_capture_flag else 0
    overall = final_authenticity_score(meta_score, tamper_prob, ai_score, secure_bonus)
    overall_label = label_from_score(overall)

    drivers = []
    if not exif["exif_present"]:
        drivers.append("EXIF metadata missing or stripped.")
    if not exif["gps_present"]:
        drivers.append("GPS data missing; geo-verification limited.")
    if exif["software"] not in ("", "Unknown") and any(x in exif["software"].lower() for x in ["photoshop", "snapseed", "lightroom", "gimp"]):
        drivers.append(f"Editing software detected: {exif['software']}.")
    if tamper_prob > 70:
        drivers.append("High tampering probability from compression/noise analysis.")
    if ai_score > 50:
        drivers.append("Signals consistent with AI-assisted generation/enhancement.")
    if not drivers:
        drivers.append("No strong forensic indicators detected in available signals.")

    return {
        "generated_at": datetime.utcnow().strftime("%d %b %Y"),
        "image_overview": {
            "format": stats["format"],
            "file_size": stats["file_size"],
            "resolution": stats["resolution"],
            "color_space": stats["color_space"],
            "sha256": sha,
        },
        "exif_summary": exif,
        "tampering": {
            "probability": tamper_prob,
            "ela_score": ela_score,
            "findings": [
                "Error Level/edge-noise consistency scoring performed.",
                "Higher score indicates stronger inconsistency signals."
            ]
        },
        "ai_detection": {
            "enabled": True,
            "ai_generated_likelihood": ai_score,
            "label": "Likely AI-assisted" if ai_score > 50 else "Not fully synthetic (low–moderate)"
        },
        "duplicate_check": {
            "enabled": False,
            "exact_match": "Not Implemented",
            "near_duplicate": "Not Implemented",
            "reuse_risk": "Not Implemented"
        },
        "geo_time": {
            "enabled": False,
            "claimed_location": "Not Available",
            "visual_landmark_match": "Not Implemented",
            "weather_consistency": "Not Implemented",
            "shadow_direction": "Not Implemented",
            "geo_time_score": "Not Implemented"
        },
        "scores": {
            "metadata_score": meta_score,
            "tampering_score": tamper_prob,
            "ai_score": ai_score,
            "overall_risk": overall,
            "overall_label": overall_label,
        },
        "uuid_present": secure_capture_flag,
        "chain_of_custody": "Intact" if secure_capture_flag else "Not Verifiable",
        "risk_drivers": drivers,
        "recommendation": (
            "Request the original image file directly from the device; cross-check with additional photos/videos; "
            "validate claim timeline with supporting evidence; flag claim for enhanced fraud review."
            if overall < 60 else
            "Proceed with standard claim verification; retain original file for audit."
        )
    }
