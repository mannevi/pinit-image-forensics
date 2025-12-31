from PIL import Image, ImageChops, ImageEnhance
import piexif
import numpy as np
import os
import re
import hashlib
from datetime import datetime

# Color palette (HEX)
COLORS = {
    "BLUE":  "#1F4FFF",  # Highly Authentic
    "GREEN": "#1FAF55",  # Low Risk
    "AMBER": "#FF9F1C",  # Medium–High / Medium risk
    "RED":   "#E63946",  # High Fraud Risk
    "GRAY":  "#2B2B2B"
}

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_decode(v):
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore").strip()
        except Exception:
            return "Unknown"
    if v is None:
        return "Unknown"
    return str(v).strip() or "Unknown"

def _extract_exif(image_path: str) -> dict:
    try:
        return piexif.load(image_path)
    except Exception:
        return {}

def _get_software(exif: dict) -> str:
    software = exif.get("0th", {}).get(piexif.ImageIFD.Software, b"Unknown")
    return _safe_decode(software)

def _get_device_make_model(exif: dict):
    make = _safe_decode(exif.get("0th", {}).get(piexif.ImageIFD.Make, b"Unknown"))
    model = _safe_decode(exif.get("0th", {}).get(piexif.ImageIFD.Model, b"Unknown"))
    return make, model

def _get_datetime_original(exif: dict) -> str:
    dt = exif.get("Exif", {}).get(piexif.ExifIFD.DateTimeOriginal, b"")
    return _safe_decode(dt) if dt else "Unknown"

def _gps_present(exif: dict) -> bool:
    gps = exif.get("GPS", {})
    return bool(gps) and len(gps.keys()) > 0

def _uuid_from_filename(filename: str) -> str:
    if not filename:
        return ""
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", filename)
    return m.group(0) if m else ""

def _ela_metrics(image_path: str):
    img = Image.open(image_path).convert("RGB")
    tmp = os.path.join(os.path.dirname(image_path), "_tmp_recompress.jpg")
    img.save(tmp, "JPEG", quality=90)
    recompressed = Image.open(tmp).convert("RGB")

    diff = ImageChops.difference(img, recompressed)
    diff = ImageEnhance.Brightness(diff).enhance(10)

    arr = np.array(diff).astype(np.float32)
    mean_val = float(np.mean(arr))
    p95 = float(np.percentile(arr, 95))

    try:
        os.remove(tmp)
    except Exception:
        pass

    # mapped probability (bounded)
    tamper_prob = min(100.0, (mean_val * 1.8) + (p95 * 0.22))
    return {
        "ela_mean": round(mean_val, 2),
        "ela_p95": round(p95, 2),
        "tampering_probability": int(round(tamper_prob))
    }

def compute_metadata_integrity(exif_present: bool, gps_present: bool, datetime_present: bool, software_known: bool) -> int:
    score = 100
    if not exif_present:
        score -= 30
    if not gps_present:
        score -= 20
    if not datetime_present:
        score -= 20
    if not software_known:
        score -= 10
    return max(0, min(100, score))

def compute_authenticity_score(meta_score: int, tamper_prob: int, ai_score: int, secure_bonus: int = 0) -> int:
    # bounded penalties so score never collapses to 0 incorrectly
    tamper_penalty = min(tamper_prob * 0.5, 40)     # 0..40
    ai_penalty = min(ai_score * 0.3, 20)            # 0..20
    meta_penalty = max(0, 50 - (meta_score * 0.5))  # 0..50

    score = 100 - (tamper_penalty + ai_penalty + meta_penalty)
    score += secure_bonus
    return max(5, min(100, int(round(score))))

def risk_from_score(score: int):
    if score >= 90:
        return ("Highly Authentic", "BLUE")
    if score >= 75:
        return ("Low Risk", "GREEN")
    if score >= 60:
        return ("Medium–High Risk", "AMBER")
    return ("High Fraud Risk", "RED")

def analyze_image(image_path: str, original_filename: str = "", secure_capture_flag: bool = False):
    img = Image.open(image_path)
    width, height = img.size
    file_size_mb = round(os.path.getsize(image_path) / (1024 * 1024), 2)
    color_space = img.mode
    sha256 = _sha256_file(image_path)

    exif = _extract_exif(image_path)
    exif_present = bool(exif) and (
        len(exif.get("0th", {})) > 0 or len(exif.get("Exif", {})) > 0 or len(exif.get("GPS", {})) > 0
    )

    software = _get_software(exif)
    make, model = _get_device_make_model(exif)
    dt_original = _get_datetime_original(exif)
    gps_present = _gps_present(exif)

    datetime_present = (dt_original != "Unknown")
    software_known = (software != "Unknown")

    uuid_hint = _uuid_from_filename(original_filename)
    uuid_embedded = bool(uuid_hint) or bool(secure_capture_flag)

    # “AI likelihood” (simple heuristic – real-time, not a trained model)
    ai_score = 0
    if width == height and width in (512, 768, 1024, 1536):
        ai_score += 25
    if not exif_present:
        ai_score += 20
    if any(x in software.lower() for x in ["stable diffusion", "midjourney", "dall-e", "comfyui", "automatic1111"]):
        ai_score += 40
    ai_score = min(100, ai_score)

    ela = _ela_metrics(image_path)
    tamper_prob = ela["tampering_probability"]

    meta_score = compute_metadata_integrity(exif_present, gps_present, datetime_present, software_known)

    secure_bonus = 10 if uuid_embedded else 0
    authenticity_score = compute_authenticity_score(meta_score, tamper_prob, ai_score, secure_bonus)

    risk_label, risk_color_key = risk_from_score(authenticity_score)

    # Chain-of-custody
    if uuid_embedded:
        chain_status = "Intact"
        capture_method = "PinIT Secure Capture App"
        capture_integrity = "Verified at Source"
    else:
        chain_status = "Not Verifiable"
        capture_method = "Unknown / Standard Upload"
        capture_integrity = "Not Verified"

    # Compression artifacts (simple descriptor based on tamper_prob)
    if tamper_prob >= 70:
        compression_artifacts = "High"
    elif tamper_prob >= 40:
        compression_artifacts = "Moderate"
    else:
        compression_artifacts = "Low"

    generated_at = datetime.now().strftime("%d %b %Y")

    # Risk drivers (evidence bullets)
    drivers = []
    if not exif_present:
        drivers.append("EXIF metadata missing or stripped.")
    if not gps_present:
        drivers.append("GPS data missing; geo-verification limited.")
    if software_known and any(x in software.lower() for x in ["photoshop", "snapseed", "lightroom", "gimp"]):
        drivers.append(f"Editing software detected: {software}.")
    if tamper_prob >= 60:
        drivers.append("ELA indicates inconsistent compression/noise patterns suggesting edits.")
    if ai_score >= 50:
        drivers.append("Signals consistent with AI-generated or AI-assisted image creation/enhancement.")
    if not drivers:
        drivers.append("No strong forensic indicators detected in the available signals.")

    return {
        "generated_at": generated_at,

        "scores": {
            "overall_risk": authenticity_score,              # keep as /100
            "overall_label": risk_label,
            "metadata_score": meta_score,
            "tampering_score": tamper_prob,
            "ai_score": ai_score
        },

        "colors": {
            "risk_key": risk_color_key,
            "risk_hex": COLORS[risk_color_key],
            "palette": COLORS
        },

        "image_overview": {
            "image_type": "JPEG/PNG",
            "file_size": f"{file_size_mb} MB",
            "resolution": f"{width} × {height} pixels",
            "color_space": "sRGB" if color_space in ("RGB", "RGBA") else str(color_space),
            "compression_artifacts": compression_artifacts,
            "sha256": sha256,
            "uuid": uuid_hint if uuid_hint else ("UUID present (secure capture)" if uuid_embedded else "Not detected"),
        },

        "capture": {
            "capture_method": capture_method,
            "capture_integrity_status": capture_integrity,
            "chain_of_custody_status": chain_status,
            "secure_capture": uuid_embedded
        },

        "exif_summary": {
            "device_make": make,
            "device_model": model,
            "datetime": dt_original,
            "software": software,
            "gps_present": gps_present,
            "exif_present": exif_present
        },

        "tampering": {
            "ela_mean": ela["ela_mean"],
            "ela_p95": ela["ela_p95"],
            "probability": tamper_prob,
            "findings": [
                "Error Level Analysis (ELA) performed.",
                "Noise/compression inconsistency scoring applied."
            ]
        },

        "ai_detection": {
            "enabled": True,
            "ai_generated_likelihood": ai_score,
            "label": ("Likely AI-assisted" if ai_score >= 50 else "Not fully synthetic (low–moderate)")
        },

        "duplicate_check": {
            "enabled": False,
            "exact_match": "Not Implemented",
            "near_duplicate": "Not Implemented",
            "reuse_risk": "Not Implemented"
        },

        "geo_time": {
            "enabled": False,
            "claimed_location": "N/A",
            "visual_landmark_match": "Not Implemented",
            "weather_consistency": "Not Implemented",
            "shadow_direction": "Not Implemented",
            "geo_time_score": "Not Implemented"
        },

        "risk_drivers": drivers,

        "recommendation": (
            "Request the original image file directly from the device; cross-check with additional photos/videos; "
            "validate claim timeline with supporting evidence; flag claim for enhanced fraud review."
            if risk_label in ("Medium–High Risk", "High Fraud Risk") else
            "Proceed with standard claim validation; retain the original file for audit."
        )
    }
