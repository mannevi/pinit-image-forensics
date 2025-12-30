from PIL import Image, ImageChops, ImageEnhance
import piexif
import numpy as np
import os
import re

# ----- Color System (HEX) -----
COLORS = {
    "BLUE":  "#1F4FFF",  # Highly Authentic
    "GREEN": "#1FAF55",  # Low Risk
    "AMBER": "#FF9F1C",  # Medium Risk
    "RED":   "#E63946",  # High Risk
    "GRAY":  "#2B2B2B"
}

def _safe_decode(v):
    if isinstance(v, bytes):
        try:
            return v.decode(errors="ignore")
        except Exception:
            return "Unknown"
    return str(v) if v is not None else "Unknown"

def _extract_exif(image_path):
    try:
        exif = piexif.load(image_path)
        return exif
    except Exception:
        return {}

def _get_software_tag(exif):
    software = exif.get("0th", {}).get(piexif.ImageIFD.Software, b"Unknown")
    return _safe_decode(software).strip() or "Unknown"

def _get_datetime_original(exif):
    dt = exif.get("Exif", {}).get(piexif.ExifIFD.DateTimeOriginal, b"")
    return _safe_decode(dt).strip() or "Unknown"

def _gps_present(exif):
    gps = exif.get("GPS", {})
    return bool(gps) and len(gps.keys()) > 0

def _uuid_hint_from_filename(filename: str) -> str:
    if not filename:
        return ""
    m = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", filename)
    return m.group(0) if m else ""

def _ai_like_heuristic(width, height, software_tag, exif_present):
    # Heuristic only (real-time): many AI images are 1024x1024 and have minimal/no EXIF.
    # This does NOT claim "AI generated", just increases risk if suspicious.
    score = 0
    if width == height and width in (512, 768, 1024, 1536):
        score += 12
    if not exif_present:
        score += 10
    if software_tag.lower() in ("unknown", ""):
        score += 4
    if any(x in software_tag.lower() for x in ["stable diffusion", "midjourney", "dall-e", "comfyui", "automatic1111"]):
        score += 18
    return min(30, score)

def _ela_metrics(image_path):
    img = Image.open(image_path).convert("RGB")
    tmp = os.path.join(os.path.dirname(image_path), "_tmp_recompress.jpg")
    img.save(tmp, "JPEG", quality=90)

    recompressed = Image.open(tmp).convert("RGB")
    diff = ImageChops.difference(img, recompressed)
    diff = ImageEnhance.Brightness(diff).enhance(10)

    arr = np.array(diff).astype(np.float32)
    mean_val = float(np.mean(arr))               # overall ELA magnitude
    p95 = float(np.percentile(arr, 95))          # strong anomalies
    os.remove(tmp)

    # Map to probabilities (bounded)
    tamper_prob = min(100.0, (mean_val * 2.0) + (p95 * 0.25))
    return {
        "ela_mean": round(mean_val, 2),
        "ela_p95": round(p95, 2),
        "tampering_probability": int(round(tamper_prob))
    }

def risk_from_score(score: int):
    # Score-driven risk system
    if score >= 90:
        return ("Highly Authentic", "BLUE")
    if score >= 75:
        return ("Low Risk", "GREEN")
    if score >= 60:
        return ("Medium Risk", "AMBER")
    return ("High Fraud Risk", "RED")

def analyze_image(image_path: str, filename_for_uuid: str = "", user_claimed_secure_capture: bool = False):
    img = Image.open(image_path)
    width, height = img.size
    file_size_mb = round(os.path.getsize(image_path) / (1024 * 1024), 2)
    color_space = img.mode

    exif = _extract_exif(image_path)
    exif_present = bool(exif) and (len(exif.get("0th", {})) > 0 or len(exif.get("Exif", {})) > 0)

    software_tag = _get_software_tag(exif)
    dt_original = _get_datetime_original(exif)
    gps_present = _gps_present(exif)

    # UUID detection (best-effort real-time)
    uuid_hint = _uuid_hint_from_filename(filename_for_uuid)
    uuid_embedded = bool(uuid_hint) or bool(user_claimed_secure_capture)

    # If UUID-secure capture, we should *not* claim software unknown
    if uuid_embedded and (software_tag == "Unknown"):
        software_tag = "PinIT Secure Capture (assumed via secure-capture flag/UUID)"

    # ELA metrics (real-time tampering signal)
    ela = _ela_metrics(image_path)

    # Scoring components (transparent & consistent)
    base = 100

    # Tampering penalty
    tamper_penalty = int(round(ela["tampering_probability"] * 0.55))  # 0..55
    base -= tamper_penalty

    # Metadata penalty
    meta_penalty = 0
    if not exif_present:
        meta_penalty += 12
    if software_tag != "Unknown" and any(x in software_tag.lower() for x in ["photoshop", "snapseed", "lightroom", "gimp"]):
        meta_penalty += 18
    if not gps_present:
        meta_penalty += 6
    if dt_original == "Unknown":
        meta_penalty += 6
    base -= meta_penalty

    # AI-like heuristic risk (not definitive)
    ai_penalty = _ai_like_heuristic(width, height, software_tag, exif_present)
    base -= ai_penalty

    # Secure capture bonus
    secure_bonus = 0
    if uuid_embedded:
        secure_bonus = 10
        base += secure_bonus

    authenticity_score = max(0, min(100, int(round(base))))
    risk_label, risk_color_key = risk_from_score(authenticity_score)

    # Chain of custody logic
    if uuid_embedded:
        chain_status = "✅ Intact & Verifiable (UUID/Secure Capture present)"
    else:
        chain_status = "⚠️ Not Verifiable (no secure-capture UUID found)"

    # Metadata integrity score (simple)
    meta_integrity = 100 - meta_penalty
    meta_integrity = max(0, min(100, int(meta_integrity)))

    return {
        "width": width,
        "height": height,
        "file_size_mb": file_size_mb,
        "color_space": color_space,

        "uuid_hint": uuid_hint if uuid_hint else "Not detected",
        "uuid_embedded": uuid_embedded,

        "exif_present": exif_present,
        "software_tag": software_tag,
        "datetime_original": dt_original,
        "gps_present": gps_present,

        "ela_mean": ela["ela_mean"],
        "ela_p95": ela["ela_p95"],
        "tampering_probability": ela["tampering_probability"],

        "metadata_integrity_score": meta_integrity,

        "authenticity_score": authenticity_score,
        "risk_label": risk_label,
        "risk_color_key": risk_color_key,
        "risk_color_hex": COLORS[risk_color_key],

        "chain_of_custody_status": chain_status,

        # Explainable scoring
        "score_breakdown": {
            "tamper_penalty": tamper_penalty,
            "metadata_penalty": meta_penalty,
            "ai_penalty": ai_penalty,
            "secure_bonus": secure_bonus
        }
    }
