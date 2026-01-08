import os
import hashlib
import numpy as np
from PIL import Image, ImageChops
from datetime import datetime
import piexif


# ======================================================
# EXIF EXTRACTION (with GPS decoding)
# ======================================================
def extract_exif(path):
    try:
        ex = piexif.load(path)
        gps = ex.get("GPS", {})

        def dms_to_deg(dms, ref):
            d = dms[0][0] / dms[0][1]
            m = dms[1][0] / dms[1][1]
            s = dms[2][0] / dms[2][1]
            val = d + m / 60 + s / 3600
            return -val if ref in [b"S", b"W"] else val

        lat = lon = None
        if piexif.GPSIFD.GPSLatitude in gps:
            lat = dms_to_deg(
                gps[piexif.GPSIFD.GPSLatitude],
                gps.get(piexif.GPSIFD.GPSLatitudeRef, b"N")
            )
        if piexif.GPSIFD.GPSLongitude in gps:
            lon = dms_to_deg(
                gps[piexif.GPSIFD.GPSLongitude],
                gps.get(piexif.GPSIFD.GPSLongitudeRef, b"E")
            )

        return {
            "make": ex["0th"].get(piexif.ImageIFD.Make, b"").decode(errors="ignore"),
            "model": ex["0th"].get(piexif.ImageIFD.Model, b"").decode(errors="ignore"),
            "datetime": ex["0th"].get(piexif.ImageIFD.DateTime, b"").decode(errors="ignore"),
            "software": ex["0th"].get(piexif.ImageIFD.Software, b"").decode(errors="ignore"),
            "gps_present": lat is not None and lon is not None,
            "latitude": lat,
            "longitude": lon
        }
    except Exception:
        return {
            "make": "",
            "model": "",
            "datetime": "",
            "software": "",
            "gps_present": False,
            "latitude": None,
            "longitude": None
        }


# ======================================================
# METADATA SCORE
# ======================================================
def metadata_score(exif, secure_capture):
    score = 100
    if not exif["make"]:
        score -= 10
    if not exif["model"]:
        score -= 15
    if not exif["datetime"]:
        score -= 20
    if not exif["gps_present"]:
        score -= 20
    if exif["software"]:
        score -= 30

    # 🔴 Download / forwarded image penalty
    if not secure_capture:
        score -= 30

    return max(0, score)


# ======================================================
# GLOBAL TAMPERING (EXPOSURE / CONTRAST)
# ======================================================
def global_tampering_score(image_path):
    img = Image.open(image_path).convert("L")
    arr = np.asarray(img) / 255.0

    score = 0
    indicators = []

    if np.mean(arr > 0.98) > 0.015:
        score += 25
        indicators.append("Highlight clipping detected")

    if np.mean(arr < 0.02) > 0.01:
        score += 15
        indicators.append("Shadow detail loss detected")

    if np.std(arr) < 0.18:
        score += 20
        indicators.append("Abnormally low contrast")

    hist, _ = np.histogram(arr, bins=256, range=(0, 1), density=True)
    entropy = -np.sum((hist + 1e-9) * np.log2(hist + 1e-9))
    if entropy < 6.5:
        score += 20
        indicators.append("Histogram entropy unusually low")

    return min(100, score), indicators


# ======================================================
# TAMPERING SCORE (LOCAL + GLOBAL)
# ======================================================
def tampering_score(image_path):
    img = Image.open(image_path).convert("RGB")

    # ----- Local tampering (ELA) -----
    tmp = "tmp_ela.jpg"
    img.save(tmp, "JPEG", quality=90)
    diff = ImageChops.difference(img, Image.open(tmp))
    ela = np.asarray(diff.convert("L"))
    os.remove(tmp)

    ela_score = min(100, (np.mean(ela > 40) * 100) * 0.8 + np.mean(ela) * 0.2)

    # ----- Global tampering -----
    global_score, indicators = global_tampering_score(image_path)

    # ----- Recompression penalty -----
    recompression_penalty = 10

    # ----- Final weighted score -----
    final_score = (
        0.5 * ela_score +
        0.3 * global_score +
        0.2 * recompression_penalty
    )

    # ❗ Never allow 0%
    final_score = max(final_score, 10)

    return int(final_score), indicators


# ======================================================
# DEEPFAKE / AI HEURISTIC
# ======================================================
def deepfake_score(img, exif):
    risk = 0
    if not exif["model"]:
        risk += 20
    if exif["software"]:
        risk += 25

    gray = np.asarray(img.convert("L")) / 255.0
    lap_var = np.var(
        -4 * gray +
        np.roll(gray, 1, 0) + np.roll(gray, -1, 0) +
        np.roll(gray, 1, 1) + np.roll(gray, -1, 1)
    )

    if lap_var < 0.001:
        risk += 20

    return min(100, risk)


# ======================================================
# GEO SCORE
# ======================================================
def geo_score(exif, claimed, secure_capture):
    score = 100
    if not exif["gps_present"]:
        score -= 40
    if not exif["datetime"]:
        score -= 30
    if claimed and not exif["gps_present"]:
        score -= 10

    # 🔴 Non-secure upload cap
    if not secure_capture:
        score = min(score, 40)

    return max(0, score)


# ======================================================
# MAIN ENTRY POINT
# ======================================================
def analyze_image(image_path, original_filename, secure_capture_flag, claimed_location):
    img = Image.open(image_path)
    exif = extract_exif(image_path)

    meta = metadata_score(exif, secure_capture_flag)
    tamp, tamper_indicators = tampering_score(image_path)
    deep = deepfake_score(img, exif)
    geo = geo_score(exif, claimed_location, secure_capture_flag)

    dup = 10  # placeholder

    risk = int(
        (100 - meta) * 0.22 +
        tamp * 0.28 +
        deep * 0.18 +
        dup * 0.17 +
        (100 - geo) * 0.15
    )

    auth = max(0, 100 - risk)

    # ❗ Edited images cannot be Highly Authentic
    if tamp >= 25:
        auth = min(auth, 65)

    if auth >= 80:
        verdict = "Highly Authentic"
    elif auth >= 60:
        verdict = "Partially Authentic"
    elif auth >= 40:
        verdict = "Suspicious"
    else:
        verdict = "High Fraud Risk"

    sha256 = hashlib.sha256(open(image_path, "rb").read()).hexdigest()

    return {
        "generated_at": datetime.utcnow().strftime("%d %b %Y"),

        "executive_summary": {
            "overall_finding": verdict,
            "finding_details": "Automated analysis completed using metadata, tampering, and heuristic checks."
        },

        "image_overview": {
            "image_type": img.format,
            "file_size_mb": round(os.path.getsize(image_path)/(1024*1024), 2),
            "resolution": f"{img.width} × {img.height}",
            "color_space": img.mode,
            "compression_artifacts": "Present",
            "capture_method": "PinIT Secure Capture" if secure_capture_flag else "Standard Upload",
            "capture_integrity_status": "Verified" if secure_capture_flag else "Not Verified",
            "user_uuid_embedded": "Not Found"
        },

        "authenticity": {
            "score": auth,
            "label": verdict
        },

        "metadata": {
            "integrity_score": meta,
            "exif": exif,
            "observations": []
        },

        "tampering": {
            "tampering_probability_pct": tamp,
            "detected_indicators": tamper_indicators,
            "heatmap_path": None
        },

        "deepfake": {
            "risk_score": deep,
            "ai_generated_content": "Unlikely" if deep < 50 else "Likely",
            "interpretation": "Heuristic-based AI detection"
        },

        "duplicate_reuse": {
            "reuse_risk_level": "Low"
        },

        "geo_time": {
            "claimed_location": claimed_location or "Not Provided",
            "gps_present": exif["gps_present"],
            "gps_coordinates": (
                f"{exif['latitude']}, {exif['longitude']}"
                if exif["gps_present"] else
                "Not Available (Stripped or Missing)"
            ),
            "confidence_score": geo,
            "confidence_level": "High" if geo >= 70 else "Low"
        },

        "risk_classification": {
            "risk_factors": {
                "Metadata Integrity": meta,
                "Tampering Indicators": tamp,
                "Deepfake Probability": deep,
                "Duplication Risk": dup,
                "Geo-Time Accuracy": geo
            },
            "overall_risk_score": risk,
            "overall_risk_rating": verdict,
            "recommended_action": "Proceed with standard verification"
        },

        "file_hash": {
            "sha256": sha256
        }
    }
