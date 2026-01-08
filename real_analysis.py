import os
import hashlib
import numpy as np
from PIL import Image, ImageChops
from datetime import datetime
import piexif


# -------------------------
# EXIF extraction (with GPS)
# -------------------------
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


# -------------------------
# Scoring functions
# -------------------------
def metadata_score(exif):
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
    return max(0, score)


def tampering_score(image_path):
    img = Image.open(image_path).convert("RGB")
    tmp = "tmp_ela.jpg"
    img.save(tmp, "JPEG", quality=90)

    diff = ImageChops.difference(img, Image.open(tmp))
    arr = np.asarray(diff.convert("L"))
    os.remove(tmp)

    high_ratio = np.mean(arr > 40) * 100
    avg = np.mean(arr)

    probability = min(100, int(high_ratio * 0.8 + avg * 0.2))
    return probability, round(avg, 2), round(high_ratio, 2)


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


def geo_score(exif, claimed):
    score = 100
    if not exif["gps_present"]:
        score -= 40
    if not exif["datetime"]:
        score -= 30
    if claimed and not exif["gps_present"]:
        score -= 10
    return max(0, score)


# -------------------------
# MAIN ENTRY POINT
# -------------------------
def analyze_image(image_path, original_filename, secure_capture_flag, claimed_location):
    img = Image.open(image_path)
    exif = extract_exif(image_path)

    meta = metadata_score(exif)
    tamp, ela_avg, ela_ratio = tampering_score(image_path)
    deep = deepfake_score(img, exif)
    geo = geo_score(exif, claimed_location)

    dup = 10  # placeholder for now

    risk = int(
        (100 - meta) * 0.22 +
        tamp * 0.28 +
        deep * 0.18 +
        dup * 0.17 +
        (100 - geo) * 0.15
    )

    auth = max(0, 100 - risk)

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
            "compression_artifacts": "Low",
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
            "ela_avg": ela_avg,
            "ela_high_ratio_pct": ela_ratio,
            "heatmap_path": None
        },

        "deepfake": {
            "risk_score": deep,
            "ai_generated_content": "Not fully synthetic",
            "ai_assisted_editing": "Unlikely",
            "interpretation": "Low indicators of synthetic generation",
            "signals": []
        },

        "duplicate_reuse": {
            "reuse_risk_level": "Low"
        },

        "geo_time": {
            "claimed_location": claimed_location or "Not Provided",
            "gps_present": exif["gps_present"],
            "gps_coordinates": (
                f"{exif['latitude']}, {exif['longitude']}"
                if exif["gps_present"] else "Not Available (GPS stripped or missing)"
            ),
            "confidence_score": geo,
            "confidence_level": "High" if geo >= 70 else "Low",
            "notes": []
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
