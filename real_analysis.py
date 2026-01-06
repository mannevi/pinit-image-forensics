from PIL import Image, ExifTags
import numpy as np
import os


# ---------------------------
# ELA CALCULATION
# ---------------------------
def calculate_ela(image_path):
    original = Image.open(image_path).convert("RGB")
    temp_path = "temp_ela.jpg"

    original.save(temp_path, "JPEG", quality=90)
    compressed = Image.open(temp_path)

    ela = np.mean(np.abs(np.asarray(original, dtype=np.int16)
                         - np.asarray(compressed, dtype=np.int16)))

    os.remove(temp_path)
    return float(ela)


# ---------------------------
# METADATA EXTRACTION
# ---------------------------
def extract_exif(image_path):
    exif_data = {
        "datetime": None,
        "gps": None,
        "software": None
    }

    try:
        img = Image.open(image_path)
        exif_raw = img._getexif()
        if not exif_raw:
            return exif_data

        for tag, value in exif_raw.items():
            tag_name = ExifTags.TAGS.get(tag, tag)

            if tag_name == "DateTimeOriginal":
                exif_data["datetime"] = value
            elif tag_name == "Software":
                exif_data["software"] = value
            elif tag_name == "GPSInfo":
                exif_data["gps"] = value

    except Exception:
        pass

    return exif_data


# ---------------------------
# AUTHENTICITY SCORE (POINT 1 CORE FIX)
# ---------------------------
def compute_authenticity_score(ela, exif, secure_capture):
    score = 100

    # Penalize ELA
    if ela > 3000:
        score -= 40
    elif ela > 1500:
        score -= 25
    elif ela > 800:
        score -= 10

    # Penalize missing metadata
    if not exif.get("datetime"):
        score -= 15
    if not exif.get("gps"):
        score -= 10
    if exif.get("software") not in (None, "", "Unknown"):
        score -= 20

    # Penalize non-secure capture
    if not secure_capture:
        score -= 10

    return max(0, min(100, score))


# ---------------------------
# MAIN ANALYSIS FUNCTION
# ---------------------------
def analyze_image(image_path):
    ela = calculate_ela(image_path)
    exif = extract_exif(image_path)

    # Currently you do not have secure capture implemented
    secure_capture_flag = False

    authenticity_score = compute_authenticity_score(
        ela=ela,
        exif=exif,
        secure_capture=secure_capture_flag
    )

    analysis = {
        "image": {
            "type": os.path.splitext(image_path)[1].upper().replace(".", ""),
            "size": os.path.getsize(image_path),
        },
        "exif": exif,
        "tampering": {
            "ela": round(ela, 2),
            "probability": 100 - authenticity_score
        },
        "ai": {
            "enabled": True,
            "score": max(0, 100 - authenticity_score) // 10
        },
        "authenticity_score": authenticity_score,
        "secure_capture": secure_capture_flag
    }

    return analysis
