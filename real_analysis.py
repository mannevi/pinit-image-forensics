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

    ela = np.mean(
        np.abs(
            np.asarray(original, dtype=np.int16)
            - np.asarray(compressed, dtype=np.int16)
        )
    )

    os.remove(temp_path)
    return float(ela)


# ---------------------------
# METADATA EXTRACTION
# ---------------------------
def extract_exif(image_path):
    exif = {
        "datetime": None,
        "gps": None,
        "software": None,
    }

    try:
        img = Image.open(image_path)
        raw = img._getexif()
        if not raw:
            return exif

        for tag, value in raw.items():
            name = ExifTags.TAGS.get(tag, tag)
            if name == "DateTimeOriginal":
                exif["datetime"] = value
            elif name == "GPSInfo":
                exif["gps"] = value
            elif name == "Software":
                exif["software"] = value

    except Exception:
        pass

    return exif


# ---------------------------
# AUTHENTICITY SCORE (FIXED)
# ---------------------------
def compute_authenticity_score(ela, exif, secure_capture):
    score = 100
    explanations = []

    # 1. ELA impact (primary)
    if ela > 3000:
        score -= 40
        explanations.append("Very high ELA inconsistency detected")
    elif ela > 1500:
        score -= 25
        explanations.append("Moderate ELA inconsistency detected")
    elif ela > 800:
        score -= 10
        explanations.append("Minor ELA artifacts detected")
    else:
        explanations.append("Low ELA variation (consistent image)")

    # 2. Metadata interpretation (FIXED LOGIC)
    if not exif["datetime"] and not exif["gps"] and not exif["software"]:
        explanations.append(
            "Metadata missing — common for shared/exported images"
        )
        # NO PENALTY
    else:
        if exif["software"]:
            score -= 15
            explanations.append("Editing software tag detected")

    # 3. Secure capture (informational only)
    if not secure_capture:
        explanations.append("Image not captured via secure app")

    return max(0, min(100, score)), explanations


# ---------------------------
# MAIN ANALYSIS
# ---------------------------
def analyze_image(image_path):
    ela = calculate_ela(image_path)
    exif = extract_exif(image_path)

    secure_capture_flag = False

    authenticity_score, explanations = compute_authenticity_score(
        ela=ela,
        exif=exif,
        secure_capture=secure_capture_flag,
    )

    tamper_probability = max(0, min(100, int((ela / 3000) * 100)))

    analysis = {
        "image": {
            "type": os.path.splitext(image_path)[1].upper().replace(".", ""),
            "size": os.path.getsize(image_path),
        },
        "exif": exif,
        "authenticity_score": authenticity_score,
        "explanations": explanations,
        "tampering": {
            "ela": round(ela, 2),
            "probability": tamper_probability,
        },
        "ai": {
            "enabled": True,
            "score": 1 if authenticity_score > 80 else 3,
        },
        "secure_capture": secure_capture_flag,
    }

    return analysis
