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
# NOISE / SMOOTHNESS CHECK
# ---------------------------
def compute_noise_variance(image_path):
    img = Image.open(image_path).convert("L")
    arr = np.asarray(img, dtype=np.float32)
    return float(np.var(arr))


# ---------------------------
# METADATA EXTRACTION
# ---------------------------
def extract_exif(image_path):
    exif = {"datetime": None, "gps": None, "software": None}

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
# CORE SCORING LOGIC
# ---------------------------
def analyze_image(image_path):
    ela = calculate_ela(image_path)
    noise_var = compute_noise_variance(image_path)
    exif = extract_exif(image_path)

    explanations = []
    score = 100
    ai_risk = 1

    # ---------- ELA ----------
    if ela > 2500:
        score -= 35
        explanations.append("High ELA inconsistency detected")
    elif ela > 1200:
        score -= 20
        explanations.append("Moderate ELA inconsistency detected")
    elif ela < 5:
        explanations.append("Very low ELA variation")

    # ---------- METADATA ----------
    metadata_missing = not exif["datetime"] and not exif["gps"] and not exif["software"]

    if metadata_missing:
        explanations.append("Metadata missing (common for shared or encrypted images)")
        score -= 10

    if exif["software"]:
        score -= 15
        explanations.append("Editing software tag detected")

    # ---------- ENCRYPTION / RECOMPRESSION ----------
    if metadata_missing and ela < 10 and noise_var < 300:
        score -= 10
        explanations.append("Possible recompression or encryption artifacts")

    # ---------- AI HEURISTIC DETECTION ----------
    if ela < 5 and noise_var < 200 and metadata_missing:
        ai_risk = 8
        score -= 40
        explanations.append("AI-generated image likely (over-smooth texture, no metadata)")
    elif ela < 10 and noise_var < 300:
        ai_risk = 5
        score -= 20
        explanations.append("AI-assisted or synthetic enhancement suspected")

    # ---------- FINAL CLAMP ----------
    score = max(0, min(100, score))

    tamper_probability = min(100, int((ela / 2500) * 100))

    return {
        "authenticity_score": score,
        "explanations": explanations,
        "tampering": {
            "ela": round(ela, 2),
            "probability": tamper_probability,
        },
        "ai": {
            "enabled": True,
            "score": ai_risk,
        },
        "image": {
            "type": os.path.splitext(image_path)[1].upper().replace(".", ""),
            "size": os.path.getsize(image_path),
        },
        "exif": exif,
    }
