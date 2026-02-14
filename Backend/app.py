from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pickle
import cv2
import numpy as np
from PIL import Image

app = Flask(__name__)
CORS(app)

# Load phishing dataset
phishing_data = pd.read_csv("dataset/phishing_urls.csv")

# Load trusted domains (whitelist)
trusted_domains = pd.read_csv("dataset/trusted_domains.csv")["domain"].tolist()

# Load trained ML model
model = pickle.load(open("model.pkl", "rb"))

print("Phishing dataset loaded:", len(phishing_data))
print("Trusted domains loaded:", len(trusted_domains))
print("ML model loaded successfully")

# Brand similarity checker
def is_brand_impersonation(domain):

    brands = ["google", "amazon", "paypal", "bank", "sbi", "upi", "phonepe", "gpay"]
    domain_name = domain.split(".")[0]

    for brand in brands:
        similarity = SequenceMatcher(None, domain_name, brand).ratio()

        if similarity > 0.75:
            return brand

        domain_fixed = domain_name.replace("0", "o").replace("1", "l").replace("3", "e")
        similarity_fixed = SequenceMatcher(None, domain_fixed, brand).ratio()

        if similarity_fixed > 0.75:
            return brand

    return None


# ML feature extraction
def extract_features(url):

    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}

    features["length"] = len(url)
    features["has_https"] = 1 if url.startswith("https") else 0
    features["has_hyphen"] = 1 if "-" in domain else 0
    features["has_digit"] = 1 if any(char.isdigit() for char in domain) else 0

    suspicious_tlds = ["ru", "tk", "xyz", "top", "ml", "ga"]
    tld = domain.split(".")[-1] if "." in domain else ""
    features["tld_risk"] = 1 if tld in suspicious_tlds else 0

    brand_words = ["paypal", "amazon", "google", "bank", "upi"]
    features["brand_word"] = 1 if any(word in domain for word in brand_words) else 0

    return pd.DataFrame([features])


# IMAGE FORENSIC ANALYSIS ENGINE
def analyze_payment_screenshot(image):

    risk_score = 0
    reasons = []
    extracted_text = ""


    img = np.array(image)

    # Resolution check
    height, width = img.shape[:2]
    if height < 500 or width < 300:
        risk_score += 2
        reasons.append("Low resolution screenshot (possible crop/edit)")

    # Brightness anomaly
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    brightness = np.mean(gray)

    if brightness < 40 or brightness > 220:
        risk_score += 1
        reasons.append("Abnormal brightness level")

    # Compression artifacts
    edges = cv2.Canny(gray, 100, 200)
    edge_density = np.mean(edges)

    if edge_density > 25:
        risk_score += 2
        reasons.append("High compression / editing artifacts")

    # Pixel noise detection
    blur = cv2.GaussianBlur(gray, (5,5), 0)
    noise = np.mean(cv2.absdiff(gray, blur))

    if noise > 15:
        risk_score += 2
        reasons.append("Pixel inconsistency detected")

    # OCR TEXT EXTRACTION (payment fraud intelligence)
    try:
        import pytesseract

        extracted_text = pytesseract.image_to_string(image).lower()

        payment_keywords = [
            "payment successful",
            "paid",
            "upi",
            "transaction id",
            "ref no",
            "bank",
            "received",
            "sent"
        ]

        keyword_found = any(word in extracted_text for word in payment_keywords)

        if keyword_found:
            reasons.append("Payment interface text detected")

        # suspicious mismatch logic
        if "payment successful" in extracted_text and "upi" not in extracted_text:
            risk_score += 3
            reasons.append("Fake payment UI pattern mismatch")

        if "transaction" not in extracted_text:
            risk_score += 2
            reasons.append("Transaction reference missing")

        if "₹" not in extracted_text and "rs" not in extracted_text:
            risk_score += 1
            reasons.append("Amount format not detected")

    except Exception as e:
        print("OCR ERROR:", e)

    # PAYMENT STRUCTURE INTELLIGENCE

    try:
        # detect fake "success" generator patterns
        if "success" in extracted_text and "upi" not in extracted_text:
            risk_score += 2
            reasons.append("Generic success screen without UPI details")

        # detect missing bank identifiers
        bank_words = ["sbi", "hdfc", "icici", "axis", "kotak"]
        if not any(bank in extracted_text for bank in bank_words):
            risk_score += 1
            reasons.append("Bank identity not detected")

        # detect fake reference format
        if "ref" in extracted_text and not any(char.isdigit() for char in extracted_text):
            risk_score += 2
            reasons.append("Invalid transaction reference pattern")

        # detect edited amount spacing
        if "₹" in extracted_text and "  " in extracted_text:
            risk_score += 1
            reasons.append("Edited amount formatting anomaly")

    except:
        pass

    return risk_score, reasons


@app.route("/")
def home():
    return "TruthGuard backend running"


@app.route("/check_link", methods=["POST"])
def check_link():
    try:
        data = request.get_json()
        link = data.get("link", "").strip()

        parsed = urlparse(link)
        domain = parsed.netloc.lower()

        # Trusted whitelist
        if domain in trusted_domains:
            return jsonify({
                "verdict": "SAFE",
                "score": 0,
                "reasons": ["Trusted official domain"]
            })

        domain_parts = domain.split(".")
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""

        reasons = []
        score = 0

        # RULE ENGINE

        if not link.startswith("https"):
            score += 1
            reasons.append("No HTTPS security")

        suspicious_tlds = ["ru", "tk", "xyz", "top", "ml", "ga"]
        if tld in suspicious_tlds:
            score += 2
            reasons.append(f"Suspicious domain extension: .{tld}")

        if "-" in domain:
            score += 2
            reasons.append("Hyphenated domain (common in phishing)")

        brand_fake = is_brand_impersonation(domain)
        if brand_fake:
            score += 4
            reasons.append(f"Brand impersonation detected (similar to {brand_fake})")

        keywords = ["login", "verify", "secure", "update", "reward", "otp", "account"]
        for word in keywords:
            if word in link.lower():
                score += 2
                reasons.append(f"Suspicious keyword detected: {word}")

        try:
            dataset_match = phishing_data.astype(str).apply(
                lambda row: domain in str(row.values), axis=1
            ).any()

            if dataset_match:
                score += 5
                reasons.append("Domain found in phishing intelligence dataset")
        except:
            pass

        # ML ENGINE

        features = extract_features(link)
        ml_prediction = model.predict(features)[0]

        if ml_prediction == 1:
            reasons.append("ML model predicts phishing behaviour")
            score += 4

        # FINAL HYBRID VERDICT

        if score >= 9:
            verdict = "PHISHING"
        elif score >= 5:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return jsonify({
            "verdict": verdict,
            "score": score,
            "reasons": reasons
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": "backend failed"})
    
   
    
     # IMAGE CHECK API

@app.route("/check_image", methods=["POST"])
def check_image():
    try:
        if "image" not in request.files:
            return jsonify({"error": "No image uploaded"})

        file = request.files["image"]

        image = Image.open(file.stream)

        risk_score, reasons = analyze_payment_screenshot(image)

        # Final decision
        if risk_score >= 5:
            verdict = "FAKE PAYMENT SCREENSHOT"
        elif risk_score >= 3:
            verdict = "SUSPICIOUS IMAGE"
        else:
            verdict = "LIKELY ORIGINAL"

        return jsonify({
            "verdict": verdict,
            "score": risk_score,
            "reasons": reasons
        })

    except Exception as e:
        print("IMAGE ERROR:", e)
        return jsonify({"error": "image analysis failed"})

if __name__ == "__main__":
    app.run(debug=True)
