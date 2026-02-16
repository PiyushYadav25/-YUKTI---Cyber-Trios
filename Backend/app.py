from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pickle
import cv2
import numpy as np
from PIL import Image
import pytesseract

# OCR path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = Flask(__name__)
CORS(app)

# LOAD DATASETS
phishing_data = pd.read_csv("dataset/phishing_urls.csv")
trusted_domains = set(pd.read_csv("dataset/trusted_domains.csv")["domain"].str.lower().tolist())

# LOAD MODEL
model = pickle.load(open("model.pkl", "rb"))

print("Phishing dataset:", len(phishing_data))
print("Trusted domains:", len(trusted_domains))
print("ML model loaded")

shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","buff.ly"]

phishing_domains = set(
    phishing_data.iloc[:,0]
    .astype(str)
    .apply(lambda x: urlparse(x).netloc.lower().replace("www.",""))
)

def clean_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.lower().replace("www.", "")

# BRAND TYPO DETECTOR
def is_brand_impersonation(domain):
    domain_name = domain.split(".")[0]
    normalized = domain_name.replace("0","o").replace("1","l").replace("5","s")

    common_brands = [
        "google","youtube","amazon","paypal","github","microsoft",
        "apple","facebook","instagram","whatsapp","twitter","linkedin",
        "netflix","bank","sbi","upi","phonepe","gpay","paytm","stripe"
    ]

    for brand in common_brands:
        similarity = SequenceMatcher(None, normalized, brand).ratio()
        if similarity > 0.82 and normalized != brand:
            return brand
        if brand in normalized and normalized != brand:
            return brand
    return None

# FEATURE EXTRACTION
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {}
    features["length"] = len(url)
    features["has_https"] = 1 if url.startswith("https") else 0
    features["has_hyphen"] = 1 if "-" in domain else 0
    features["has_digit"] = 1 if any(char.isdigit() for char in domain) else 0

    suspicious_tlds = ["ru","tk","xyz","top","ml","ga"]
    tld = domain.split(".")[-1] if "." in domain else ""
    features["tld_risk"] = 1 if tld in suspicious_tlds else 0

    features["brand_word"] = 1 if any(word in domain for word in ["paypal","amazon","google","bank","upi"]) else 0

    features["url_depth"] = url.count("/")
    features["subdomain_count"] = domain.count(".")
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["special_char_count"] = sum([1 for c in url if c in "@#$%^&*"])

    ordered = [
        "length","has_https","has_hyphen","has_digit",
        "tld_risk","brand_word","url_depth",
        "subdomain_count","has_at_symbol","special_char_count"
    ]

    return pd.DataFrame([[features[f] for f in ordered]], columns=ordered)

@app.route("/")
def home():
    return "TruthGuard backend running"

# LINK SCAN (UNCHANGED)
@app.route("/check_link", methods=["POST"])
def check_link():
    try:
        data = request.get_json()
        link = data.get("link","").strip()

        if not link.startswith("http"):
            link = "https://" + link

        parsed = urlparse(link)
        domain = parsed.netloc.lower().replace("www.", "")

        if domain in trusted_domains:
            return jsonify({
                "verdict":"SAFE",
                "score":0,
                "confidence":99,
                "reasons":["Official trusted domain"]
            })

        score = 0
        reasons = []
        domain_known_phishing = False

        if domain in phishing_domains:
            score += 7
            domain_known_phishing = True
            reasons.append("Known phishing domain")

        if not link.startswith("https"):
            score += 1
            reasons.append("No HTTPS")

        if "-" in domain:
            score += 1
            reasons.append("Hyphen in domain")

        if any(char.isdigit() for char in domain):
            score += 2
            reasons.append("Digit used in domain")

        brand_fake = is_brand_impersonation(domain)
        if brand_fake:
            score += 7
            reasons.append("Brand impersonation / typo attack")

        if any(short in domain for short in shorteners):
            score += 2
            reasons.append("URL shortener used")

        features = extract_features(link)
        proba = model.predict_proba(features)[0][1]
        ai_confidence = int(proba * 100)

        if proba > 0.65:
            score += 3
            reasons.append("ML phishing probability high")

        if score >= 9:
            verdict = "PHISHING"
        elif score >= 4:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        final_confidence = min(99, ai_confidence + score*2)

        return jsonify({
            "verdict": verdict,
            "score": score,
            "confidence": final_confidence,
            "reasons": reasons
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error":"backend failed"})


# IMAGE PAYMENT FRAUD DETECTOR — FINAL CALIBRATED
@app.route("/check_image", methods=["POST"])
def check_image():
    try:
        if "image" not in request.files:
            return jsonify({"error":"No image uploaded"})

        file = request.files["image"]

        image = Image.open(file.stream).convert("RGB")
        img = np.array(image)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        risk_score = 0
        reasons = []

        # brightness
        if np.mean(gray) < 40 or np.mean(gray) > 220:
            risk_score += 2
            reasons.append("Brightness anomaly")

        # editing detection
        edges = cv2.Canny(gray,100,200)
        if np.mean(edges) > 25:
            risk_score += 3
            reasons.append("Editing artifacts")

        # OCR
        ocr_text = ""
        try:
            ocr_text = pytesseract.image_to_string(image)
            ocr_text = ocr_text.lower()
        except Exception as ocr_error:
            print("OCR ERROR:", ocr_error)

        payment_keywords = ["upi","payment","transaction","paid","received","bank","success","credited"]
        has_payment_text = any(word in ocr_text for word in payment_keywords)

        if has_payment_text:
            reasons.append("Payment UI detected")

        # 🔧 FIXED RULE — only apply if payment actually detected
        if has_payment_text and ("transaction id" not in ocr_text and "txn" not in ocr_text):
            risk_score += 1
            reasons.append("Transaction reference unclear")

        if has_payment_text and ("₹" not in ocr_text and "rs" not in ocr_text):
            risk_score += 1
            reasons.append("Amount format unclear")

        # verdict
        if risk_score >= 6:
            verdict="FAKE PAYMENT SCREENSHOT"
        elif risk_score >= 3:
            verdict="SUSPICIOUS PAYMENT SCREENSHOT"
        else:
            verdict="LIKELY REAL PAYMENT"

        confidence = min(97, 60 + risk_score*7)

        return jsonify({
            "verdict": verdict,
            "score": risk_score,
            "confidence": confidence,
            "reasons": reasons,
            "ocr_text_preview": ocr_text[:120]
        })

    except Exception as e:
        print("IMAGE ERROR:", e)
        return jsonify({"error":"image analysis failed"})


if __name__ == "__main__":
    app.run(debug=True)
