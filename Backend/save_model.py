import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import pickle

# Load datasets
phishing = pd.read_csv("dataset/phishing_urls.csv")
safe = pd.read_csv("dataset/safe_urls.csv")

# Extract correct column
if "url" in phishing.columns:
    phishing_urls = phishing["url"]
elif "URL" in phishing.columns:
    phishing_urls = phishing["URL"]
else:
    phishing_urls = phishing.iloc[:, 0]

safe_urls = safe.iloc[:, 0]

# Create dataframe
phishing_df = pd.DataFrame({"url": phishing_urls, "label": 1})
safe_df = pd.DataFrame({"url": safe_urls, "label": 0})

data = pd.concat([phishing_df, safe_df], ignore_index=True)

data = data.dropna(subset=["url"])
data["url"] = data["url"].astype(str)

urls = data["url"]
labels = data["label"]

# Feature extraction
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

    return features


# Prepare training data
X = urls.apply(extract_features).apply(pd.Series)
y = labels

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X, y)

# Save model
pickle.dump(model, open("model.pkl", "wb"))

print("Model saved as model.pkl")
