# app.py
import streamlit as st
import re
import urllib.parse
import requests
import base64
from fuzzywuzzy import fuzz
import joblib
import numpy as np
from pathlib import Path

# --------------------------
# Config
# --------------------------
API_KEY = "63a673d2aa23d2ea58efbea9042316dd3d5e1ce90a90f4144a38f29a840256ef"  # Optional
VT_URL = "https://www.virustotal.com/api/v3/urls"

trusted_domains = ["google.com", "paypal.com", "facebook.com", "amazon.com",
                   "microsoft.com", "instagram.com", "apple.com"]

# --------------------------
# Paths
# --------------------------
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.pkl"

# --------------------------
# Helper Functions
# --------------------------
def is_lookalike(domain):
    for legit in trusted_domains:
        score = fuzz.ratio(domain, legit.lower())
        if score > 80 and domain != legit.lower():
            return True, legit
    return False, None

def check_with_virustotal(url):
    try:
        if not API_KEY:
            return True, "⚠️ VirusTotal check skipped (no API key)"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return False, f"⚠️ Reported by {malicious + suspicious} security engines."
            else:
                return True, "✅ No malicious activity found on VirusTotal."
        else:
            return True, f"⚠️ VirusTotal check failed ({response.status_code})"
    except Exception as e:
        return True, f"⚠️ Error contacting VirusTotal: {str(e)}"

def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    return [
        int(any(c.isdigit() for c in domain)),  # Have_IP
        len(url),                               # URL_Length
        int("@" in url),                        # Have_At
        int("//" in url),                        # Double_Slash
        int("-" in domain),                      # Prefix_Suffix
        int("https" in url.lower()),             # SSLfinal_State
    ]

def clean_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url

# --------------------------
# Load model
# --------------------------
model = None
if MODEL_PATH.exists():
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        st.error(f"Error loading model.pkl: {e}")
else:
    st.warning("model.pkl not found. Please ensure it is in the same folder as app.py")

# --------------------------
# Streamlit UI
# --------------------------
st.set_page_config(page_title="Phishing Detection Tool", layout="centered")
st.title("🔒 Phishing Detection Tool")
st.markdown("Enter a URL below to check if it is suspicious using rules, VirusTotal, and ML prediction.")

url_input = st.text_input("Enter website URL:", placeholder="example.com or https://example.com/path")

if st.button("Check URL (All Methods)"):
    if not url_input:
        st.warning("Please enter a URL.")
    else:
        url_input = clean_url(url_input)
        reasons_rule = []
        suspicious_rule = False

        parsed = urllib.parse.urlparse(url_input)
        domain = parsed.netloc.strip().lower()

        # ----------------------------
        # Rule-Based Checks
        # ----------------------------
        if domain != domain.lower():
            suspicious_rule = True
            reasons_rule.append("Domain uses unusual uppercase letters.")
        if "@" in url_input:
            suspicious_rule = True
            reasons_rule.append("Contains '@' symbol (possible redirect).")
        if len(url_input) > 75:
            suspicious_rule = True
            reasons_rule.append("URL is too long.")
        if not url_input.startswith("https://"):
            suspicious_rule = True
            reasons_rule.append("Does not use HTTPS.")
        if not re.search(r"\.(com|org|net|edu|gov|in|co|io|ai|uk|us)$", url_input):
            suspicious_rule = True
            reasons_rule.append("Unusual domain extension.")
        phishing_keywords = ["login", "update", "free", "verify", "secure", "bank",
                             "confirm", "signin", "account", "password"]
        if any(word in url_input.lower() for word in phishing_keywords):
            suspicious_rule = True
            reasons_rule.append("Contains suspicious keyword.")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            suspicious_rule = True
            reasons_rule.append("Domain is an IP address.")
        if domain.count(".") > 2:
            suspicious_rule = True
            reasons_rule.append("Contains too many subdomains.")
        if domain.count("-") > 2:
            suspicious_rule = True
            reasons_rule.append("Domain has excessive '-' characters.")
        if sum(c.isdigit() for c in domain) > 3:
            suspicious_rule = True
            reasons_rule.append("Domain contains too many numbers.")
        lookalike, legit = is_lookalike(domain)
        if lookalike:
            suspicious_rule = True
            reasons_rule.append(f"Looks similar to trusted domain: {legit}")

        # ----------------------------
        # VirusTotal Check
        # ----------------------------
        with st.spinner("Checking VirusTotal..."):
            vt_safe, vt_message = check_with_virustotal(url_input)

        # ----------------------------
        # ML Prediction
        # ----------------------------
        try:
            features = np.array(extract_features(url_input)).reshape(1, -1)
            if model is None:
                ml_result = "Model not available. Place model.pkl in app folder."
            else:
                prediction = model.predict(features)[0]
                ml_result = "🟢 Legitimate URL" if prediction == 0 else "🔴 Phishing URL"
        except Exception as e:
            ml_result = f"Error during ML prediction: {e}"

        # ----------------------------
        # Display Results
        # ----------------------------
        st.subheader("📝 Rule-Based Analysis")
        if suspicious_rule:
            st.error("⚠️ Suspicious URL detected by rules")
        else:
            st.success("✅ URL looks safe according to rules")
        for r in reasons_rule:
            st.write("- " + r)

        st.subheader("🔍 VirusTotal Check")
        st.write(vt_message)

        st.subheader("🤖 ML Model Prediction")
        if model is None:
            st.error(ml_result)
        else:
            if "Phishing" in ml_result or "🔴" in ml_result:
                st.error(ml_result)
            else:
                st.success(ml_result)
