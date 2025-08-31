import streamlit as st
import re
import urllib.parse
import requests
import base64
from fuzzywuzzy import fuzz

# ==========================
# CONFIG
# ==========================
API_KEY = "63a673d2aa23d2ea58efbea9042316dd3d5e1ce90a90f4144a38f29a840256ef"  # 🔑 Replace with your actual VirusTotal API key
VT_URL = "https://www.virustotal.com/api/v3/urls"

st.title("🔒 Phishing Detection Tool")


url = st.text_input("Enter a website URL:")

# Trusted domains list for fuzzy matching
trusted_domains = ["google.com", "paypal.com", "facebook.com", "amazon.com", "microsoft.com", "instagram.com", "apple.com"]

def is_lookalike(domain):
    """Check if domain is visually similar to trusted ones."""
    for legit in trusted_domains:
        score = fuzz.ratio(domain, legit.lower())
        if score > 80 and domain != legit.lower():
            return True, legit
    return False, None

def check_with_virustotal(url):
    """Send URL to VirusTotal and get result"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        response = requests.get(f"{VT_URL}/{url_id}", headers=headers)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                return False, f"⚠️ Reported by {malicious + suspicious} security engines."
            else:
                return True, "✅ No malicious activity found on VirusTotal."
        else:
            return True, f"⚠️ VirusTotal check failed ({response.status_code})."
    except Exception as e:
        return True, f"⚠️ Error contacting VirusTotal: {str(e)}"

if st.button("Check URL"):
    suspicious = False
    reasons = []

    # Extract domain
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.strip()

    # =============================
    # RULE-BASED CHECKS
    # =============================

    # Uppercase detection
    if domain != domain.lower():
        suspicious = True
        reasons.append("Domain uses unusual uppercase letters (possible obfuscation).")
    domain = domain.lower()

    # '@' redirect trick
    if "@" in url:
        suspicious = True
        reasons.append("Contains '@' symbol (possible redirect).")

    # Long URL
    if len(url) > 75:
        suspicious = True
        reasons.append("URL is too long.")

    # Missing HTTPS
    if not url.startswith("https://"):
        suspicious = True
        reasons.append("Does not use HTTPS.")

    # Weird domain extensions
    if not re.search(r"\.(com|org|net|edu|gov|in|co|io|ai|uk|us)$", url):
        suspicious = True
        reasons.append("Unusual domain extension.")

    # Suspicious keywords
    phishing_keywords = ["login", "update", "free", "verify", "secure", "bank", "confirm", "signin", "account", "password"]
    if any(word in url.lower() for word in phishing_keywords):
        suspicious = True
        reasons.append("Contains suspicious keyword.")

    # IP address as domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        suspicious = True
        reasons.append("Domain is an IP address (suspicious).")

    # Too many subdomains
    if domain.count(".") > 2:
        suspicious = True
        reasons.append("Contains too many subdomains (possible phishing).")

    # Hyphen abuse
    if domain.count("-") > 2:
        suspicious = True
        reasons.append("Domain has excessive '-' characters (possible phishing).")

    # Too many numbers
    if sum(c.isdigit() for c in domain) > 3:
        suspicious = True
        reasons.append("Domain contains too many numbers (possible phishing).")

    # Lookalike detection
    lookalike, legit = is_lookalike(domain)
    if lookalike:
        suspicious = True
        reasons.append(f"Looks similar to trusted domain: {legit}")

    # =============================
    # VIRUSTOTAL CHECK
    # =============================
    vt_safe, vt_message = check_with_virustotal(url)
    if not vt_safe:
        suspicious = True
        reasons.append(vt_message)
    else:
        reasons.append(vt_message)

    # =============================
    # FINAL RESULT
    # =============================
    if suspicious:
        st.error("⚠️ Suspicious URL (Possible Phishing!)")
        st.write("Reasons detected:")
        for r in reasons:
            st.write("- " + r)
    else:
        st.success("✅ Safe URL (Looks Legitimate)")
        for r in reasons:
            st.write("- " + r)
