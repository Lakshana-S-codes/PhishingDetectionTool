import streamlit as st
import re

st.title("Phishing Detection Tool (Mini Project)")

url = st.text_input("Enter a website URL:")

if st.button("Check URL"):
    # Rule-based checks
    suspicious = False
    reasons = []

    # Check if "@" symbol is in URL
    if "@" in url:
        suspicious = True
        reasons.append("Contains '@' symbol (possible redirect).")

    # Check URL length
    if len(url) > 75:
        suspicious = True
        reasons.append("URL is too long.")

    # Check if HTTPS is missing
    if not url.startswith("https://"):
        suspicious = True
        reasons.append("Does not use HTTPS.")

    # Check for uncommon domain endings (like .xyz, .top, etc.)
    if not re.search(r"\.(com|org|net|edu|gov|in|co)$", url):
        suspicious = True
        reasons.append("Unusual domain extension.")

    # Check if domain contains suspicious words
    phishing_keywords = ["login", "update", "free", "verify", "secure", "bank"]
    if any(word in url.lower() for word in phishing_keywords):
        suspicious = True
        reasons.append("Contains suspicious keyword.")

    # Final Result
    if suspicious:
        st.error("⚠️ Suspicious URL (Possible Phishing!)")
        st.write("Reasons detected:")
        for r in reasons:
            st.write("- " + r)
    else:
        st.success("✅ Safe URL (Looks Legitimate)")
