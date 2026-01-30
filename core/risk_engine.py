def calculate_risk(email, intel):
    score = 0
    reasons = []

    # ---- Sender IP ----
    if intel.get("ip", {}).get("malicious"):
        score += 30
        reasons.append("Sender IP has malicious reputation")

    # ---- Domain reputation ----
    if intel.get("domain", {}).get("malicious"):
        score += 25
        reasons.append("Sender domain flagged by threat intel")

    # ---- SPF / DKIM / DMARC ----
    if email.get("spf") != "pass":
        score += 10
        reasons.append("SPF failed or missing")

    if email.get("dkim") != "pass":
        score += 10
        reasons.append("DKIM failed or missing")

    if email.get("dmarc") == "fail":
        score += 15
        reasons.append("DMARC policy failed")

    # ---- URLs ----
    for url in intel.get("urls", []):
        if url.get("malicious"):
            score += 20
            reasons.append("Malicious URL detected")

    # ---- Attachments ----
    for att in intel.get("attachments", []):
        if att.get("malicious"):
            score += 25
            reasons.append("Malicious attachment detected")

    # ---- Final verdict ----
    if score >= 70:
        verdict = "High Risk (Phishing)"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
