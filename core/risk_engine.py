def calculate_risk(email, intel):
    score = 0
    reasons = []

    # ---- Sender IP ----
    ip = intel.get("ip", {})
    if ip.get("is_malicious"):                      # fixed: was "malicious"
        score += 30
        reasons.append("Sender IP has malicious reputation")

    # ---- Domain reputation ----
    domain = intel.get("domain", {})
    if domain.get("malicious"):
        score += 25
        reasons.append("Sender domain flagged by threat intel")

    # ---- SPF / DKIM / DMARC ----
    if email.get("spf", "").lower() != "pass":
        score += 10
        reasons.append("SPF failed or missing")

    if email.get("dkim", "").lower() != "pass":
        score += 10
        reasons.append("DKIM failed or missing")

    if email.get("dmarc", "").lower() == "fail":
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

    # ---- Normalize score ----
    score = min(score, 100)

    # ---- Verdict ----
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