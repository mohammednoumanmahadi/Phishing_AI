from datetime import datetime, timezone


def format_soc_output(email, intel, risk):
    findings = []

    spf          = email.get("spf", "").lower()
    dkim         = email.get("dkim", "").lower()
    dmarc        = email.get("dmarc", "").lower()
    from_domain  = email.get("from_domain", "")
    return_path  = email.get("return_path", "")
    subject      = email.get("subject", "")
    sender_ip    = email.get("sender_ip", "")
    links        = email.get("links", [])
    attachments  = email.get("attachments", [])

    ip_intel     = intel.get("ip", {})
    domain_intel = intel.get("domain", {})
    url_intels   = intel.get("urls", [])
    att_intels   = intel.get("attachments", [])
    whois        = intel.get("whois", {})

    malicious_urls = [u for u in url_intels if u.get("malicious")]
    malicious_atts = [a for a in att_intels if a.get("malicious")]

    # ── 1. SENDER IP ANALYSIS ─────────────────────────────────────────────
    if ip_intel.get("is_malicious"):
        confidence = ip_intel.get("abuse_confidence", 0)
        country    = ip_intel.get("country", "Unknown")
        asn_owner  = ip_intel.get("asn_owner", "Unknown ASN")
        findings.append(
            f"MALICIOUS SENDER INFRASTRUCTURE: The originating IP {sender_ip} "
            f"({country}, {asn_owner}) carries an AbuseIPDB confidence score of {confidence}%, "
            f"indicating active involvement in malicious activity. Emails from this IP should "
            f"be treated as high-risk regardless of other indicators."
        )
    elif sender_ip:
        country   = ip_intel.get("country", "Unknown")
        asn_owner = ip_intel.get("asn_owner", "Unknown")
        findings.append(
            f"Sender IP {sender_ip} ({country}, {asn_owner}) shows no current malicious "
            f"reputation in threat intelligence. However, clean IP reputation alone does not "
            f"confirm email legitimacy — threat actors frequently rotate infrastructure."
        )

    # ── 2. EMAIL AUTHENTICATION — CORRELATED ANALYSIS ────────────────────
    auth_failures = []
    if spf   != "pass": auth_failures.append("SPF")
    if dkim  != "pass": auth_failures.append("DKIM")
    if dmarc == "fail": auth_failures.append("DMARC")

    if len(auth_failures) == 3:
        findings.append(
            "CRITICAL AUTHENTICATION FAILURE: SPF, DKIM, and DMARC have all failed for this "
            "email. This triple failure is a strong indicator of spoofing or unauthorized "
            "sending. Legitimate organizations sending from their own domain almost never "
            "fail all three authentication checks simultaneously. This pattern is commonly "
            "observed in business email compromise (BEC) and brand impersonation attacks."
        )
    elif len(auth_failures) == 2:
        findings.append(
            f"AUTHENTICATION PARTIALLY FAILED: {' and '.join(auth_failures)} both failed. "
            f"While a single failure can sometimes be a configuration issue, two simultaneous "
            f"failures significantly increases the likelihood of email spoofing or unauthorized "
            f"use of the sender domain."
        )
    elif len(auth_failures) == 1:
        if "SPF" in auth_failures and dkim == "pass" and dmarc == "pass":
            findings.append(
                "SPF returned a softfail but DKIM and DMARC both passed. This pattern is "
                "common in legitimate bulk email senders (marketing platforms, CRMs) that "
                "send on behalf of a domain. The DKIM signature confirms the message was "
                "authorized by the domain owner. Risk contribution from authentication is low."
            )
        else:
            findings.append(
                f"{auth_failures[0]} authentication failed. While isolated authentication "
                f"failures can result from misconfiguration, analysts should correlate this "
                f"with other indicators before dismissing it."
            )
    else:
        findings.append(
            "Email passed all three authentication checks (SPF, DKIM, DMARC). This confirms "
            "the message was sent from an authorized server and has not been tampered with "
            "in transit. Authentication alone does not guarantee legitimacy — compromised "
            "accounts and lookalike domains can still pass all checks."
        )

    # ── 3. RETURN-PATH / FROM DOMAIN ALIGNMENT ───────────────────────────
    if from_domain and return_path:
        if from_domain not in return_path:
            rp_domain = ""
            if "@" in return_path:
                rp_domain = return_path.split("@")[-1].strip(">").strip()

            bulk_senders = [
                "sendgrid.net", "mailchimp.com", "amazonses.com",
                "mailgun.org", "sparkpostmail.com", "exacttarget.com",
                "salesforce.com", "marketo.com", "hubspot.com"
            ]
            is_bulk = any(b in rp_domain for b in bulk_senders)

            if is_bulk:
                findings.append(
                    f"Return-path domain ({rp_domain}) does not match sender domain "
                    f"({from_domain}), but belongs to a known legitimate bulk email provider. "
                    f"This is expected behavior when organizations use third-party email "
                    f"delivery platforms. This mismatch alone is not suspicious."
                )
            else:
                findings.append(
                    f"DOMAIN MISMATCH DETECTED: The From domain ({from_domain}) does not "
                    f"align with the Return-Path domain ({rp_domain}). This discrepancy "
                    f"is a common technique in phishing attacks where adversaries display "
                    f"a trusted brand name in the From field while routing replies to an "
                    f"attacker-controlled domain. Analysts should verify whether "
                    f"{rp_domain} has any legitimate relationship to {from_domain}."
                )
        else:
            findings.append(
                f"From domain and Return-Path are aligned on {from_domain}. No header "
                f"spoofing indicators detected in the sender routing chain."
            )

    # ── 4. DOMAIN REPUTATION ─────────────────────────────────────────────
    if domain_intel.get("malicious"):
        detections = domain_intel.get("detections", 0)
        findings.append(
            f"MALICIOUS DOMAIN CONFIRMED: The sender domain {from_domain} is flagged as "
            f"malicious by {detections} threat intelligence engine(s) on VirusTotal. "
            f"This domain has been identified as involved in phishing, malware distribution, "
            f"or other malicious activity. All emails from this domain should be blocked "
            f"and existing communications reviewed."
        )
    else:
        findings.append(
            f"Sender domain {from_domain} has no current malicious reputation flags. "
            f"Note that newly created phishing domains often have no reputation history — "
            f"a clean domain verdict should be combined with WHOIS age analysis."
        )

    # ── 5. SUBJECT LINE ANALYSIS ─────────────────────────────────────────
    if subject:
        urgency_keywords = [
            "urgent", "immediate", "action required", "verify", "suspended",
            "locked", "unusual activity", "unauthorized", "confirm", "alert",
            "limited time", "expires", "final notice", "invoice", "payment",
            "wire transfer", "account", "password", "reset", "click here"
        ]
        matched = [k for k in urgency_keywords if k.lower() in subject.lower()]
        if matched:
            findings.append(
                f"SOCIAL ENGINEERING INDICATORS IN SUBJECT: The subject line contains "
                f"urgency/action language: '{', '.join(matched)}'. Phishing emails "
                f"consistently use psychological pressure tactics in subject lines to "
                f"bypass rational decision-making. Subject: '{subject}'."
            )
        else:
            findings.append(
                f"Subject line '{subject}' contains no common urgency or social engineering "
                f"keywords. This does not rule out phishing but reduces likelihood of "
                f"mass-template phishing campaigns."
            )

    # ── 6. URL ANALYSIS ──────────────────────────────────────────────────
    if links:
        if malicious_urls:
            for u in malicious_urls:
                findings.append(
                    f"MALICIOUS URL DETECTED: {u.get('url')} was flagged as malicious "
                    f"by {u.get('detections', 0)} VirusTotal engine(s). This URL is "
                    f"associated with phishing pages, credential harvesting, or malware "
                    f"delivery. Any user who clicked this link should be treated as "
                    f"potentially compromised and their credentials reset immediately."
                )
        else:
            findings.append(
                f"{len(links)} URL(s) extracted from email body. All URLs returned clean "
                f"verdicts from VirusTotal at time of analysis. Note that URLs may be "
                f"cloaked, time-gated, or redirect to malicious content after initial "
                f"scanning — treat with caution if other indicators are present."
            )
    else:
        findings.append(
            "No URLs detected in the email body. Absence of URLs reduces the likelihood "
            "of credential harvesting attacks but does not rule out malicious intent — "
            "attachment-based or social engineering attacks may contain no links."
        )

    # ── 7. ATTACHMENT ANALYSIS ───────────────────────────────────────────
    if attachments:
        if malicious_atts:
            for i, att in enumerate(malicious_atts):
                original = attachments[i] if i < len(attachments) else {}
                findings.append(
                    f"MALICIOUS ATTACHMENT CONFIRMED: File '{original.get('filename', 'unknown')}' "
                    f"(SHA256: {original.get('sha256', 'N/A')}) was identified as malicious "
                    f"by {att.get('detections', 0)} VirusTotal engine(s). This file should "
                    f"be treated as active malware. Isolate any endpoint that opened this "
                    f"attachment and initiate incident response procedures immediately."
                )
        else:
            att_names = [a.get("filename", "unknown") for a in attachments]
            findings.append(
                f"Attachment(s) present: {', '.join(att_names)}. No malicious verdicts "
                f"returned from VirusTotal at time of analysis. Encrypted archives, "
                f"password-protected files, and documents with macros may evade "
                f"automated scanning — manual review is recommended for sensitive environments."
            )
    else:
        findings.append(
            "No file attachments detected in this email."
        )

    # ── 8. WHOIS / DOMAIN AGE ANALYSIS ───────────────────────────────────
    creation_date = whois.get("creation_date")
    print(f"[DEBUG] creation_date raw value: {repr(creation_date)}")
    print(f"[DEBUG] creation_date type: {type(creation_date)}")
    parsed_date   = None

    if creation_date:
        try:
            if isinstance(creation_date, str):
                creation_date = creation_date.strip("[]").split(",")[0].strip()
                parsed_date   = datetime.fromisoformat(creation_date)
            elif isinstance(creation_date, datetime):
                parsed_date = creation_date

            if parsed_date:
                if parsed_date.tzinfo is None:
                    parsed_date = parsed_date.replace(tzinfo=timezone.utc)

                age_days = (datetime.now(timezone.utc) - parsed_date).days

                if age_days < 30:
                    findings.append(
                        f"NEWLY REGISTERED DOMAIN — HIGH RISK: {from_domain} was registered "
                        f"only {age_days} day(s) ago. Domains registered within 30 days are "
                        f"a hallmark of phishing infrastructure. Threat actors register fresh "
                        f"domains specifically to avoid reputation-based blocking. This is a "
                        f"strong corroborating indicator of a phishing campaign."
                    )
                elif age_days < 180:
                    findings.append(
                        f"RECENTLY REGISTERED DOMAIN — MODERATE RISK: {from_domain} was "
                        f"registered {age_days} days ago ({age_days // 30} months). Domains "
                        f"under 6 months old warrant additional scrutiny, particularly when "
                        f"combined with other phishing indicators."
                    )
                else:
                    years = age_days // 365
                    findings.append(
                        f"Domain {from_domain} has been registered for approximately {years} "
                        f"year(s) (since {parsed_date.strftime('%Y-%m-%d')}). Established "
                        f"domain age reduces the likelihood of a newly-spun phishing domain, "
                        f"though compromised legitimate domains are frequently used in "
                        f"targeted attacks."
                    )
        except Exception:
            findings.append(
                "WHOIS creation date could not be parsed. Manual domain age verification "
                "is recommended via a WHOIS lookup tool."
            )
    else:
        findings.append(
            f"WHOIS data unavailable for {from_domain}. This may indicate a privacy-protected "
            f"registration, an expired domain, or a TLD not supported by the WHOIS lookup. "
            f"Inability to verify domain registration history is itself a moderate risk indicator."
        )

    # ── 9. CORRELATION SUMMARY ───────────────────────────────────────────
    high_signals = []
    if ip_intel.get("is_malicious"):  high_signals.append("malicious sender IP")
    if domain_intel.get("malicious"): high_signals.append("malicious sender domain")
    if malicious_urls:                high_signals.append(f"{len(malicious_urls)} malicious URL(s)")
    if malicious_atts:                high_signals.append(f"{len(malicious_atts)} malicious attachment(s)")
    if len(auth_failures) >= 2:       high_signals.append("multiple authentication failures")

    if high_signals:
        findings.append(
            f"CORRELATION SUMMARY: This email triggered {len(high_signals)} high-confidence "
            f"indicator(s): {', '.join(high_signals)}. The convergence of multiple independent "
            f"signals significantly increases confidence in a malicious classification. "
            f"Single indicators can produce false positives — correlated signals rarely do."
        )
    else:
        findings.append(
            "CORRELATION SUMMARY: No high-confidence malicious indicators were detected "
            "across sender infrastructure, authentication, URLs, or attachments. "
            "The email appears consistent with legitimate correspondence based on "
            "available threat intelligence at the time of analysis."
        )

    # ── 10. DYNAMIC RECOMMENDATIONS ──────────────────────────────────────
    recommendations = []

    if risk["score"] >= 70:
        recommendations.append(
            f"IMMEDIATE ACTION: Block sender domain {from_domain} and IP {sender_ip} "
            f"at the email gateway and firewall. Do not allow any further emails from "
            f"this infrastructure."
        )
    elif risk["score"] >= 40:
        recommendations.append(
            f"Consider adding {from_domain} to your email gateway watchlist and monitor "
            f"for further suspicious emails from this sender."
        )

    if malicious_urls:
        recommendations.append(
            "Identify all recipients of this email and verify whether any links were clicked. "
            "Reset credentials immediately for any user who interacted with the malicious URL(s)."
        )

    if malicious_atts:
        recommendations.append(
            "Isolate any endpoint that opened the malicious attachment. Initiate incident "
            "response procedures and conduct a full forensic investigation of affected systems."
        )

    if risk["score"] >= 40 or ip_intel.get("is_malicious") or domain_intel.get("malicious"):
        recommendations.append(
            f"Search email gateway logs for other messages originating from {sender_ip} "
            f"or {from_domain} to identify the full scope of the campaign."
        )

    if len(auth_failures) >= 2:
        recommendations.append(
            "Review your organization's DMARC, DKIM, and SPF policies. Enforce DMARC "
            "reject policy to prevent unauthorized use of your domain in spoofing attacks."
        )

    if parsed_date:
        try:
            age_days = (datetime.now(timezone.utc) - parsed_date).days
            if age_days < 180:
                recommendations.append(
                    f"Flag {from_domain} as a recently registered domain in your threat "
                    f"intelligence platform and monitor for associated infrastructure."
                )
        except Exception:
            pass

    if risk["score"] < 40:
        recommendations.append(
            "No immediate action required. Continue standard email security monitoring "
            "and ensure users are trained to report suspicious emails through official channels."
        )

    recommendations.append(
        "Conduct periodic phishing awareness training to help employees identify "
        "social engineering tactics and report suspicious emails promptly."
    )

    # ── CLASSIFICATION ────────────────────────────────────────────────────
    classification = (
        "Malicious"     if risk["score"] >= 70 else
        "Suspicious"    if risk["score"] >= 40 else
        "Non-Malicious"
    )

    return {
        "classification": classification,
        "facts": {
            "sender_email":  email.get("from_email"),
            "sender_domain": from_domain,
            "recipient":     email.get("to"),
            "subject":       subject,
            "return_path":   return_path,
            "sender_ip":     sender_ip,
            "spf":           spf,
            "dkim":          dkim,
            "dmarc":         dmarc,
            "urls":          links,
            "attachments":   attachments,
            "whois":         whois
        },
        "findings":        findings,
        "verdict": {
            "risk_level": risk["verdict"],
            "risk_score":  risk["score"],
            "reasons":     risk["reasons"]
        },
        "recommendations": recommendations
    }
