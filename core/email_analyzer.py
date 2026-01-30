import os
import re
import email
import hashlib
import ipaddress
from email import policy
from email.utils import parseaddr

# ---------------- SAFE DECODING ---------------- #

def safe_get_text(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset()
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")

# ---------------- HASH FUNCTION ---------------- #

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

# ---------------- REGEX ---------------- #

URL_REGEX = re.compile(r'https?://[^\s<>"\'\]]+', re.IGNORECASE)
IP_REGEX = re.compile(
    r'(?:(?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+)'
)

# ---------------- IP UTIL ---------------- #

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False

# ---------------- MAIN ANALYZER ---------------- #

def analyze_eml(file_path):
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    results = {
        "file": os.path.basename(file_path),
        "subject": msg.get("subject", ""),
        "from_raw": msg.get("from", ""),
        "from_email": "",
        "from_domain": "",
        "return_path": msg.get("return-path", ""),
        "sender_ip": None,
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "body": "",
        "links": [],
        "attachments": []
    }

    # -------- FROM PARSE -------- #
    _, email_addr = parseaddr(results["from_raw"])
    results["from_email"] = email_addr
    if "@" in email_addr:
        results["from_domain"] = email_addr.split("@")[1]

    # -------- SENDER IP (ROBUST) -------- #
    received_headers = msg.get_all("received", [])
    found_ips = []

    for header in received_headers:
        for ip in IP_REGEX.findall(header):
            if is_public_ip(ip):
                found_ips.append(ip)

    if found_ips:
        results["sender_ip"] = found_ips[-1]  # closest to sender

    # -------- SPF / DKIM / DMARC -------- #
    auth_results = msg.get_all("authentication-results", [])

    for auth in auth_results:
        auth_lower = auth.lower()
        if "spf=" in auth_lower:
            results["spf"] = re.search(r'spf=(\w+)', auth_lower).group(1)
        if "dkim=" in auth_lower:
            results["dkim"] = re.search(r'dkim=(\w+)', auth_lower).group(1)
        if "dmarc=" in auth_lower:
            results["dmarc"] = re.search(r'dmarc=(\w+)', auth_lower).group(1)

    # -------- BODY / ATTACHMENTS -------- #
    links = set()

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()

            if ctype == "text/plain" and disp is None:
                text = safe_get_text(part)
                results["body"] += text
                links.update(URL_REGEX.findall(text))

            if disp == "attachment":
                data = part.get_payload(decode=True)
                if data:
                    results["attachments"].append({
                        "filename": part.get_filename(),
                        "sha256": sha256_hash(data),
                        "size": len(data)
                    })
    else:
        text = safe_get_text(msg)
        results["body"] = text
        links.update(URL_REGEX.findall(text))

    results["links"] = list(links)
    results["body"] = results["body"][:2000]

    return results
