import requests

# ---------------- CONFIG ----------------
VT_API_KEY = "ca55913f8826e1829d4d69c79df722c649e750f27a655d50797a5a00c1734e1b"
ABUSEIPDB_API_KEY = "6ccb99f95d89bf1b64a595c75df7b0bc3ff62a07047fb5c63384630f4d45bd091d0dd70cd1add207"

# ---------------- IP CHECK ----------------
def reputation_score(ip):
    if not ip:
        return {"malicious": False, "confidence": 0}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(url, headers=headers, params=params, timeout=10)
    data = r.json().get("data", {})

    return {
        "malicious": data.get("abuseConfidenceScore", 0) > 50,
        "confidence": data.get("abuseConfidenceScore", 0)
    }

# ---------------- DOMAIN / URL ----------------
def check_vt_url(url):
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{requests.utils.quote(url, safe='')}"

    r = requests.get(vt_url, headers=headers)
    if r.status_code != 200:
        return {"malicious": False}

    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"] > 0,
        "stats": stats
    }

# ---------------- FILE HASH ----------------
def check_file_hash(hash_value):
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"malicious": False}

    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"] > 0,
        "stats": stats
    }
