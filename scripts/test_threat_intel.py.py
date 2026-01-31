import requests
import os

# ================= CONFIG ================= #

VT_API_KEY = "PUT_YOUR_VT_KEY_HERE"
ABUSEIPDB_API_KEY = "PUT_YOUR_ABUSEIPDB_KEY_HERE"

VT_BASE = "https://www.virustotal.com/api/v3"

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}

ABUSE_HEADERS = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

# ================= IP REPUTATION ================= #

def check_ip_reputation(ip):
    if not ip:
        return {"error": "No IP provided"}

    result = {
        "ip": ip,
        "abuse_confidence": 0,
        "is_malicious": False,

        # Enrichment
        "country": None,
        "asn": None,
        "asn_owner": None,
        "network": None,

        "error": None
    }

    try:
        # AbuseIPDB
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=ABUSE_HEADERS,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )

        if r.status_code == 200:
            data = r.json()["data"]
            result["abuse_confidence"] = data.get("abuseConfidenceScore", 0)
            result["is_malicious"] = result["abuse_confidence"] > 50

        # VirusTotal enrichment
        vt = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers=VT_HEADERS,
            timeout=10
        )

        if vt.status_code == 200:
            attrs = vt.json()["data"]["attributes"]
            result["country"] = attrs.get("country")
            result["asn"] = attrs.get("asn")
            result["asn_owner"] = attrs.get("as_owner")
            result["network"] = attrs.get("network")

    except Exception as e:
        result["error"] = str(e)

    return result

# ================= URL / DOMAIN ================= #

def check_vt_url(url):
    if not url:
        return {"error": "No URL provided"}

    try:
        encoded = requests.utils.quote(url, safe="")
        r = requests.get(
            f"{VT_BASE}/urls/{encoded}",
            headers=VT_HEADERS,
            timeout=10
        )

        if r.status_code != 200:
            return {"malicious": False, "error": "VT lookup failed"}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "url": url,
            "malicious": stats["malicious"] > 0,
            "stats": stats
        }

    except Exception as e:
        return {"error": str(e)}

# ================= FILE HASH ================= #

def check_file_hash(hash_value):
    if not hash_value:
        return {"error": "No hash provided"}

    try:
        r = requests.get(
            f"{VT_BASE}/files/{hash_value}",
            headers=VT_HEADERS,
            timeout=10
        )

        if r.status_code != 200:
            return {"malicious": False, "error": "VT lookup failed"}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "hash": hash_value,
            "malicious": stats["malicious"] > 0,
            "stats": stats
        }

    except Exception as e:
        return {"error": str(e)}
