import requests
import os
import base64
import time
from pathlib import Path
from dotenv import load_dotenv
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.database import (
    get_cached_ip, set_cached_ip,
    get_cached_url, set_cached_url,
    get_cached_domain, set_cached_domain,
    get_cached_hash, set_cached_hash
)

load_dotenv(Path(__file__).resolve().parent / "api.env")

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")

VT_BASE = "https://www.virustotal.com/api/v3"

VT_HEADERS = {"x-apikey": VT_API_KEY}
ABUSE_HEADERS = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

# ================= IP REPUTATION ================= #

def check_ip_reputation(ip):
    if not ip:
        return {"error": "No IP provided"}

    # check cache first
    cached = get_cached_ip(ip)
    if cached:
        print(f"[CACHE HIT] IP: {ip}")
        return cached

    result = {
        "ip": ip,
        "abuse_confidence": 0,
        "is_malicious": False,
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

        time.sleep(1)

        # VirusTotal
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

        time.sleep(1)

        # IPInfo fallback
        if not result["country"] or not result["asn"]:
            ipinfo = requests.get(
                f"https://ipinfo.io/{ip}",
                params={"token": IPINFO_API_KEY},
                timeout=10
            )
            if ipinfo.status_code == 200:
                data = ipinfo.json()
                result["country"] = result["country"] or data.get("country")
                if data.get("org"):
                    parts = data["org"].split(" ", 1)
                    if len(parts) == 2:
                        result["asn"] = result["asn"] or parts[0]
                        result["asn_owner"] = result["asn_owner"] or parts[1]

    except Exception as e:
        result["error"] = str(e)

    # save to cache
    set_cached_ip(ip, result)
    return result

# ================= URL CHECK ================= #

def check_vt_url(url):
    if not url:
        return {"error": "No URL provided"}

    if not url.startswith("http"):
        url = "http://" + url

    # check cache first
    cached = get_cached_url(url)
    if cached:
        print(f"[CACHE HIT] URL: {url}")
        return cached

    try:
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        r = requests.get(
            f"{VT_BASE}/urls/{encoded}",
            headers=VT_HEADERS,
            timeout=10
        )

        if r.status_code != 200:
            submit = requests.post(
                f"{VT_BASE}/urls",
                headers=VT_HEADERS,
                data={"url": url},
                timeout=10
            )
            if submit.status_code not in (200, 201):
                return {"url": url, "malicious": False,
                        "error": f"Submission failed — HTTP {submit.status_code}"}

            for attempt in range(10):
                time.sleep(3)
                r = requests.get(
                    f"{VT_BASE}/urls/{encoded}",
                    headers=VT_HEADERS,
                    timeout=10
                )
                if r.status_code == 200:
                    break
            else:
                return {"url": url, "malicious": False, "error": "Analysis timed out"}

        if r.status_code != 200:
            return {"url": url, "malicious": False}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)

        result = {
            "url": url,
            "malicious": detections > 0,
            "detections": detections,
            "stats": stats
        }

        # save to cache
        set_cached_url(url, result)
        return result

    except Exception as e:
        return {"error": str(e)}

# ================= DOMAIN CHECK ================= #

def check_vt_domain(domain):
    if not domain:
        return {"error": "No domain provided"}

    # check cache first
    cached = get_cached_domain(domain)
    if cached:
        print(f"[CACHE HIT] Domain: {domain}")
        return cached

    try:
        r = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers=VT_HEADERS,
            timeout=10
        )
        time.sleep(1)

        if r.status_code != 200:
            return {"domain": domain, "malicious": False}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)

        result = {
            "domain": domain,
            "malicious": detections > 0,
            "detections": detections,
            "stats": stats
        }

        # save to cache
        set_cached_domain(domain, result)
        return result

    except Exception as e:
        return {"error": str(e)}

# ================= FILE HASH ================= #

def check_file_hash(hash_value):
    if not hash_value:
        return {"error": "No hash provided"}

    # check cache first
    cached = get_cached_hash(hash_value)
    if cached:
        print(f"[CACHE HIT] Hash: {hash_value}")
        return cached

    try:
        r = requests.get(
            f"{VT_BASE}/files/{hash_value}",
            headers=VT_HEADERS,
            timeout=10
        )
        time.sleep(1)

        if r.status_code == 404:
            return {"hash": hash_value, "malicious": False,
                    "error": "Hash not found in VT database"}

        if r.status_code != 200:
            return {"hash": hash_value, "malicious": False}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)

        result = {
            "hash": hash_value,
            "malicious": detections > 0,
            "detections": detections,
            "stats": stats
        }

        # save to cache
        set_cached_hash(hash_value, result)
        return result

    except Exception as e:
        return {"error": str(e)}