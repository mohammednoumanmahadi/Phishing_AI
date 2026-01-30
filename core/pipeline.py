import sys
import os

# Add project root (Phishing_AI) to Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from core.email_analyzer import analyze_eml
from core.threat_intel import reputation_score, check_vt_url, check_file_hash
from core.risk_engine import calculate_risk 
from core.whois_lookup import  get_whois

def run_pipeline(eml_file):
    # Step 1: Analyze email
    result = analyze_eml(eml_file)

    # Step 2: Threat intel
    intel = {
        "ip": check_ip_reputation(result["sender_ip"]),
        "domain": check_vt_url(result["from_domain"]),
        "urls": [check_vt_url(u) for u in result["links"]],
        "attachments": [check_file_hash(a["sha256"]) for a in result["attachments"]],
        "whois": get_whois_info(result["from_domain"])  # <--- WHOIS added
    }

    # Step 3: Risk scoring
    risk = calculate_risk(result, intel)

    print("INTEL STRUCTURE:", intel)

    # Step 4: Return full analysis
    return {
        "email": result,
        "intel": intel,
        "risk": risk
    }
