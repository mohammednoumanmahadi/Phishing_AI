import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from core.email_analyzer import analyze_eml
from core.threat_intel import check_ip_reputation, check_vt_url, check_vt_domain, check_file_hash
from core.risk_engine import calculate_risk
from core.whois_lookup import get_whois
from core.soc_formatter import format_soc_output
from core.database import save_pipeline_result

def run_pipeline(eml_file):
    email = analyze_eml(eml_file)

    intel = {
        "ip": check_ip_reputation(email["sender_ip"]) if email["sender_ip"] else {},
        "domain": check_vt_domain(email["from_domain"]),
        "urls": [check_vt_url(u) for u in email["links"]],
        "attachments": [check_file_hash(a["sha256"]) for a in email["attachments"]],
        "whois": get_whois(email["from_domain"])
    }

    risk = calculate_risk(email, intel)
    soc_report = format_soc_output(email, intel, risk)

    result = {
        "email": email,
        "intel": intel,
        "risk": risk,
        "soc_report": soc_report
    }

    # persist to database
    scan_id = save_pipeline_result(result)
    result["scan_id"] = scan_id

    return result