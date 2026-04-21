import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.risk_engine import calculate_risk

email = {
    "spf": "fail",
    "dkim": "pass",
    "dmarc": "fail",
    "body": "Urgent! Verify your account immediately"
}

intel = {
    "ip": {"malicious": True},
    "domain": {"malicious": False},
    "urls": [{"malicious": True}],
    "attachments": []
}

result = calculate_risk(email, intel)

print("\n=== RISK ENGINE TEST ===")
print(result)
