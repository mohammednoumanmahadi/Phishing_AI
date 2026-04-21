import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.llm_report import generate_report

# 🔹 Minimal realistic context (mock pipeline output)
test_context = {
    "email": {
        "subject": "Meeting Request",
        "from_email": "jason.bssuniversal@outlook.com",
        "from_domain": "outlook.com",
        "return_path": "jason.bssuniversal=outlook.com__abc123@mail.example.com",
        "sender_ip": "18.222.52.31",
        "spf": "pass",
        "dkim": "none",
        "dmarc": "none",
        "links": ["https://yeswehack.com"],
        "attachments": []
    },
    "intel": {
        "ip": {
            "malicious": False,
            "confidence": 20,
            "asn": "AS16509",
            "isp": "Amazon"
        },
        "domain": {"malicious": False},
        "urls": [{"url": "https://yeswehack.com", "malicious": False}],
        "attachments": [],
        "whois": {
            "domain": "yeswehack.com",
            "registrar": "Gandi",
            "country": "FR"
        }
    },
    "risk": {
        "score": 25,
        "verdict": "Low Risk",
        "reasons": ["External sender", "No malicious indicators"]
    }
}

print("\n=== LLM REPORT TEST START ===\n")

report = generate_report(test_context)

print(report)

print("\n=== LLM REPORT TEST END ===")
