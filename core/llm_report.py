import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

def generate_report(context: dict) -> str:
    """
    Sends phishing analysis context to Ollama (Mistral)
    and returns a professional SOC-style report.
    """

    prompt = f"""
You are a Senior SOC Analyst performing an enterprise phishing investigation.

STRICT RULES:
- Use ONLY the data provided.
- Do NOT assume missing information.
- If data is not available, write "Not Available".
- Do NOT exaggerate risk.
- Justify every conclusion with evidence.
- If a well-known provider (Outlook, Gmail, Google, Microsoft) is involved,
  evaluate Return-Path alignment and authentication results carefully.

-------------------------
REPORT FORMAT
-------------------------

Dear Team,

We have analyzed the received email with the following details:

Email Details:
• Sender Address:
• Recipient Address:
• Subject:
• Return-Path:
• Sender IP Address:
• Sender Domain:
• SPF Result:
• DKIM Result:
• DMARC Result:

Threat Intelligence Summary:
• IP Reputation:
• Domain Reputation:
• URL Findings:
• Attachment Findings:
• WHOIS Summary:

Analysis:
• Provide bullet-point analysis based strictly on evidence
• Clearly state whether URLs and domains are clean or suspicious
• If WHOIS data is available, mention whether the domain is newly registered
• Compare Sender Domain and Return-Path domain and explain any mismatch
• Identify look-alike or impersonation attempts (e.g., microsoft-support.com vs microsoft.com)
• If sender uses Outlook/Gmail but Return-Path belongs to a third-party service,
  explain whether this is expected or suspicious
• Mention SPF, DKIM, and DMARC results and their impact
• Clearly justify why the email is classified as Malicious or Non-Malicious

Risk Assessment:
• Overall Risk Level:
• Risk Score:
• Reasoning:

Recommendations:
• Kindly delete the email and block the domain and IP if it is not relevant to business
• Conduct periodic phishing awareness training for end users
• Educate users not to register corporate emails on third-party websites
• Educate users not to click URLs from unsolicited external emails

-------------------------
DATA FOR ANALYSIS
-------------------------
{json.dumps(context, indent=2)}

-------------------------
END OF INSTRUCTIONS
-------------------------

Respond ONLY with the formatted SOC report.
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=90
    )

    response.raise_for_status()
    return response.json()["response"]
