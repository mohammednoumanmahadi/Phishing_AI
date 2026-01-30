import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

def generate_report(context: dict) -> str:
    """
    Sends phishing analysis context to Ollama (Mistral)
    and returns a structured security report.
    """

    prompt = f"""
You are a SOC analyst.

Analyze the following email security data and generate a professional phishing analysis report.

Include:
1. Threat Summary
2. Indicators of Compromise (IP, Domain, URLs, Hashes)
3. WHOIS insights
4. Risk Level (Low / Medium / High)
5. Reasoning
6. Recommended Actions

DATA:
{json.dumps(context, indent=2)}
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=60
    )

    response.raise_for_status()
    return response.json()["response"]
