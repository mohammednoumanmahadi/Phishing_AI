import requests

BASE = "http://localhost:8000"

print("Health:", requests.get(f"{BASE}/api/health").json())
print("Stats:", requests.get(f"{BASE}/api/stats").json())
print("Scans:", requests.get(f"{BASE}/api/scans").json())
print("IOCs:", requests.get(f"{BASE}/api/iocs").json())