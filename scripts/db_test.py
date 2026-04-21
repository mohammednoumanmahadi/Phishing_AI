import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.database import init_db, get_all_scans, get_dashboard_stats
from core.database import (
    get_cached_ip, set_cached_ip,
    get_cached_url, set_cached_url
)

init_db()
print("DB initialized OK")

print("\n=== Dashboard Stats ===")
print(get_dashboard_stats())

print("\n=== All Scans ===")
scans = get_all_scans()
for s in scans:
    print(s)

print("\n=== Testing Cache ===")

set_cached_ip("1.2.3.4", {"ip": "1.2.3.4", "is_malicious": True, "abuse_confidence": 90})
set_cached_url("http://br-icloud.com.br", {"url": "http://br-icloud.com.br", "malicious": True, "detections": 12})

print("IP cache:", get_cached_ip("1.2.3.4"))
print("URL cache:", get_cached_url("http://br-icloud.com.br"))
print("Missing key:", get_cached_ip("9.9.9.9"))