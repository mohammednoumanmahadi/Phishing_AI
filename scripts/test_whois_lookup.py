import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from core.whois_lookup import get_whois

# 🔴 Test with a known domain
TEST_DOMAIN = "google.com"

result = get_whois(TEST_DOMAIN)

print("=" * 70)
print("WHOIS LOOKUP TEST")
print("=" * 70)

for k, v in result.items():
    print(f"{k}: {v}")
