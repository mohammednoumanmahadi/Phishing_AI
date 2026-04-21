import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.threat_intel import (
    check_ip_reputation,
    check_vt_url,
    check_file_hash
)

# ---------------- TEST IP ---------------- #

test_ip = "185.220.101.1"

print("\n=== Testing IP Reputation ===")
ip_result = check_ip_reputation(test_ip)
print(ip_result)

# ---------------- TEST URL ---------------- #

test_url = "br-icloud.com.br"

print("\n=== Testing URL Reputation ===")
url_result = check_vt_url(test_url)
print(url_result)

# ---------------- TEST HASH ---------------- #

test_hash = "44d88612fea8a8f36de82e1278abb02f"

print("\n=== Testing File Hash Reputation ===")
hash_result = check_file_hash(test_hash)
print(hash_result)