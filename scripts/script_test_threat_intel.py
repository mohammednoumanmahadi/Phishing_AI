import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.threat_intel import (
    check_ip_reputation,
    check_vt_url,
    check_file_hash
)

print("\n=== IP TEST ===")
print(check_ip_reputation("218.157.171.60"))

print("\n=== URL TEST ===")
print(check_vt_url("www.linkedin.com"))

print("\n=== HASH TEST ===")
print(check_file_hash("44d88612fea8a8f36de82e1278abb02f"))
