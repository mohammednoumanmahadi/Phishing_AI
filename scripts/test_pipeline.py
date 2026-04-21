import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import run_pipeline

TEST_EML = r"C:\Users\moham\OneDrive\Desktop\AI\Phishing_AI\data\sample-5.eml"

result = run_pipeline(TEST_EML)

print("\n=== PIPELINE RESULT ===\n")

print("SUBJECT:", result["email"]["subject"])
print("FROM:", result["email"]["from_email"])
print("SENDER IP:", result["email"]["sender_ip"])

print("\n--- INTEL ---")
for k, v in result["intel"].items():
    print(k, "=>", v)

print("\n--- RISK ---")
print(result["risk"])
