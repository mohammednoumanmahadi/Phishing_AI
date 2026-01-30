import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.email_analyzer import analyze_eml

# 🔴 CHANGE THIS PATH to a REAL .eml file you have
TEST_EML = r"C:\Users\moham\OneDrive\Desktop\AI\Phishing_AI\data\sample-4.eml"

if not os.path.exists(TEST_EML):
    print("❌ Test EML file not found:", TEST_EML)
    exit(1)

result = analyze_eml(TEST_EML)

print("=" * 70)
print("EMAIL ANALYZER TEST RESULT")
print("=" * 70)

for k, v in result.items():
    if isinstance(v, list):
        print(f"{k}:")
        for item in v:
            print("  ", item)
    else:
        print(f"{k}: {v}")
