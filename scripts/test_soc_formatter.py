import sys
import os

# Add project root to PYTHONPATH
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from core.pipeline import run_pipeline

# ✅ Build absolute path safely
TEST_EML = os.path.join(PROJECT_ROOT, "data", "sample-4.eml")

if not os.path.exists(TEST_EML):
    raise FileNotFoundError(f"Test EML not found: {TEST_EML}")

result = run_pipeline(TEST_EML)

print("\n=== PIPELINE OUTPUT ===")
print("EMAIL:")
print(result["email"])

print("\nINTEL:")
print(result["intel"])

print("\nRISK:")
print(result["risk"])

print(result.keys())
