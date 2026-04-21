import sys
import os

# make sure Python can find the core/ folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import tempfile
import shutil

from core.pipeline import run_pipeline
from core.llm_report import generate_report
from core.pdf_report import generate_pdf
from core.database import (
    get_all_scans,
    get_scan_by_id,
    get_dashboard_stats,
    get_connection,
    init_db
)

# ─────────────────────────────────────────
#  Create the FastAPI app
# ─────────────────────────────────────────

app = FastAPI(title="Phishing AI", version="1.0")

# CORS — this allows your React frontend (running on port 5173)
# to talk to your FastAPI backend (running on port 8000)
# Without this the browser will block all requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# make sure DB and cache tables exist on startup
init_db()

# ─────────────────────────────────────────
#  ENDPOINT 1 — Health check
#  GET /api/health
#  Just confirms the server is running
# ─────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}

# ─────────────────────────────────────────
#  ENDPOINT 2 — Dashboard stats
#  GET /api/stats
#  Returns total scans, malicious count etc
#  Used by the overview dashboard cards
# ─────────────────────────────────────────

@app.get("/api/stats")
def stats():
    return get_dashboard_stats()

# ─────────────────────────────────────────
#  ENDPOINT 3 — All historical scans
#  GET /api/scans
#  Returns list of all past scans
#  Used by the history table page
# ─────────────────────────────────────────

@app.get("/api/scans")
def all_scans():
    return get_all_scans()

# ─────────────────────────────────────────
#  ENDPOINT 4 — Single scan detail
#  GET /api/scan/{id}
#  Returns full detail for one scan
#  Used when user clicks a row in history
# ─────────────────────────────────────────

@app.get("/api/scan/{scan_id}")
def single_scan(scan_id: int):
    result = get_scan_by_id(scan_id)
    if not result["scan"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

# ─────────────────────────────────────────
#  ENDPOINT 5 — Upload and scan email
#  POST /api/scan
#  Accepts .eml file, runs full pipeline
#  Returns risk score, findings, SOC report
#  This is the main feature endpoint
# ─────────────────────────────────────────

@app.post("/api/scan")
async def scan_email(file: UploadFile = File(...)):

    # only accept .eml files
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    # save uploaded file to a temp location so pipeline can read it
    # we use tempfile so it gets cleaned up automatically
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        # run the full pipeline — this is where all the magic happens
        result = run_pipeline(tmp_path)

        # build a clean response for the frontend
        return {
            "scan_id":        result["scan_id"],
            "email":          result["email"],
            "risk":           result["risk"],
            "soc_report":     result["soc_report"],
            "intel": {
                "ip":          result["intel"]["ip"],
                "domain":      result["intel"]["domain"],
                "urls":        result["intel"]["urls"],
                "attachments": result["intel"]["attachments"],
                "whois":       result["intel"]["whois"],
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        # always clean up the temp file
        os.unlink(tmp_path)

# ─────────────────────────────────────────
#  ENDPOINT 6 — Generate LLM report
#  POST /api/report/{scan_id}
#  Runs Mistral on the saved scan data
#  Returns the full SOC narrative report
# ─────────────────────────────────────────

@app.post("/api/report/{scan_id}")
def generate_llm_report(scan_id: int):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data["scan"]:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        report_text = generate_report(scan_data)
        return {"scan_id": scan_id, "report": report_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM error: {str(e)}")

# ─────────────────────────────────────────
#  ENDPOINT 7 — Download PDF report
#  GET /api/pdf/{scan_id}
#  Generates and returns a PDF file
# ─────────────────────────────────────────

@app.get("/api/pdf/{scan_id}")
def download_pdf(scan_id: int):
    scan_data = get_scan_by_id(scan_id)
    if not scan_data["scan"]:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        # generate LLM report text first
        report_text = generate_report(scan_data)
        # convert to PDF
        pdf_path = generate_pdf(report_text)
        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"Phishing_Report_{scan_id}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────
#  ENDPOINT 8 — IOC tracker
#  GET /api/iocs
#  Returns all malicious IPs, URLs, domains
#  aggregated across all scans
#  Used by the IOC tracker page
# ─────────────────────────────────────────

@app.get("/api/iocs")
def get_iocs():
    conn = get_connection()

    # malicious IPs with how many times seen
    ips = conn.execute("""
        SELECT ip, country, asn_owner,
               abuse_confidence,
               COUNT(*) as seen_in_scans
        FROM ip_findings
        WHERE is_malicious = 1
        GROUP BY ip
        ORDER BY seen_in_scans DESC
    """).fetchall()

    # malicious URLs with count
    urls = conn.execute("""
        SELECT url, detections,
               COUNT(*) as seen_in_scans
        FROM url_findings
        WHERE malicious = 1
        GROUP BY url
        ORDER BY seen_in_scans DESC
    """).fetchall()

    # malicious attachments with count
    hashes = conn.execute("""
        SELECT filename, sha256, detections,
               COUNT(*) as seen_in_scans
        FROM attachment_findings
        WHERE malicious = 1
        GROUP BY sha256
        ORDER BY seen_in_scans DESC
    """).fetchall()

    conn.close()

    return {
        "malicious_ips":   [dict(r) for r in ips],
        "malicious_urls":  [dict(r) for r in urls],
        "malicious_hashes": [dict(r) for r in hashes]
    }