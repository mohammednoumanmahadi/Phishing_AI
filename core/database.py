import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "phishing_history.db"

def get_connection():
    os.makedirs(DB_PATH.parent, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT NOT NULL,
            filename    TEXT,
            subject     TEXT,
            from_email  TEXT,
            from_domain TEXT,
            return_path TEXT,
            sender_ip   TEXT,
            spf         TEXT,
            dkim        TEXT,
            dmarc       TEXT
        );

        CREATE TABLE IF NOT EXISTS risk_results (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL REFERENCES email_scans(id),
            score          INTEGER,
            verdict        TEXT,
            classification TEXT,
            reasons        TEXT
        );

        CREATE TABLE IF NOT EXISTS url_findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL REFERENCES email_scans(id),
            url        TEXT,
            malicious  INTEGER,
            detections INTEGER
        );

        CREATE TABLE IF NOT EXISTS attachment_findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL REFERENCES email_scans(id),
            filename   TEXT,
            sha256     TEXT,
            malicious  INTEGER,
            detections INTEGER
        );

        CREATE TABLE IF NOT EXISTS ip_findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER NOT NULL REFERENCES email_scans(id),
            ip               TEXT,
            is_malicious     INTEGER,
            abuse_confidence INTEGER,
            country          TEXT,
            asn              TEXT,
            asn_owner        TEXT
        );
    """)

    conn.commit()
    conn.close()

def save_pipeline_result(result):
    """
    Takes the full dict returned by run_pipeline() and persists
    everything to the database. Returns the new scan_id.
    """
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    try:
        email    = result["email"]
        intel    = result["intel"]
        risk     = result["risk"]
        soc      = result["soc_report"]

        # ---------- email_scans ----------
        cursor.execute("""
            INSERT INTO email_scans
                (scanned_at, filename, subject, from_email, from_domain,
                 return_path, sender_ip, spf, dkim, dmarc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            email.get("file"),
            email.get("subject"),
            email.get("from_email"),
            email.get("from_domain"),
            email.get("return_path"),
            email.get("sender_ip"),
            email.get("spf"),
            email.get("dkim"),
            email.get("dmarc"),
        ))
        scan_id = cursor.lastrowid

        # ---------- risk_results ----------
        cursor.execute("""
            INSERT INTO risk_results
                (scan_id, score, verdict, classification, reasons)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            risk.get("score"),
            risk.get("verdict"),
            soc.get("classification"),
            json.dumps(risk.get("reasons", [])),
        ))

        # ---------- url_findings ----------
        for url_result in intel.get("urls", []):
            cursor.execute("""
                INSERT INTO url_findings
                    (scan_id, url, malicious, detections)
                VALUES (?, ?, ?, ?)
            """, (
                scan_id,
                url_result.get("url"),
                int(bool(url_result.get("malicious"))),
                url_result.get("detections", 0),
            ))

        # ---------- attachment_findings ----------
        for i, att_result in enumerate(intel.get("attachments", [])):
            original = email.get("attachments", [])
            filename = original[i]["filename"] if i < len(original) else None
            cursor.execute("""
                INSERT INTO attachment_findings
                    (scan_id, filename, sha256, malicious, detections)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                filename,
                att_result.get("hash"),
                int(bool(att_result.get("malicious"))),
                att_result.get("detections", 0),
            ))

        # ---------- ip_findings ----------
        ip = intel.get("ip", {})
        if ip and not ip.get("error"):
            cursor.execute("""
                INSERT INTO ip_findings
                    (scan_id, ip, is_malicious, abuse_confidence,
                     country, asn, asn_owner)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                ip.get("ip"),
                int(bool(ip.get("is_malicious"))),
                ip.get("abuse_confidence", 0),
                ip.get("country"),
                ip.get("asn"),
                ip.get("asn_owner"),
            ))

        conn.commit()
        return scan_id

    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def get_all_scans():
    """Returns all scans joined with risk results — for the dashboard history table."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            e.id, e.scanned_at, e.filename, e.subject,
            e.from_email, e.from_domain, e.sender_ip,
            e.spf, e.dkim, e.dmarc,
            r.score, r.verdict, r.classification
        FROM email_scans e
        LEFT JOIN risk_results r ON r.scan_id = e.id
        ORDER BY e.scanned_at DESC
    """)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_by_id(scan_id):
    """Returns full detail for a single scan — for the report viewer."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM email_scans WHERE id = ?", (scan_id,))
    scan = dict(cursor.fetchone() or {})

    cursor.execute("SELECT * FROM risk_results WHERE scan_id = ?", (scan_id,))
    risk = dict(cursor.fetchone() or {})
    if risk.get("reasons"):
        risk["reasons"] = json.loads(risk["reasons"])

    cursor.execute("SELECT * FROM url_findings WHERE scan_id = ?", (scan_id,))
    urls = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM attachment_findings WHERE scan_id = ?", (scan_id,))
    attachments = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM ip_findings WHERE scan_id = ?", (scan_id,))
    ip = dict(cursor.fetchone() or {})

    conn.close()
    return {
        "scan": scan,
        "risk": risk,
        "urls": urls,
        "attachments": attachments,
        "ip": ip
    }


def get_dashboard_stats():
    """Aggregated stats for the dashboard overview cards."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM email_scans")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as c FROM risk_results WHERE classification = 'Malicious'")
    malicious = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM risk_results WHERE classification = 'Suspicious'")
    suspicious = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM risk_results WHERE classification = 'Non-Malicious'")
    clean = cursor.fetchone()["c"]

    cursor.execute("SELECT AVG(score) as avg FROM risk_results")
    avg_score = cursor.fetchone()["avg"] or 0

    cursor.execute("SELECT COUNT(*) as c FROM url_findings WHERE malicious = 1")
    malicious_urls = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM attachment_findings WHERE malicious = 1")
    malicious_attachments = cursor.fetchone()["c"]

    conn.close()
    return {
        "total_scans": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
        "avg_risk_score": round(avg_score, 1),
        "malicious_urls": malicious_urls,
        "malicious_attachments": malicious_attachments
    }
# ================= CACHE LAYER ================= #

CACHE_TTL_DAYS = 7

def _is_fresh(cached_at: str) -> bool:
    """Returns True if cached result is within TTL."""
    try:
        cached_time = datetime.fromisoformat(cached_at)
        return (datetime.utcnow() - cached_time).days < CACHE_TTL_DAYS
    except Exception:
        return False


def init_cache_tables(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cache_ip (
            ip          TEXT PRIMARY KEY,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cache_url (
            url         TEXT PRIMARY KEY,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cache_domain (
            domain      TEXT PRIMARY KEY,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cache_hash (
            hash        TEXT PRIMARY KEY,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        );
    """)
    conn.commit()


def init_db():
    """Re-export so pipeline import still works."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT NOT NULL,
            filename    TEXT,
            subject     TEXT,
            from_email  TEXT,
            from_domain TEXT,
            return_path TEXT,
            sender_ip   TEXT,
            spf         TEXT,
            dkim        TEXT,
            dmarc       TEXT
        );

        CREATE TABLE IF NOT EXISTS risk_results (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL REFERENCES email_scans(id),
            score          INTEGER,
            verdict        TEXT,
            classification TEXT,
            reasons        TEXT
        );

        CREATE TABLE IF NOT EXISTS url_findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL REFERENCES email_scans(id),
            url        TEXT,
            malicious  INTEGER,
            detections INTEGER
        );

        CREATE TABLE IF NOT EXISTS attachment_findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER NOT NULL REFERENCES email_scans(id),
            filename   TEXT,
            sha256     TEXT,
            malicious  INTEGER,
            detections INTEGER
        );

        CREATE TABLE IF NOT EXISTS ip_findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER NOT NULL REFERENCES email_scans(id),
            ip               TEXT,
            is_malicious     INTEGER,
            abuse_confidence INTEGER,
            country          TEXT,
            asn              TEXT,
            asn_owner        TEXT
        );
    """)
    conn.commit()
    init_cache_tables(conn)
    conn.close()


# ---- IP cache ---- #

def get_cached_ip(ip: str):
    conn = get_connection()
    init_cache_tables(conn)
    row = conn.execute(
        "SELECT result, cached_at FROM cache_ip WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    if row and _is_fresh(row["cached_at"]):
        return json.loads(row["result"])
    return None

def set_cached_ip(ip: str, result: dict):
    conn = get_connection()
    init_cache_tables(conn)
    conn.execute(
        "INSERT OR REPLACE INTO cache_ip (ip, result, cached_at) VALUES (?, ?, ?)",
        (ip, json.dumps(result), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ---- URL cache ---- #

def get_cached_url(url: str):
    conn = get_connection()
    init_cache_tables(conn)
    row = conn.execute(
        "SELECT result, cached_at FROM cache_url WHERE url = ?", (url,)
    ).fetchone()
    conn.close()
    if row and _is_fresh(row["cached_at"]):
        return json.loads(row["result"])
    return None

def set_cached_url(url: str, result: dict):
    conn = get_connection()
    init_cache_tables(conn)
    conn.execute(
        "INSERT OR REPLACE INTO cache_url (url, result, cached_at) VALUES (?, ?, ?)",
        (url, json.dumps(result), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ---- Domain cache ---- #

def get_cached_domain(domain: str):
    conn = get_connection()
    init_cache_tables(conn)
    row = conn.execute(
        "SELECT result, cached_at FROM cache_domain WHERE domain = ?", (domain,)
    ).fetchone()
    conn.close()
    if row and _is_fresh(row["cached_at"]):
        return json.loads(row["result"])
    return None

def set_cached_domain(domain: str, result: dict):
    conn = get_connection()
    init_cache_tables(conn)
    conn.execute(
        "INSERT OR REPLACE INTO cache_domain (domain, result, cached_at) VALUES (?, ?, ?)",
        (domain, json.dumps(result), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


# ---- Hash cache ---- #

def get_cached_hash(hash_value: str):
    conn = get_connection()
    init_cache_tables(conn)
    row = conn.execute(
        "SELECT result, cached_at FROM cache_hash WHERE hash = ?", (hash_value,)
    ).fetchone()
    conn.close()
    if row and _is_fresh(row["cached_at"]):
        return json.loads(row["result"])
    return None

def set_cached_hash(hash_value: str, result: dict):
    conn = get_connection()
    init_cache_tables(conn)
    conn.execute(
        "INSERT OR REPLACE INTO cache_hash (hash, result, cached_at) VALUES (?, ?, ?)",
        (hash_value, json.dumps(result), datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()