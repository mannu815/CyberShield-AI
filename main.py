from __future__ import annotations

import ipaddress
import json
import os
import socket
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("CYBERSHIELD_DB", str(BASE_DIR.parent / "cybershield.db")))
app = FastAPI(title="CyberShield AI", version="0.1.0", description="Defensive, passive website security assessment MVP")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect_db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status_code INTEGER,
            duration_ms INTEGER,
            results_json TEXT NOT NULL
        )""")


init_db()


def validate_public_target(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Enter a website URL, for example https://example.com")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid URL. Usernames and passwords in URLs are not allowed.")
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        raise ValueError("For this MVP, only common web ports 80, 443, 8080, and 8443 are allowed.")
    host = parsed.hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".internal", ".test")):
        raise ValueError("Local/internal hostnames are blocked. Use a public test domain or a dedicated lab setup.")
    try:
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The hostname could not be resolved.")
    ips = {ipaddress.ip_address(item[4][0]) for item in addresses}
    if not ips:
        raise ValueError("No IP addresses found for this hostname.")
    for ip in ips:
        if not ip.is_global:
            raise ValueError("Private, loopback, link-local, and non-public IP targets are blocked in this MVP.")
    return raw_url


def finding(title, severity, status, evidence, recommendation, category):
    return {
        "title": title, "severity": severity, "status": status,
        "evidence": evidence, "recommendation": recommendation, "category": category
    }


def passive_scan(target: str) -> dict:
    """Run low-impact passive/configuration checks only. No exploitation or crawling."""
    parsed = urlparse(target)
    headers_out = {}
    status_code = None
    final_url = target
    notes = []
    started = time.monotonic()
    findings = []

    # Redirects are followed manually and each destination is revalidated.
    current = target
    response = None
    for _ in range(4):
        current = validate_public_target(current)
        try:
            with httpx.Client(follow_redirects=False, timeout=8.0, verify=True, headers={"User-Agent": "CyberShieldAI/0.1 (passive security assessment)"}) as client:
                response = client.get(current)
        except (httpx.HTTPError, ValueError) as exc:
            raise ValueError(f"Could not safely fetch target: {type(exc).__name__}")
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
            next_url = urljoin(current, response.headers["location"])
            current = validate_public_target(next_url)
            continue
        break
    else:
        raise ValueError("Too many redirects; scan stopped.")

    if response is None:
        raise ValueError("No HTTP response was received.")
    status_code = response.status_code
    final_url = str(response.url)
    headers_out = {k.lower(): v for k, v in response.headers.items()}
    is_https = urlparse(final_url).scheme == "https"

    if not is_https:
        findings.append(finding("HTTPS not used on final page", "High", "Observed", final_url,
            "Enable HTTPS and redirect HTTP requests to HTTPS. Confirm the certificate is valid.", "Transport security"))
    else:
        findings.append(finding("HTTPS is enabled", "Informational", "Observed", "Final URL uses HTTPS.",
            "Keep TLS configuration updated and monitor certificate expiry.", "Transport security"))

    header_checks = [
        ("strict-transport-security", "HSTS header missing", "Medium", "For HTTPS sites, configure Strict-Transport-Security after confirming all relevant subdomains support HTTPS."),
        ("content-security-policy", "Content-Security-Policy header missing", "Medium", "Define a suitable Content-Security-Policy and test it before enforcing broadly."),
        ("x-content-type-options", "X-Content-Type-Options header missing", "Low", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy header missing", "Low", "Set a privacy-appropriate Referrer-Policy, such as strict-origin-when-cross-origin."),
        ("permissions-policy", "Permissions-Policy header missing", "Informational", "Restrict browser features that the site does not need."),
        ("x-frame-options", "Frame embedding protection not explicitly set", "Low", "Use CSP frame-ancestors; X-Frame-Options may be retained for compatibility."),
    ]
    for header, title, severity, recommendation in header_checks:
        if header not in headers_out:
            findings.append(finding(title, severity, "Potential weakness", f"Response header '{header}' was not present.", recommendation, "HTTP headers"))
        else:
            findings.append(finding(f"{header} header present", "Informational", "Observed", f"{header}: {headers_out[header][:300]}", "Review the value for your application and deployment requirements.", "HTTP headers"))

    cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    if not cookie_headers:
        findings.append(finding("No Set-Cookie header observed on landing response", "Informational", "Observed", "The landing response did not set cookies; other paths may behave differently.", "Review authentication and session cookies on relevant application paths.", "Cookies"))
    else:
        for index, cookie in enumerate(cookie_headers[:20], start=1):
            lower = cookie.lower()
            missing = []
            if "secure" not in lower: missing.append("Secure")
            if "httponly" not in lower: missing.append("HttpOnly")
            if "samesite" not in lower: missing.append("SameSite")
            if missing:
                findings.append(finding(f"Cookie {index} missing security attributes", "Medium", "Potential weakness", f"Set-Cookie attributes missing or not detected: {', '.join(missing)}. Cookie value redacted.", "Set Secure for HTTPS cookies, HttpOnly when JavaScript access is unnecessary, and an appropriate SameSite value. Verify each cookie's purpose.", "Cookies"))
            else:
                findings.append(finding(f"Cookie {index} has common security attributes", "Informational", "Observed", "Secure, HttpOnly, and SameSite attributes were detected. Cookie value redacted.", "Confirm settings are appropriate for the cookie's role.", "Cookies"))

    # Check security.txt at the root only, safely and without crawling.
    origin = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
    try:
        security_txt_url = origin + "/.well-known/security.txt"
        validate_public_target(security_txt_url)
        with httpx.Client(follow_redirects=False, timeout=5.0, verify=True, headers={"User-Agent": "CyberShieldAI/0.1 (passive security assessment)"}) as client:
            sec_resp = client.get(security_txt_url)
        if sec_resp.status_code == 200:
            findings.append(finding("security.txt is publicly available", "Informational", "Observed", "/.well-known/security.txt returned HTTP 200.", "Keep security contact and disclosure policy details current.", "Disclosure"))
        else:
            findings.append(finding("security.txt not found at standard location", "Informational", "Not detected", f"Standard path returned HTTP {sec_resp.status_code}.", "Consider publishing a security.txt contact and disclosure policy.", "Disclosure"))
    except Exception:
        findings.append(finding("security.txt check inconclusive", "Informational", "Inconclusive", "The standard path could not be checked safely.", "Review manually if needed.", "Disclosure"))

    duration_ms = int((time.monotonic() - started) * 1000)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("Critical", "High", "Medium", "Low", "Informational")}
    return {
        "target": target, "final_url": final_url, "status_code": status_code,
        "scanned_at": datetime.now(timezone.utc).isoformat(), "duration_ms": duration_ms,
        "mode": "Passive checks only", "counts": counts, "findings": findings,
        "limitations": [
            "This scan checks a single landing page and a standard security.txt path; it does not crawl the site.",
            "Missing headers or cookie attributes are indicators, not proof that the site is exploitable.",
            "No exploit payloads, login attempts, data extraction, or destructive tests are performed.",
            "A clean result does not mean a website is secure. Authentication, authorization, business logic, APIs, source code, and infrastructure need additional authorized testing."
        ]
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with connect_db() as con:
        rows = con.execute("SELECT id, target, created_at, status_code, duration_ms, results_json FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    history = []
    for row in rows:
        data = json.loads(row["results_json"])
        history.append({"id": row["id"], "target": row["target"], "created_at": row["created_at"], "status_code": row["status_code"], "duration_ms": row["duration_ms"], "counts": data.get("counts", {})})
    return templates.TemplateResponse(request=request, name="index.html", context={"history": history})


@app.post("/api/scans")
def create_scan(target: str = Form(...), authorized: str | None = Form(None)):
    if authorized != "yes":
        raise HTTPException(status_code=400, detail="Confirm that you own the target or have explicit written permission to test it.")
    try:
        safe_target = validate_public_target(target)
        results = passive_scan(safe_target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    created_at = datetime.now(timezone.utc).isoformat()
    with connect_db() as con:
        cur = con.execute("INSERT INTO scans (target, created_at, status_code, duration_ms, results_json) VALUES (?, ?, ?, ?, ?)",
            (safe_target, created_at, results["status_code"], results["duration_ms"], json.dumps(results)))
        scan_id = cur.lastrowid
    return {"id": scan_id, **results}


@app.get("/api/scans")
def list_scans():
    with connect_db() as con:
        rows = con.execute("SELECT id, target, created_at, status_code, duration_ms, results_json FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return [{"id": r["id"], "target": r["target"], "created_at": r["created_at"], "status_code": r["status_code"], "duration_ms": r["duration_ms"], "results": json.loads(r["results_json"])} for r in rows]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    with connect_db() as con:
        row = con.execute("SELECT results_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(json.loads(row["results_json"]))


@app.get("/health")
def health():
    return {"status": "ok", "product": "CyberShield AI", "version": "0.1.0", "mode": "passive MVP"}
