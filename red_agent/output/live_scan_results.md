# Red ELISAR - Live Vulnerability Scan Report

## Summary

- Target URL: http://127.0.0.1:5000
- Scan Timestamp (UTC): 2026-04-07T09:58:54.840303+00:00
- Elapsed Seconds: 0.9
- Total Findings: 34
- Overall Risk: CRITICAL
- Scan Method: LIVE_ACTIVE_SCAN

## Severity Breakdown

| Severity | Count |
|---|---:|
| CRITICAL | 15 |
| HIGH | 7 |
| MEDIUM | 8 |
| LOW | 2 |
| INFO | 2 |

## Findings

### 1. Sensitive File / Path Disclosure [CRITICAL]

- Detail: Path '/.env' returned HTTP 200 — Exposed .env file with credentials
- CWE: CWE-312
- MITRE Hint: T1552.001
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/.env → 200 OK | Preview: SECRET_KEY=secret123 DATABASE_URL=sqlite:///vuln_app.db ADMIN_PASSWORD=admin123 DEBUG=True FLASK_ENV=development API_KEY...
- Recommendation: Remove or protect '/.env'. Ensure sensitive files are outside the web root and access-controlled.

### 2. Sensitive File / Path Disclosure [CRITICAL]

- Detail: Path '/backup' returned HTTP 200 — Exposed backup file/directory
- CWE: CWE-312
- MITRE Hint: T1552
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/backup → 200 OK | Preview: <!DOCTYPE html> <html> <head>     <title>VulnShop - Online Store</title> </head> <body> <div>     VulnShop   <a href="/"...
- Recommendation: Remove or protect '/backup'. Ensure sensitive files are outside the web root and access-controlled.

### 3. Sensitive File / Path Disclosure [CRITICAL]

- Detail: Path '/api/users' returned HTTP 200 — Unauthenticated user data API
- CWE: CWE-306
- MITRE Hint: T1078
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/api/users → 200 OK | Preview: {   "count": 3,   "status": "ok",   "users": [     {       "email": "admin@vuln-shop.local",       "id": 1,       "passw...
- Recommendation: Remove or protect '/api/users'. Ensure sensitive files are outside the web root and access-controlled.

### 4. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' OR '1'='1' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' OR '1'='1 → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 5. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' OR 1=1--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' OR 1=1-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 6. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' UNION SELECT NULL--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' UNION SELECT NULL-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 7. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' UNION SELECT NULL,NULL--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' UNION SELECT NULL,NULL-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 8. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' UNION SELECT id,username,password,email FROM users--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' UNION SELECT id,username,password,email FROM users-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 9. SQL Injection (UNION — Data Exfiltrated) [CRITICAL]

- Detail: UNION payload successfully retrieved user table data via http://127.0.0.1:5000/search?q
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: Live response contains user credentials extracted from DB. Payload: ' UNION SELECT id,username,password,email FROM users--
- Recommendation: Immediate remediation: parameterise all queries. Rotate all credentials exposed in this database.

### 10. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '1; DROP TABLE users--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=1; DROP TABLE users-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 11. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' AND SLEEP(0)--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' AND SLEEP(0)-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 12. SQL Injection (Error-Based) [CRITICAL]

- Detail: SQLi payload '' OR SUBSTR(username,1,1)='a'--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- CWE: CWE-89
- MITRE Hint: T1190
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' OR SUBSTR(username,1,1)='a'-- → HTTP 200 | Matched: sql
- Recommendation: Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.

### 13. Authentication Bypass via SQL Injection [CRITICAL]

- Detail: Login form bypassed using SQLi payload: '' OR '1'='1'--' — Classic tautology bypass. Response confirms successful login.
- CWE: CWE-287
- MITRE Hint: T1078
- Confirmed Live: True
- Evidence: POST /login username='' OR '1'='1'--' password='anything' → HTTP 200 | Response: Logged in as: <b>' OR '1'='1'--</b> (ID=1)</p>
    <form method="POST">
        
- Recommendation: Use parameterised queries for all authentication checks. Implement account lockout and rate limiting.

### 14. Unauthenticated Admin Panel Access [CRITICAL]

- Detail: Admin path '/admin' returns HTTP 200 without any authentication credentials
- CWE: CWE-284
- MITRE Hint: T1078
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/admin → HTTP 200 | Admin keywords confirmed in live response body
- Recommendation: Protect all admin routes with strong authentication and role-based access control.

### 15. Unencrypted HTTP (No TLS) [CRITICAL]

- Detail: Application is served over plain HTTP — all traffic including credentials is transmitted in cleartext
- CWE: CWE-319
- MITRE Hint: T1557
- Confirmed Live: True
- Evidence: Target URL scheme is 'http://' — confirmed from http://127.0.0.1:5000
- Recommendation: Deploy TLS (HTTPS) via a certificate authority (e.g. Let's Encrypt). Configure HSTS after enabling HTTPS.

### 16. Missing Security Header [HIGH]

- Detail: HTTP response is missing the 'Content-Security-Policy' header
- CWE: CWE-79
- MITRE Hint: T1059.007
- Confirmed Live: True
- Evidence: Header 'Content-Security-Policy' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'Content-Security-Policy' to all HTTP responses. Example config depends on your web server / framework.

### 17. Missing Security Header [HIGH]

- Detail: HTTP response is missing the 'Strict-Transport-Security' header
- CWE: CWE-311
- MITRE Hint: T1557
- Confirmed Live: True
- Evidence: Header 'Strict-Transport-Security' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'Strict-Transport-Security' to all HTTP responses. Example config depends on your web server / framework.

### 18. CORS Wildcard Misconfiguration [HIGH]

- Detail: Server allows cross-origin requests from ANY domain (*)
- CWE: CWE-942
- MITRE Hint: T1557
- Confirmed Live: True
- Evidence: Live response: Access-Control-Allow-Origin: *
- Recommendation: Replace '*' with specific trusted origins. Never combine wildcard CORS with cookies/credentials.

### 19. Sensitive File / Path Disclosure [HIGH]

- Detail: Path '/admin' returned HTTP 200 — Unauthenticated admin panel access
- CWE: CWE-284
- MITRE Hint: T1078
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/admin → 200 OK | Preview: <!DOCTYPE html> <html> <head>     <title>VulnShop - Online Store</title> </head> <body> <div>     VulnShop   <a href="/"...
- Recommendation: Remove or protect '/admin'. Ensure sensitive files are outside the web root and access-controlled.

### 20. Reflected Cross-Site Scripting (XSS) [HIGH]

- Detail: XSS payload reflected unescaped on http://127.0.0.1:5000/greet?name=<payload>
- CWE: CWE-79
- MITRE Hint: T1059.007
- Confirmed Live: True
- Evidence: Sent: <script>alert('XSS_1')</script> | Marker 'XSS_1' found verbatim in live HTTP response
- Recommendation: HTML-escape all user input before rendering. Use template engines with auto-escaping (e.g., Jinja2 with |e).

### 21. Reflected Cross-Site Scripting (XSS) [HIGH]

- Detail: XSS payload reflected unescaped on http://127.0.0.1:5000/search?q=<payload>
- CWE: CWE-79
- MITRE Hint: T1059.007
- Confirmed Live: True
- Evidence: Sent: <script>alert('XSS_1')</script> | Marker 'XSS_1' found verbatim in live HTTP response
- Recommendation: HTML-escape all user input before rendering. Use template engines with auto-escaping (e.g., Jinja2 with |e).

### 22. Error / Stack Trace Information Leakage [HIGH]

- Detail: Raw SQL query exposed in error message at http://127.0.0.1:5000/search?q=' AND 1=CONVERT(int,'error')--
- CWE: CWE-209
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/search?q=' AND 1=CONVERT(int,'error')-- → HTTP 200 | Pattern 'query was:' matched in live response
- Recommendation: Disable debug mode and custom error handlers. Return generic 500 pages in production. Never expose stack traces to end users.

### 23. Missing Security Header [MEDIUM]

- Detail: HTTP response is missing the 'X-Frame-Options' header
- CWE: CWE-1021
- MITRE Hint: T1185
- Confirmed Live: True
- Evidence: Header 'X-Frame-Options' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'X-Frame-Options' to all HTTP responses. Example config depends on your web server / framework.

### 24. Missing Security Header [MEDIUM]

- Detail: HTTP response is missing the 'X-Content-Type-Options' header
- CWE: CWE-430
- MITRE Hint: T1204
- Confirmed Live: True
- Evidence: Header 'X-Content-Type-Options' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'X-Content-Type-Options' to all HTTP responses. Example config depends on your web server / framework.

### 25. Information Disclosure (Banner) [MEDIUM]

- Detail: Header 'Server' reveals technology: 'Werkzeug/3.1.6 Python/3.13.3, Apache/2.2.8 (Ubuntu)'
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: Live response header → Server: Werkzeug/3.1.6 Python/3.13.3, Apache/2.2.8 (Ubuntu)
- Recommendation: Remove or generalize the 'Server' response header.

### 26. Information Disclosure (Banner) [MEDIUM]

- Detail: Header 'X-Powered-By' reveals technology: 'PHP/7.2.1'
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: Live response header → X-Powered-By: PHP/7.2.1
- Recommendation: Remove or generalize the 'X-Powered-By' response header.

### 27. Information Disclosure (Banner) [MEDIUM]

- Detail: Header 'X-App-Version' reveals technology: '1.0.0-dev'
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: Live response header → X-App-Version: 1.0.0-dev
- Recommendation: Remove or generalize the 'X-App-Version' response header.

### 28. Open Redirect [MEDIUM]

- Detail: Parameter 'url' on /redirect causes unvalidated redirect to external domain: http://evil-attacker.example.com
- CWE: CWE-601
- MITRE Hint: T1204
- Confirmed Live: True
- Evidence: GET /redirect?url=http://evil-attacker.example.com → HTTP 302 Location: http://evil-attacker.example.com
- Recommendation: Validate redirect destinations against a whitelist. Never redirect to user-supplied external URLs.

### 29. Insecure Cookie Configuration [MEDIUM]

- Detail: Missing Secure flag — cookie sent over HTTP
- CWE: CWE-614
- MITRE Hint: T1185
- Confirmed Live: True
- Evidence: Live Set-Cookie header: session=eyJ1c2VyIjoiYWRtaW4ifQ.adTVXw._ii6tGkZHtrX58e8N9WSUugKHAI; HttpOnly; Path=/
- Recommendation: Set cookies with: HttpOnly; Secure; SameSite=Strict (or Lax for SSO).

### 30. Insecure Cookie Configuration [MEDIUM]

- Detail: Missing SameSite flag — CSRF risk
- CWE: CWE-614
- MITRE Hint: T1185
- Confirmed Live: True
- Evidence: Live Set-Cookie header: session=eyJ1c2VyIjoiYWRtaW4ifQ.adTVXw._ii6tGkZHtrX58e8N9WSUugKHAI; HttpOnly; Path=/
- Recommendation: Set cookies with: HttpOnly; Secure; SameSite=Strict (or Lax for SSO).

### 31. Missing Security Header [LOW]

- Detail: HTTP response is missing the 'Referrer-Policy' header
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: Header 'Referrer-Policy' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'Referrer-Policy' to all HTTP responses. Example config depends on your web server / framework.

### 32. Missing Security Header [LOW]

- Detail: HTTP response is missing the 'Permissions-Policy' header
- CWE: CWE-693
- MITRE Hint: T1562
- Confirmed Live: True
- Evidence: Header 'Permissions-Policy' absent in live response from http://127.0.0.1:5000
- Recommendation: Add 'Permissions-Policy' to all HTTP responses. Example config depends on your web server / framework.

### 33. Sensitive File / Path Disclosure [INFO]

- Detail: Path '/robots.txt' returned HTTP 200 — robots.txt reveals hidden paths
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/robots.txt → 200 OK | Preview: User-agent: * Disallow: /admin Disallow: /backup Disallow: /.env Disallow: /api/users Disallow: /config Disallow: /db...
- Recommendation: Remove or protect '/robots.txt'. Ensure sensitive files are outside the web root and access-controlled.

### 34. Sensitive File / Path Disclosure [INFO]

- Detail: Path '/sitemap.xml' returned HTTP 200 — sitemap.xml reveals all endpoints
- CWE: CWE-200
- MITRE Hint: T1592
- Confirmed Live: True
- Evidence: GET http://127.0.0.1:5000/sitemap.xml → 200 OK | Preview: <?xml version="1.0" encoding="UTF-8"?> <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">   <url><loc>http://1...
- Recommendation: Remove or protect '/sitemap.xml'. Ensure sensitive files are outside the web root and access-controlled.
