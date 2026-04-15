# Interactive Web Scan

- Generated: 2026-04-15 16:44 UTC
- Target URL: http://127.0.0.1:5000
- Total vulnerabilities: 21

## MITRE Mapping Per Vulnerability

### 1. Exposed Sensitive Resource [CRITICAL]
- Detail: Sensitive path '/robots.txt' is publicly accessible (HTTP 200)
- Techniques:
  - [T1552] Unsecured Credentials
  - [T1552.001] Credentials In Files
  - [T1555.006] Cloud Secrets Management Stores

### 2. No HTTPS / Plain HTTP [CRITICAL]
- Detail: Site is served over HTTP — all traffic is unencrypted
- Techniques:
  - [T1599] Network Boundary Bridging
  - [T1090.003] Multi-hop Proxy
  - [T1557] Adversary-in-the-Middle

### 3. Missing Security Header [HIGH]
- Detail: HTTP header 'Content-Security-Policy' is not set — Mitigates XSS by restricting allowed content sources
- Techniques:
  - [T1059.007] JavaScript
  - [T1189] Drive-by Compromise
  - [T1220] XSL Script Processing

### 4. CORS Misconfiguration [HIGH]
- Detail: Access-Control-Allow-Origin is wildcard (*)
- Techniques:
  - [T1599] Network Boundary Bridging
  - [T1090.003] Multi-hop Proxy
  - [T1557] Adversary-in-the-Middle

### 5. Information Disclosure [MEDIUM]
- Detail: Header 'Server' exposes technology details: 'Werkzeug/3.1.6 Python/3.13.3, Apache/2.2.8 (Ubuntu)'
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1596.002] WHOIS
  - [T1590.005] IP Addresses

### 6. Exposed Sensitive Resource [CRITICAL]
- Detail: Path '/.env' returned HTTP 200 — Exposed .env file with credentials
- Techniques:
  - [T1552.001] Direct mapping from vulnerability type
  - [T1555.003] Credentials from Web Browsers
  - [T1552] Unsecured Credentials

### 7. Exposed Sensitive Resource [CRITICAL]
- Detail: Path '/backup' returned HTTP 200 — Exposed backup file/directory
- Techniques:
  - [T1552] Unsecured Credentials
  - [T1552.001] Credentials In Files
  - [T1555.006] Cloud Secrets Management Stores

### 8. Exposed Sensitive Resource [CRITICAL]
- Detail: Path '/api/users' returned HTTP 200 — Unauthenticated user data API
- Techniques:
  - [T1078.002] Domain Accounts
  - [T1078] Valid Accounts
  - [T1003.006] DCSync

### 9. SQL Injection [CRITICAL]
- Detail: SQLi payload '' UNION SELECT id,username,password,email FROM users--' on http://127.0.0.1:5000/search?q=... triggered SQL error pattern 'sql' in live response
- Techniques:
  - [T1203] Exploitation for Client Execution
  - [T1190] Exploit Public-Facing Application
  - [T1210] Exploitation of Remote Services

### 10. SQL Injection [CRITICAL]
- Detail: Login form bypassed using SQLi payload: '' OR '1'='1'--' — Classic tautology bypass. Response confirms successful login.
- Techniques:
  - [T1203] Exploitation for Client Execution
  - [T1190] Exploit Public-Facing Application
  - [T1210] Exploitation of Remote Services

### 11. Unauthenticated Admin Panel Access [CRITICAL]
- Detail: Admin path '/admin' returns HTTP 200 without any authentication credentials
- Techniques:
  - [T1078.002] Domain Accounts
  - [T1078] Valid Accounts
  - [T1003.006] DCSync

### 12. Unencrypted HTTP [CRITICAL]
- Detail: Application is served over plain HTTP — all traffic including credentials is transmitted in cleartext
- Techniques:
  - [T1599] Network Boundary Bridging
  - [T1090.003] Multi-hop Proxy
  - [T1557] Adversary-in-the-Middle

### 13. Missing Security Header [HIGH]
- Detail: HTTP response is missing the 'Strict-Transport-Security' header
- Techniques:
  - [T1059.007] JavaScript
  - [T1189] Drive-by Compromise
  - [T1220] XSL Script Processing

### 14. CORS Wildcard Misconfiguration [HIGH]
- Detail: Server allows cross-origin requests from ANY domain (*)
- Techniques:
  - [T1599] Network Boundary Bridging
  - [T1090.003] Multi-hop Proxy
  - [T1557] Adversary-in-the-Middle

### 15. Exposed Sensitive Resource [HIGH]
- Detail: Path '/admin' returned HTTP 200 — Unauthenticated admin panel access
- Techniques:
  - [T1078.002] Domain Accounts
  - [T1078] Valid Accounts
  - [T1003.006] DCSync

### 16. Reflected Cross-Site Scripting (XSS) [HIGH]
- Detail: XSS payload reflected unescaped on http://127.0.0.1:5000/greet?name=<payload>
- Techniques:
  - [T1059.007] JavaScript
  - [T1189] Drive-by Compromise
  - [T1220] XSL Script Processing

### 17. Error / Stack Trace Information Leakage [HIGH]
- Detail: Raw SQL query exposed in error message at http://127.0.0.1:5000/search?q=' AND 1=CONVERT(int,'error')--
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1596.002] WHOIS
  - [T1590.005] IP Addresses

### 18. Open Redirect [MEDIUM]
- Detail: Parameter 'url' on /redirect causes unvalidated redirect to external domain: http://evil-attacker.example.com
- Techniques:
  - [T1204] Direct mapping from vulnerability type
  - [T1204.001] Malicious Link
  - [T1566.002] Spearphishing Link

### 19. Insecure Cookie Configuration [MEDIUM]
- Detail: Missing Secure flag — cookie sent over HTTP
- Techniques:
  - [T1550.004] Web Session Cookie
  - [T1539] Steal Web Session Cookie
  - [T1185] Browser Session Hijacking

### 20. Exposed Sensitive Resource [INFO]
- Detail: Path '/robots.txt' returned HTTP 200 — robots.txt reveals hidden paths
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1596.002] WHOIS
  - [T1590.005] IP Addresses

### 21. Exposed Sensitive Resource [INFO]
- Detail: Path '/sitemap.xml' returned HTTP 200 — sitemap.xml reveals all endpoints
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1596.002] WHOIS
  - [T1590.005] IP Addresses

## Attack Chain

- Step 1: [T1592] Gather Victim Host Information (reconnaissance)
- Step 2: [T1203] Exploitation for Client Execution (execution)
- Step 3: [T1599] Network Boundary Bridging (defense-evasion)
- Step 4: [T1552] Unsecured Credentials (credential-access)
