# Interactive Web Scan

- Generated: 2026-04-29 17:58 UTC
- Target URL: http://127.0.0.1:5000
- Total vulnerabilities: 24

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
  - [T1189] Drive-by Compromise
  - [T1059.007] JavaScript
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
  - [T1592.004] Client Configurations
  - [T1592.003] Firmware

### 6. Exposed Sensitive Resource [CRITICAL]
- Detail: Path '/.env' returned HTTP 200 — Exposed .env file with credentials
- Techniques:
  - [T1552.001] Credentials In Files
  - [T1190] Exploit Public-Facing Application
  - [T1548.004] Elevated Execution with Prompt

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
  - [T1190] Exploit Public-Facing Application
  - [T1210] Exploitation of Remote Services
  - [T1189] Drive-by Compromise

### 10. SQL Injection [CRITICAL]
- Detail: Login form bypassed using SQLi payload: '' OR '1'='1'--' — Classic tautology bypass. Response confirms successful login.
- Techniques:
  - [T1190] Exploit Public-Facing Application
  - [T1210] Exploitation of Remote Services
  - [T1189] Drive-by Compromise

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
  - [T1189] Drive-by Compromise
  - [T1059.007] JavaScript
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

### 16. Exposed Sensitive Resource [HIGH]
- Detail: Path '/config' returned HTTP 200 — Config directory accessible
- Techniques:
  - [T1552] Unsecured Credentials
  - [T1552.001] Credentials In Files
  - [T1555.006] Cloud Secrets Management Stores

### 17. Reflected Cross-Site Scripting (XSS) [HIGH]
- Detail: XSS payload reflected unescaped on http://127.0.0.1:5000/greet?name=<payload>
- Techniques:
  - [T1189] Drive-by Compromise
  - [T1059.007] JavaScript
  - [T1220] XSL Script Processing

### 18. Error / Stack Trace Information Leakage [HIGH]
- Detail: Raw SQL query exposed in error message at http://127.0.0.1:5000/search?q=' AND 1=CONVERT(int,'error')--
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1592.004] Client Configurations
  - [T1592.003] Firmware

### 19. Open Redirect [MEDIUM]
- Detail: Parameter 'url' on /redirect causes unvalidated redirect to external domain: http://evil-attacker.example.com
- Techniques:
  - [T1204.001] Malicious Link
  - [T1204] User Execution
  - [T1566.002] Spearphishing Link

### 20. Insecure Cookie Configuration [MEDIUM]
- Detail: Missing Secure flag — cookie sent over HTTP
- Techniques:
  - [T1185] Browser Session Hijacking
  - [T1550.004] Web Session Cookie
  - [T1539] Steal Web Session Cookie

### 21. Exposed Sensitive Resource [INFO]
- Detail: Path '/robots.txt' returned HTTP 200 — robots.txt reveals hidden paths
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1592.004] Client Configurations
  - [T1592.003] Firmware

### 22. Exposed Sensitive Resource [INFO]
- Detail: Path '/sitemap.xml' returned HTTP 200 — sitemap.xml reveals all endpoints
- Techniques:
  - [T1592] Gather Victim Host Information
  - [T1592.004] Client Configurations
  - [T1592.003] Firmware

### 23. Reflected Cross-Site Scripting (XSS) [HIGH]
- Detail: Form parameter 'q' at http://127.0.0.1:5000/search reflects unescaped input.
- Techniques:
  - [T1189] Drive-by Compromise
  - [T1059.007] JavaScript
  - [T1220] XSL Script Processing

### 24. Reflected Cross-Site Scripting (XSS) [HIGH]
- Detail: Form parameter 'name' at http://127.0.0.1:5000/greet reflects unescaped input.
- Techniques:
  - [T1189] Drive-by Compromise
  - [T1059.007] JavaScript
  - [T1220] XSL Script Processing

## Attack Chain

- Step 1: [T1592] Gather Victim Host Information (reconnaissance)
- Step 2: [T1608.005] Link Target (resource-development)
- Step 3: [T1566.002] Spearphishing Link (initial-access)
- Step 4: [T1204.001] Malicious Link (execution)
- Step 5: [T1176.001] Browser Extensions (persistence)
- Step 6: [T1548.004] Elevated Execution with Prompt (privilege-escalation)
- Step 7: [T1599] Network Boundary Bridging (defense-evasion)
- Step 8: [T1552.001] Credentials In Files (credential-access)
- Step 9: [T1016.001] Internet Connection Discovery (discovery)
- Step 10: [T1210] Exploitation of Remote Services (lateral-movement)
- Step 11: [T1185] Browser Session Hijacking (collection)
- Step 12: [T1048.003] Exfiltration Over Unencrypted Non-C2 Protocol (exfiltration)
- Step 13: [T1499.003] Application Exhaustion Flood (impact)
