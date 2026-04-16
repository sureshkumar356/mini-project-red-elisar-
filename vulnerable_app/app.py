"""
VULNERABLE TEST TARGET - For Red ELISAR demo only.
THIS APP IS INTENTIONALLY INSECURE - DO NOT DEPLOY PUBLICLY.

Run: python app.py
Access: http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string, redirect, jsonify, session
import sqlite3

app = Flask(__name__)

# VULNERABILITY 15: Weak, hardcoded secret key
app.secret_key = "secret123"

# Database setup
DB_PATH = "vuln_app.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    # Seed data
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM products")
    c.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin",   "admin123",      "admin@vuln-shop.local"),
        (2, "alice",   "password",      "alice@vuln-shop.local"),
        (3, "bob",     "bob123",        "bob@vuln-shop.local"),
    ])
    c.executemany("INSERT INTO products VALUES (?,?,?,?)", [
        (1, "Laptop",  999.99,  "High performance laptop"),
        (2, "Phone",   499.99,  "Latest smartphone"),
        (3, "Tablet",  299.99,  "Compact tablet"),
    ])
    conn.commit()
    conn.close()

# Middleware: add insecure headers
@app.after_request
def add_insecure_headers(response):
    # VULNERABILITY 6: Expose technology stack in headers
    response.headers["X-Powered-By"] = "PHP/7.2.1"        # fake but realistic
    response.headers["Server"]       = "Apache/2.2.8 (Ubuntu)"  # old version
    response.headers["X-App-Version"] = "1.0.0-dev"

    # VULNERABILITY 14: CORS wildcard
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

    # NOT SET (intentionally missing):
    # Content-Security-Policy
    # Strict-Transport-Security
    # X-Frame-Options
    # X-Content-Type-Options
    # Referrer-Policy
    # Permissions-Policy

    return response

# HTML template
BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>VulnShop - Online Store</title>
</head>
<body>
<div>
    VulnShop
  <a href="/">Home</a>
  <a href="/search">Search</a>
  <a href="/greet">Greet</a>
  <a href="/login">Login</a>
  <a href="/admin">Admin</a>
  <a href="/products">Products</a>
  <a href="/api/users">API</a>
</div>
<div>
  {content}
</div>
</body>
</html>
"""

# Routes

@app.route("/")
def index():
    content = """
    <h1>Welcome to VulnShop!</h1>
    <p>This is a deliberately vulnerable application for security testing.</p>
    <p><b>DO NOT</b> deploy this on a public server.</p>
    <p>This demo shop has many security vulnerabilities built in for educational purposes.</p>
    <h3>Available Pages:</h3>
    <ul>
        <li><a href="/search">/search</a> — Product search (SQL Injection vulnerable)</li>
        <li><a href="/greet?name=World">/greet</a> — Greeting page (Reflected XSS vulnerable)</li>
        <li><a href="/login">/login</a> — Login page (weak credentials)</li>
        <li><a href="/admin">/admin</a> — Admin panel (exposed)</li>
        <li><a href="/redirect?url=http://example.com">/redirect</a> — Open redirect</li>
        <li><a href="/backup">/backup</a> — Exposed backup file</li>
        <li><a href="/.env">/.env</a> — Exposed environment file</li>
        <li><a href="/api/users">/api/users</a> — Unauthenticated user data API</li>
        <li><a href="/error_test">/error_test</a> — Error with stack trace</li>
    </ul>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/search")
def search():
    """VULNERABILITY 8: SQL Injection — user input goes directly into SQL query."""
    query   = request.args.get("q", "")
    results = []
    error   = None

    if query:
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            # VULNERABLE: Direct string interpolation — DO NOT DO THIS IN REAL CODE
            sql = f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'"
            c.execute(sql)
            results = c.fetchall()
            conn.close()
        except Exception as e:
            # VULNERABILITY 13: Expose error details including SQL query
            error = f"Database error: {str(e)} | Query was: {sql}"

    content = f"""
    <h2>Product Search (SQLi Vulnerable)</h2>
    <form method="GET">
        <input name="q" value="{query}" placeholder="Search products..." size="40">
        <button type="submit">Search</button>
    </form>
    <p>Try: <code>Laptop</code>, or for SQLi: <code>' OR '1'='1</code>,
       or to dump users: <code>' UNION SELECT id,username,password,email FROM users--</code></p>
    {"<p>" + error + "</p>" if error else ""}
    <table>
        <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
        {"".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in results) if results else "<tr><td colspan=4>No results</td></tr>"}
    </table>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/greet")
def greet():
    """VULNERABILITY 9: Reflected XSS — user input echoed without sanitization."""
    # VULNERABLE: name parameter echoed directly into HTML without escaping
    name = request.args.get("name", "Guest")
    content = f"""
    <h2>Greeting Page (XSS Vulnerable)</h2>
    <form method="GET">
        <input name="name" value="{name}" placeholder="Your name" size="30">
        <button type="submit">Greet Me</button>
    </form>
    <p>Try entering: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    <hr>
    <h3>Hello, {name}! Welcome to VulnShop.</h3>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABILITY 10: Hardcoded credentials (admin/admin123)."""
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Also SQL injectable version
        try:
            conn = sqlite3.connect(DB_PATH)
            c    = conn.cursor()
            # VULNERABLE: hardcoded + SQL injectable
            sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            c.execute(sql)
            user = c.fetchone()
            conn.close()
            if user:
                session["user"] = username
                message = f"<p>Logged in as: <b>{username}</b> (ID={user[0]})</p>"
            else:
                message = "<p>Invalid credentials</p>"
        except Exception as e:
            message = f"<p>DB Error: {e}</p>"

    content = f"""
    <h2>Login (SQLi + Weak Creds)</h2>
    {message}
    <form method="POST">
        <input name="username" placeholder="Username" size="25"><br><br>
        <input name="password" type="password" placeholder="Password" size="25"><br><br>
        <button type="submit">Login</button>
    </form>
    <p>Hint: Try <code>admin</code> / <code>admin123</code> or SQLi: <code>' OR '1'='1'--</code></p>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/admin")
def admin():
    """VULNERABILITY: Admin panel accessible without authentication."""
    content = """
    <h2>Admin Panel (No Auth Required)</h2>
    <p><b>This admin panel is accessible without any authentication.</b></p>
    <h3>System Information:</h3>
    <table>
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>App Secret Key</td><td>secret123</td></tr>
        <tr><td>Database</td><td>vuln_app.db (SQLite)</td></tr>
        <tr><td>Server</td><td>Apache/2.2.8 (Ubuntu)</td></tr>
        <tr><td>PHP Version</td><td>7.2.1</td></tr>
        <tr><td>Debug Mode</td><td>ON</td></tr>
    </table>
    <h3>User Management:</h3>
    <p><a href="/api/users">View all users (unauthenticated API)</a></p>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/redirect")
def open_redirect():
    """VULNERABILITY 11: Open Redirect — no validation on destination URL."""
    url = request.args.get("url", "/")
    # VULNERABLE: No validation — can redirect to any external site
    return redirect(url)


@app.route("/backup")
def backup():
    """VULNERABILITY 12: Exposed backup/sensitive file."""
    content = """
    <h2>Exposed Backup File (Info Disclosure)</h2>
    <pre>
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
    </pre>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/.env")
def env_file():
    """VULNERABILITY 12: Exposed .env / environment configuration."""
    return """SECRET_KEY=secret123
DATABASE_URL=sqlite:///vuln_app.db
ADMIN_PASSWORD=admin123
DEBUG=True
FLASK_ENV=development
API_KEY=sk-dev-1234567890abcdef
JWT_SECRET=jwt_super_secret_key_123
""", 200, {"Content-Type": "text/plain"}


@app.route("/api/users")
def api_users():
    """VULNERABILITY: Unauthenticated API exposing all user data."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "status": "ok",
        "count":  len(rows),
        "users":  [{"id": r[0], "username": r[1], "password": r[2], "email": r[3]} for r in rows]
    })


@app.route("/products")
def products():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM products")
    rows = c.fetchall()
    conn.close()
    content = """
    <h2>All Products</h2>
    <table>
        <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
        """ + "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>${r[2]}</td><td>{r[3]}</td></tr>" for r in rows) + """
    </table>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/error_test")
def error_test():
    """Return a controlled error response without crashing the app."""
    try:
        _ = 1 / 0
        return "OK"
    except ZeroDivisionError:
        return jsonify({
            "status": "error",
            "message": "Internal test error was handled safely."
        }), 500


@app.route("/robots.txt")
def robots():
    """Expose sensitive paths in robots.txt."""
    return """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /.env
Disallow: /api/users
Disallow: /config
Disallow: /db
""", 200, {"Content-Type": "text/plain"}


@app.route("/sitemap.xml")
def sitemap():
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:5000/</loc></url>
  <url><loc>http://127.0.0.1:5000/search</loc></url>
  <url><loc>http://127.0.0.1:5000/admin</loc></url>
  <url><loc>http://127.0.0.1:5000/api/users</loc></url>
</urlset>""", 200, {"Content-Type": "application/xml"}


# Main
if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  VulnShop — Deliberately Vulnerable Web App")
    print("  For Red ELISAR Security Testing ONLY")
    print("  Running at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    # VULNERABILITY 7: Debug mode ON — allows remote code execution via debugger
    app.run(debug=True, host="127.0.0.1", port=5000)
