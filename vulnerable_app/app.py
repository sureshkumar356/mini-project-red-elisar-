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

# HTML template — light professional ecommerce theme
BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnShop — Deliberately Vulnerable App</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<style>
/* ── Reset & Base ─────────────────────────────────────── */
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --bg:#F2EDF8;--surface:#FFFFFF;--card:#FFFFFF;--border:#DDD2E8;
  --red:#7A264F;--red2:#662041;--green:#10B981;--yellow:#8B5E74;
  --blue:#B65B84;--purple:#334155;--cyan:#0EA5E9;
  --text:#2E2A43;--muted:#655D79;--font:Inter,system-ui,sans-serif;
}}
body{{background:linear-gradient(180deg,#F7F4FB 0%,var(--bg) 100%);color:var(--text);font-family:var(--font);min-height:100vh;font-size:15px;line-height:1.6}}

/* ── Hero ─────────────────────────────────────────────── */
.hero{{
  background:linear-gradient(120deg,#FFFFFF 0%,#F2EAF8 100%);
  border:1px solid var(--border);border-radius:16px;
  padding:3rem 2.5rem;margin-bottom:2rem;position:relative;overflow:hidden;
  box-shadow:0 8px 20px rgba(15,23,42,.06);
}}
.hero::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 70% 50%,rgba(122,38,79,.08),transparent 60%);
  pointer-events:none;
}}
.hero-tag{{
  display:inline-block;background:#F6ECF2;
  border:1px solid #D8B5C9;color:var(--red);
  padding:4px 14px;border-radius:20px;font-size:.72rem;
  font-weight:700;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:1.2rem;
}}
.hero h1{{font-size:2.2rem;font-weight:800;line-height:1.2;margin-bottom:.75rem}}
.hero h1 span{{color:var(--red)}}
.hero p{{color:var(--muted);font-size:1rem;max-width:560px;line-height:1.7}}
.hero-actions{{display:flex;gap:1rem;margin-top:1.75rem;flex-wrap:wrap}}
.hero-btn{{
  padding:.65rem 1.6rem;border-radius:8px;font-weight:600;font-size:.875rem;
  text-decoration:none;transition:all .2s;letter-spacing:.3px;
}}
.hero-btn-primary{{
  background:var(--blue);color:#fff;
  border:none;
}}
.hero-btn-primary:hover{{transform:translateY(-1px);box-shadow:0 4px 18px rgba(122,38,79,.28)}}
.hero-btn-secondary{{
  background:#fff;color:var(--text);border:1px solid var(--border);
}}
.hero-btn-secondary:hover{{border-color:#CBD5E1;background:#F8FAFC}}

/* ── Feature grid ──────────────────────────────────────── */
.feature-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}}
.feature-card{{
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:1.25rem;transition:border-color .2s,transform .2s;
  box-shadow:0 1px 2px rgba(15,23,42,.05);
}}
.feature-card:hover{{border-color:#D8B5C9;transform:translateY(-2px)}}
.feature-card .fc-label{{
  font-size:.68rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  color:var(--blue);margin-bottom:.5rem;
}}
.feature-card h3{{font-size:.95rem;font-weight:600;margin-bottom:.4rem}}
.feature-card p{{font-size:.78rem;color:var(--muted);line-height:1.5}}

/* ── Header / Nav ─────────────────────────────────────── */
header{{
  background:var(--red2);
  border-bottom:1px solid #5B1D3B;
  padding:0 2rem;
  display:flex;align-items:center;justify-content:space-between;
  height:60px;
  position:sticky;top:0;z-index:100;
}}
.logo{{display:flex;align-items:center;gap:10px;text-decoration:none}}
.logo-icon{{
  width:34px;height:34px;
  background:var(--blue);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:.7rem;font-weight:800;color:#fff;letter-spacing:.5px;box-shadow:0 4px 12px rgba(122,38,79,.28);
}}
.logo-text{{font-size:1.1rem;font-weight:700;color:#FDF7FB}}
.logo-text span{{color:#F4CFE1}}
.logo-sub{{font-size:.65rem;color:#E8D0DE;letter-spacing:1.5px;text-transform:uppercase}}
nav{{display:flex;gap:4px;align-items:center}}
nav a{{
  color:#F5E8EF;text-decoration:none;padding:6px 14px;border-radius:6px;
  font-size:.85rem;font-weight:500;transition:all .18s;
}}
nav a:hover{{background:rgba(255,255,255,.14);color:#FFFFFF}}
nav a.danger{{color:#FFFFFF;border:1px solid #C68DAA}}
nav a.danger:hover{{background:rgba(255,255,255,.18);border-color:#E2B8CC}}

/* ── Layout ───────────────────────────────────────────── */
main{{max-width:1100px;margin:2rem auto;padding:0 1.5rem}}

/* ── Vuln Badge ───────────────────────────────────────── */
.vuln-badge{{
  display:inline-flex;align-items:center;gap:6px;
  background:#F6ECF2;border:1px solid #D8B5C9;
  color:var(--red);padding:4px 12px;border-radius:20px;
  font-size:.72rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;
  margin-bottom:1rem;
}}

/* ── Cards ────────────────────────────────────────────── */
.card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;
  box-shadow:0 1px 2px rgba(15,23,42,.05);
}}
.card h2{{font-size:1.25rem;font-weight:700;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}}
.card h3{{font-size:1rem;font-weight:600;margin:1rem 0 .5rem;color:var(--muted)}}
.card p{{color:var(--muted);margin-bottom:.5rem}}
.card ul{{padding-left:1.2rem;color:var(--muted)}}
.card ul li{{margin-bottom:.35rem}}
.card ul li a{{color:var(--blue);text-decoration:none;font-weight:500}}
.card ul li a:hover{{text-decoration:underline}}

/* ── Forms ────────────────────────────────────────────── */
form{{display:flex;flex-direction:column;gap:.75rem;max-width:480px}}
label{{font-size:.8rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}}
input[type=text],input[type=password],input[type=search]{{
  background:#FFFFFF;border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:.6rem .9rem;font-family:var(--font);font-size:.9rem;
  transition:border-color .2s;outline:none;width:100%;
}}
input:focus{{border-color:#C98BA8;box-shadow:0 0 0 3px rgba(122,38,79,.14)}}
button[type=submit],.btn{{
  background:var(--blue);
  color:#fff;border:none;border-radius:8px;
  padding:.6rem 1.4rem;font-weight:600;font-size:.875rem;
  cursor:pointer;transition:all .2s;letter-spacing:.3px;
  display:inline-flex;align-items:center;gap:6px;width:fit-content;
}}
button[type=submit]:hover,.btn:hover{{
  transform:translateY(-1px);box-shadow:0 4px 18px rgba(122,38,79,.28);
}}
.hint-box{{
  background:#FFFBEB;border:1px solid #FDE68A;
  border-radius:8px;padding:.75rem 1rem;font-size:.82rem;color:var(--yellow);
  margin-top:.5rem;
}}
.hint-box code{{
  background:#FEF3C7;padding:1px 6px;border-radius:4px;
  font-family:'Courier New',monospace;font-size:.85em;
}}

/* ── Tables ───────────────────────────────────────────── */
table{{width:100%;border-collapse:collapse;font-size:.875rem;margin-top:.75rem}}
th{{
  background:var(--red);padding:.65rem 1rem;text-align:left;
  font-size:.75rem;text-transform:uppercase;letter-spacing:.5px;color:#FFFFFF;
  border-bottom:1px solid var(--border);font-weight:600;
}}
td{{
  padding:.6rem 1rem;border-bottom:1px solid #E7DCEF;
  color:var(--text);vertical-align:top;
}}
tr:last-child td{{border:none}}
tr:hover td{{background:#F8F2FA}}

/* ── Code / Pre ───────────────────────────────────────── */
pre{{
  background:#F8F2FA;border:1px solid var(--border);border-radius:10px;
  padding:1.25rem;font-family:'Courier New',monospace;font-size:.8rem;
  color:#1E293B;line-height:1.7;overflow-x:auto;
}}
code{{
  background:#F4EAF4;color:#5B1F3C;
  padding:2px 6px;border-radius:4px;font-family:'Courier New',monospace;font-size:.85em;
}}

/* ── Messages ─────────────────────────────────────────── */
.msg-ok{{
  background:#ECFDF5;border:1px solid #A7F3D0;
  color:var(--green);border-radius:8px;padding:.65rem 1rem;font-weight:500;font-size:.875rem;
}}
.msg-err{{
  background:#FEF2F2;border:1px solid #FECACA;
  color:#B91C1C;border-radius:8px;padding:.65rem 1rem;font-weight:500;font-size:.875rem;font-family:'Courier New',monospace;
}}

/* ── Home grid ────────────────────────────────────────── */
.route-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem;margin-top:1rem}}
.route-item{{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:1rem 1.2rem;transition:border-color .2s;
}}
.route-item:hover{{border-color:var(--red)}}
.route-item a{{color:var(--blue);font-weight:600;text-decoration:none;font-size:.9rem}}
.route-item a:hover{{text-decoration:underline}}
.route-item p{{font-size:.78rem;color:var(--muted);margin-top:4px}}
.vuln-tag{{
  display:inline-block;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;
  letter-spacing:.5px;text-transform:uppercase;margin-top:4px;
}}
.tag-sqli{{background:rgba(230,57,70,.15);color:var(--red2)}}
.tag-xss{{background:rgba(230,126,34,.15);color:#e67e22}}
.tag-auth{{background:rgba(155,89,182,.15);color:var(--purple)}}
.tag-info{{background:rgba(52,152,219,.15);color:var(--blue)}}
.tag-redirect{{background:rgba(26,188,156,.15);color:var(--cyan)}}

/* ── Footer ───────────────────────────────────────────── */
footer{{
  text-align:center;padding:2rem;color:var(--muted);font-size:.78rem;
  border-top:1px solid var(--border);margin-top:3rem;
}}
footer span{{color:var(--red)}}
</style>
</head>
<body>

<header>
  <a class="logo" href="/">
    <div class="logo-icon">VS</div>
    <div>
      <div class="logo-text">Vuln<span>Shop</span></div>
      <div class="logo-sub">Modern Demo Store</div>
    </div>
  </a>
  <nav>
    <a href="/products">Products</a>
    <a href="/search">Search</a>
    <a href="/greet">Greet</a>
    <a href="/account">Account</a>
    <a href="/cart">Cart</a>
    <a href="/admin" class="danger">Admin Panel</a>
  </nav>
</header>

<main>
  {content}
</main>

<footer>
  VulnShop &nbsp;|&nbsp; Built for <span>Red ELISAR</span> Security Testing
</footer>

</body>
</html>
"""

# Routes

@app.route("/")
def index():
    content = """
    <div class="hero">
      <div class="hero-tag">Featured Storefront</div>
      <h1>Simple and Modern <span>Shopping Experience</span></h1>
      <p>Discover curated products with a clean browsing flow, seamless search, and a lightweight checkout-ready interface for demo environments.</p>
      <div class="hero-actions">
        <a href="/products" class="hero-btn hero-btn-primary">Browse Products</a>
        <a href="/search" class="hero-btn hero-btn-secondary">Search</a>
        <a href="/account" class="hero-btn hero-btn-secondary">My Account</a>
      </div>
    </div>
    <div class="feature-grid">
      <div class="feature-card">
        <div class="fc-label">Catalogue</div>
        <h3>Products Grid</h3>
        <p>Browse category-ready product cards with clear pricing and purchase actions.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Account</div>
        <h3>Account Center</h3>
        <p>Access profile information, order history, and saved payment preferences.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Management</div>
        <h3>Admin Dashboard</h3>
        <p>Review system stats and a simple operations table in one place.</p>
      </div>
      <div class="feature-card">
        <div class="fc-label">Developer</div>
        <h3>Search Experience</h3>
        <p>Find products quickly using compact, responsive search controls.</p>
      </div>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/account")
def account():
    content = """
    <div class="card">
      <h2>Account Overview</h2>
      <p>Welcome back. Manage your profile, security settings, and purchase preferences.</p>
    </div>
    <div class="card">
      <table>
        <tr><th>Section</th><th>Status</th><th>Notes</th></tr>
        <tr><td>Profile</td><td>Complete</td><td>Basic details are up to date.</td></tr>
        <tr><td>Orders</td><td>3 recent</td><td>Latest order delivered successfully.</td></tr>
        <tr><td>Saved Cards</td><td>1 card</td><td>Primary payment method available.</td></tr>
      </table>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/cart")
def cart():
    content = """
    <div class="card">
      <h2>Cart</h2>
      <p>Review selected products before checkout.</p>
    </div>
    <div class="card">
      <table>
        <tr><th>Product</th><th>Qty</th><th>Price</th><th>Total</th></tr>
        <tr><td>Laptop</td><td>1</td><td>$999.99</td><td>$999.99</td></tr>
        <tr><td>Phone</td><td>1</td><td>$499.99</td><td>$499.99</td></tr>
      </table>
      <p style="margin-top:1rem"><b>Subtotal: $1499.98</b></p>
      <a class="btn" href="/login">Continue to Checkout</a>
    </div>
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
    <div class="card">
      <h2>Product Search</h2>
      <form method="GET" style="flex-direction:row;align-items:center;gap:.5rem;max-width:600px">
        <input name="q" value="{query}" placeholder="Search products..." type="text" style="flex:1">
        <button type="submit">Search</button>
      </form>
      <div class="hint-box" style="margin-top:1rem">
        Try: <code>Laptop</code> &nbsp;|&nbsp;
        <code>' OR '1'='1</code> &nbsp;|&nbsp;
        <code>' UNION SELECT id,username,password,email FROM users--</code>
      </div>
      {"<div class='msg-err' style='margin-top:.75rem'>" + error + "</div>" if error else ""}
    </div>
    <div class="card">
      <h3>Results</h3>
      <table>
        <tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>
        {"".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in results) if results else "<tr><td colspan=4 style='color:var(--muted);text-align:center;padding:1.5rem'>No results found.</td></tr>"}
      </table>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))



@app.route("/greet")
def greet():
    """VULNERABILITY 9: Reflected XSS — user input echoed without sanitization."""
    # VULNERABLE: name parameter echoed directly into HTML without escaping
    name = request.args.get("name", "Guest")
    content = f"""
    <div class="card">
      <h2>Greeting</h2>
      <form method="GET" style="flex-direction:row;align-items:center;gap:.5rem;max-width:480px">
        <input name="name" value="{name}" placeholder="Your name" type="text" style="flex:1">
        <button type="submit">Greet Me</button>
      </form>
      <div class="hint-box" style="margin-top:1rem">
        Try payload: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
      </div>
    </div>
    <div class="card">
      <h3 style="color:var(--text)">Hello, {name}! Welcome to VulnShop.</h3>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABILITY 10: Hardcoded credentials (admin/admin123)."""
    message = ""
    msg_cls = ""
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
                message = f"✅ Logged in as: <b>{username}</b> (ID={user[0]})"
                msg_cls = "msg-ok"
            else:
                message = "❌ Invalid credentials."
                msg_cls = "msg-err"
        except Exception as e:
            message = f"DB Error: {e}"
            msg_cls = "msg-err"

    content = f"""
    <div class="card">
      <h2>Sign In</h2>
      {f'<div class="{msg_cls}" style="margin-bottom:1rem">{message}</div>' if message else ""}
      <form method="POST">
        <label>Username</label>
        <input name="username" placeholder="Username" type="text">
        <label>Password</label>
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
      </form>
      <div class="hint-box" style="margin-top:1.25rem">
        Credentials: <code>admin</code> / <code>admin123</code> &nbsp;|&nbsp;
        SQLi bypass: <code>' OR '1'='1'--</code>
      </div>
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/admin")
def admin():
    """VULNERABILITY: Admin panel accessible without authentication."""
    content = """
    <div class="card">
      <h2>Admin Panel</h2>
      <p style="color:var(--muted)">System administration and configuration.</p>
    </div>
    <div class="card">
      <h3>System Information</h3>
      <table>
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>App Secret Key</td><td><code>secret123</code></td></tr>
        <tr><td>Database</td><td><code>vuln_app.db (SQLite)</code></td></tr>
        <tr><td>Server</td><td><code>Apache/2.2.8 (Ubuntu)</code></td></tr>
        <tr><td>PHP Version</td><td><code>7.2.1</code></td></tr>
        <tr><td>Debug Mode</td><td style="color:var(--red2)"><b>ON</b></td></tr>
        <tr><td>CORS</td><td style="color:var(--red2)">Wildcard (*)</td></tr>
      </table>
    </div>
    <div class="card">
      <h3>User Management</h3>
      <p><a href="/api/users" style="color:var(--blue)">View all users</a></p>
    </div>
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
    <div class="card">
      <h2>Backup File</h2>
      <p style="color:var(--muted)">Database backup configuration and credentials.</p>
    </div>
    <div class="card">
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
    </div>
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


@app.route("/api/products")
def api_products():
    """VULNERABILITY: Unauthenticated API endpoint returning internal product data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "status": "ok",
        "count": len(rows),
        "products": [
            {"id": r[0], "name": r[1], "price": r[2], "description": r[3]}
            for r in rows
        ]
    })


@app.route("/products")
def products():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM products")
    rows = c.fetchall()
    conn.close()
    content = """
    <div class="card">
      <h2>All Products</h2>
      <p style="color:var(--muted)">Browse our full product catalogue.</p>
    </div>
    <div class="feature-grid">
        """ + "".join(
            f"""
            <div class='feature-card'>
              <div style='height:120px;border-radius:10px;background:#F1F5F9;border:1px solid var(--border);margin-bottom:.8rem;display:flex;align-items:center;justify-content:center;color:var(--muted)'>Product Image</div>
              <h3>{r[1]}</h3>
              <p style='color:var(--muted)'>{r[3]}</p>
              <p style='margin-top:.5rem;font-weight:700;color:var(--green)'>${r[2]}</p>
              <button class='btn' style='margin-top:.6rem'>Add to Cart</button>
            </div>
            """
            for r in rows
        ) + """
    </div>
    """
    return render_template_string(BASE_HTML.format(content=content))


@app.route("/error_test")
def error_test():
    """VULNERABILITY: Deliberate unhandled error endpoint for stack-trace/debug exposure."""
    _ = 1 / 0
    return "OK"


@app.route("/config")
def config_dump():
    """VULNERABILITY: Public config disclosure."""
    return """{
  "app_name": "VulnShop",
  "environment": "development",
  "debug": true,
  "database": "sqlite:///vuln_app.db",
  "jwt_secret": "jwt_super_secret_key_123",
  "admin_user": "admin",
  "admin_pass": "admin123"
}""", 200, {"Content-Type": "application/json"}


@app.route("/.git")
def git_metadata():
    """VULNERABILITY: Simulated exposed .git metadata."""
    return """ref: refs/heads/main
commit=9fbc9f1d3aaf1aab9e1f0f3a66f3dc11b9f2a123
author=dev@vuln-shop.local
""", 200, {"Content-Type": "text/plain"}


@app.route("/db")
def db_info():
    """VULNERABILITY: Database diagnostics exposed publicly."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    users_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM products")
    products_count = c.fetchone()[0]
    conn.close()
    return jsonify({
        "db_path": DB_PATH,
        "users_count": users_count,
        "products_count": products_count,
        "note": "diagnostics endpoint left open"
    })


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
