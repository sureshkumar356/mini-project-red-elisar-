import os
import subprocess
import glob



scenarios = [
    {
        "name": "SQL injection attack against vulnerable search and login surfaces to extract user records",
        "url": "http://127.0.0.1:5000",
        "length": 8
    },
    {
        "name": "Cross-Site Request Forgery (CSRF) attack exploiting missing tokens and SameSite cookie flags to hijack user sessions",
        "url": "http://127.0.0.1:5000",
        "length": 8
    },
    {
        "name": "Unauthenticated attacker discovers sensitive backup files, environment variables, and admin API endpoints",
        "url": "http://127.0.0.1:5000",
        "length": 8
    }
]

for s in scenarios:
    print(f"Running scenario: {s['name']}...")
    cmd = [
        ".venv\\Scripts\\python.exe", "run.py",
        "--scenario", s['name'],
        "--target-env", "VulnShop Flask web app with SQLite backend",
        "--target-url", s['url'],
        "--chain-length", str(s['length'])
    ]
    subprocess.run(cmd, cwd="c:\\mini project", check=False)
    print("Complete.\n")

print("Done running all scenarios.")
