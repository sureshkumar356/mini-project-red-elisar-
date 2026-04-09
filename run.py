"""
Red ELISAR — Root Launcher
============================
Entry point for the Red ELISAR package located in red_agent/.

Usage (from c:\\mini project\\):
    python run.py --scenario "APT phishing campaign"
    python run.py --index-only
    python run.py --predefined apt_phishing_to_exfil
    python run.py --batch
    python run.py --health
    python run.py --interactive
    python run.py --quick          (experiment: 5 scenarios, 1 run)
    python run.py --full           (experiment: 50 scenarios, 5 runs)
    python run.py --demo-plots     (plots with synthetic data)
    python run.py --diagram        (generate flow diagram only)
"""

import sys
import os
from pathlib import Path

# ── Add red_agent to Python path ──────────────────────────────────────────
AGENT_DIR = Path(__file__).parent / "red_agent"
sys.path.insert(0, str(AGENT_DIR))
os.chdir(AGENT_DIR)          # make relative paths inside modules resolve correctly

# ── Dispatch based on args ────────────────────────────────────────────────
EXPERIMENT_FLAGS = {"--full", "--quick", "--demo-plots", "--plots-only"}
DIAGRAM_FLAG     = "--diagram"

args = sys.argv[1:]

if DIAGRAM_FLAG in args:
    from diagram_generator import generate_diagram
    path = generate_diagram(quiet=False)
    print(f"Open: code \"{path}\"")

elif any(f in args for f in EXPERIMENT_FLAGS):
    # Remove our custom flag before delegating
    sys.argv = [str(AGENT_DIR / "run_experiment.py")] + args
    import run_experiment
    run_experiment.main()

else:
    # Default: delegate to main.py (scenario generation)
    sys.argv = [str(AGENT_DIR / "main.py")] + args
    import main
    main.main()
