"""Dashboard support modules for the dnstwist Streamlit dashboard.

The original dnstwist engine (dnstwist.py) is never imported or modified here;
it is only executed as a subprocess (see scanner.py).
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DNSTWIST_PY = ROOT / "dnstwist.py"
HISTORY_DIR = ROOT / "scan_history"
RESULTS_DIR = HISTORY_DIR / "results"
REPORTS_DIR = ROOT / "reports"
ASSETS_DIR = ROOT / "dashboard_assets"
