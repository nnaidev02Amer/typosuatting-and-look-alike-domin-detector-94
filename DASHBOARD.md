# Typosquatting & Lookalike Domain Detection Dashboard

A local Streamlit dashboard around the unmodified [dnstwist](https://github.com/elceef/dnstwist) engine.
Enter a domain, click **START SCAN**, and review the real dnstwist results in the browser. No data is
simulated: every number comes from scanner output stored on your machine.

> Only scan domains you own or are authorized to assess.

## Features

| Page | What it does |
|---|---|
| Overview | Totals, resolved / unresolved / DNS-error counts, IPv4/IPv6/MX counts, permutation-category, status, IP, MX and scan-activity charts, recent scans. Scope: latest scan or all scans combined. |
| Domain Scanner | Validates the domain, runs dnstwist in a background subprocess, shows status and elapsed time, captures stdout/stderr, saves the result to history. |
| Scan Results | Interactive table: search, permutation-type and DNS-status filters, sortable columns, row details with the raw record, filtered CSV / full JSON download. |
| Threat Analysis | Rule-based triage queue, per-permutation-type groups, analyst status + notes (stored locally). |
| Similarity Analysis | LSH (ssdeep / TLSH) and pHash scores **only when the scan produced them**; otherwise install instructions. |
| Scan History | Searchable list of all scans, reopen results/reports, delete with confirmation, import `results.json`. |
| Reports & Exports | JSON report, CSV report, text summary; optional unique-named copies in `reports/`. |

## Architecture

```
dashboard.py                  Streamlit UI (7 pages, sidebar navigation)
dashboard_modules/
  validators.py               domain validation (IDNA aware, rejects anything that is not a bare domain)
  scanner.py                  subprocess runner: shell=False, timeout, cancel, one scan at a time
  parser.py                   dnstwist JSON -> DataFrame, DNS status classification, statistics
  analytics.py                triage rules + Plotly charts
  history.py                  JSON index, result copies, analyst annotations
  reports.py                  JSON / CSV / summary builders
dashboard_assets/style.css    dark SOC theme
.streamlit/config.toml        theme + binds the server to 127.0.0.1
scan_history/                 index.json, annotations.json, results/*.json  (git-ignored)
reports/                      saved report copies                           (git-ignored)
```

The engine is executed as
`python dnstwist.py --format json --output scan_history/results/<domain>_<id>.json --threads N [--lsh ssdeep] -- <domain>`
using the interpreter that runs Streamlit (the venv). JSON is read from the output file; terminal output is never parsed.
dnstwist opens `--output` in exclusive-create mode, so an existing file can never be overwritten.

## Setup (Windows, Python 3.9)

```powershell
cd "C:\Users\SURESH\Desktop\kits project\typosuatting and look alike domin detector 94\dnstwist"
.\venv\Scripts\Activate.ps1
python --version                       # Python 3.9.x
pip install -r requirements-dashboard.txt
```

Installed versions on this machine: streamlit 1.49.1, pandas 2.2.3, plotly 6.3.1 (Streamlit also installs numpy,
pyarrow, Pillow and others). If activation is blocked: `Set-ExecutionPolicy -Scope Process RemoteSigned`.

## Start

```powershell
streamlit run dashboard.py
```

Open <http://localhost:8501>. The server is bound to `127.0.0.1` (not reachable from the network) because the app can launch scans.

## Using the dashboard

1. **Domain Scanner**: type e.g. `example.com`, tick the authorization box, press **START SCAN**.
   The page shows a running indicator and elapsed time (dnstwist reports no real progress, so no percentage is shown).
   A scan of `example.com` took about 23 s here.
2. When finished, click **View results**. Pages Scan Results, Threat Analysis, Similarity Analysis and Reports
   work on the scan selected in their *Scan* drop-down.
3. **Reports & Exports**: download JSON, CSV or the summary, or save copies to `reports/`.

### Interpreting results

* **Permutations / candidates**: generated lookalike names; the original domain is excluded from all counts.
* **Resolved**: at least one real A / AAAA / NS / MX answer. **Unresolved**: no records returned.
  **DNS error**: the only answers were `!ServFail` (lookup failure, not proof the domain is unregistered).
* **Needs investigation**: a documented triage rule matched (shown in *Triage reasons*):
  R1 resolves to an IP and has MX records; R2 dnstwist `mx_spy`; R3 LSH similarity at or above a threshold you set.
  This is a to-do list for a human, not a verdict. **No risk scores are computed.**
* **Manually confirmed malicious** can only be set by an analyst (Threat Analysis > Analyst review) after confirming independent verification.
* DNS resolution, MX records or similarity alone do not prove phishing. Many resolving lookalikes are parked pages or defensive registrations.

## Scan history

Each scan stores: target, start time, status (completed / failed / timeout / cancelled), options, duration, statistics, and the
result file path under `scan_history/results/`. Failed scans are recorded without a result file.
Your existing `results.json` is imported once, as a **copy** (the original is untouched). Imported records have an unknown scan
time and unknown options; they are marked *imported*. Re-import is detected by SHA-256, and deleting an imported record prevents
automatic re-import (use the *Import results.json* button to force it). Deleting an entry removes its index record, its stored
result copy and its analyst notes.

## Optional features

| Feature | Status here | To enable |
|---|---|---|
| LSH ssdeep | available (dnstwist uses `ppdeep`) | already installed |
| LSH TLSH | **not installed** | `pip install py-tlsh`, restart the dashboard |
| pHash screenshots | **not installed** | `pip install Pillow selenium` + Chrome/Chromium and a matching chromedriver on PATH |
| GeoIP / WHOIS / banners | not exposed in the UI | out of scope; fields are displayed if present in a result file |

Streamlit installs Pillow as its own dependency; pHash still needs Selenium and a browser driver, so it stays disabled.

## Security notes and limitations

* **LSH and pHash contact candidate websites.** `--lsh` makes dnstwist send HTTP(S) requests to every resolved candidate
  (TLS certificates are not verified for them), exposing your IP to possibly attacker-controlled hosts. The dashboard keeps it
  off by default and requires an explicit acknowledgement. pHash would render those pages in a browser (executes remote JavaScript);
  use an isolated VM. LSH has not been exercised in testing (see below).
* The dashboard never opens candidate domains; they are shown as plain text. Do not click through to them from your normal browser.
* DNS queries for every permutation (about 2,000 for `example.com`) go to your configured resolver.
* Subprocess is started with `shell=False`, an argument list, a validated domain and a `--` separator; LSH/threads options are whitelisted.
* CSV cells beginning with `= + - @` are prefixed with `'` to prevent spreadsheet formula injection.
* One scan at a time, server-wide. If you stop the dashboard mid-scan the scan stops with it (no result is stored).
* Single-user local tool: there is no authentication.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `streamlit` not recognised | Activate the venv first, or run `.\venv\Scripts\python.exe -m streamlit run dashboard.py` |
| Port 8501 already in use (another Streamlit app) | `streamlit run dashboard.py --server.port 8502` |
| "A scan of X is already running" | Wait, or press **Cancel scan** |
| Scan status `timeout` | Increase *Timeout (minutes)* or lower the thread count on slow networks |
| `missing py-tlsh library` | TLSH not installed, see Optional features |
| Many "DNS error" rows | Your resolver rate-limits bursts; lower *Scanner threads* or use `--nameservers` via the CLI |
| `results.json` not in history | It must be a dnstwist `--format json` file containing the `*original` record |
| Corrupt `scan_history/index.json` | It is renamed to `index.json.corrupt-<time>` and a fresh index is started |
