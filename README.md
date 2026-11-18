# Typosquatting and Lookalike Domain Detection System

A Python-based cybersecurity project that identifies potential typosquatting and lookalike domains using the [dnstwist](https://github.com/elceef/dnstwist) scanning engine and a custom Streamlit dashboard.

The system generates domain variations, performs DNS analysis, organizes candidate domains, and provides an interactive interface for investigating potential domain impersonation.

---

## Table of Contents

1. Project Overview
2. Problem Statement
3. Project Objectives
4. Key Features
5. System Architecture
6. How the Project Works
7. Domain Permutation Techniques
8. DNS Records Explained
9. Dashboard Pages
10. Technology Stack
11. Project Structure
12. System Requirements
13. Installation and Setup
14. Running the Dashboard
15. Performing a Domain Scan
16. Understanding Scan Results
17. Exporting Reports
18. Scan History
19. Optional Features
20. Testing
21. Security Considerations
22. Limitations
23. Future Enhancements
24. Troubleshooting
25. Acknowledgements

---

## 1. Project Overview

Typosquatting is a technique in which someone registers a domain name that resembles a legitimate website's domain name.

For example, a legitimate domain such as:

`microsoft.com`

may have similar-looking variations such as:

- `micros0ft.com`
- `microsofts.com`
- `microsof-t.com`
- `microssoft.com`

Users may confuse these domains with the original website.

Such domains may potentially be used for phishing, brand impersonation, fraudulent emails, or other deceptive activities.

This project uses the open-source **dnstwist** engine to generate potential lookalike domain names and perform DNS analysis.

A custom **Streamlit dashboard** provides an interactive interface for scanning domains, viewing DNS information, analyzing candidates, maintaining scan history, and exporting reports.

**Important:** The system identifies potential lookalike domains. A generated or DNS-resolved domain is not automatically a malicious or phishing website.

---

## 2. Problem Statement

Cybercriminals may create domain names that closely resemble legitimate websites to exploit user confusion.

Manually identifying thousands of possible domain variations is time-consuming.

The project addresses this problem by automating:

- Domain variation generation.
- DNS record discovery.
- Candidate classification.
- Scan result visualization.
- Domain investigation.
- Report generation.

The system helps security researchers and analysts identify domains that may require further investigation.

---

## 3. Project Objectives

- Generate possible typosquatting and lookalike domain variations.
- Identify DNS-resolved candidate domains.
- Retrieve available IPv4 and IPv6 information.
- Retrieve nameserver and mail exchange records.
- Categorize domain variations by permutation technique.
- Provide an interactive cybersecurity dashboard.
- Search and filter generated domain candidates.
- Maintain previous scan results locally.
- Export results in JSON and CSV formats.
- Provide a foundation for further website similarity analysis.

---

## 4. Key Features

### Domain scanning

- Enter a target domain.
- Validate the domain before scanning.
- Execute the existing dnstwist engine.
- Generate domain permutations.
- Perform DNS analysis.
- Display scan status and elapsed time.

### Domain permutation

Supports the permutation techniques available in dnstwist, including:

- Addition
- Bitsquatting
- Homoglyph
- Hyphenation
- Insertion
- Omission
- Repetition
- Replacement
- Subdomain
- Transposition
- Vowel-swap
- Plural
- Cyrillic
- Dictionary
- TLD swap
- Various

Not every technique necessarily appears in every scan.

### DNS analysis

Retrieve available DNS information:

- A records
- AAAA records
- NS records
- MX records

### Interactive dashboard

- Dark cybersecurity-themed interface.
- Overview statistics.
- Interactive result tables.
- Search and filtering.
- Domain details.
- Analytics and charts.
- Scan history.
- Report downloads.

### Threat investigation

- Identify resolved candidate domains.
- Highlight candidates matching documented investigation rules.
- Display available DNS information.
- Allow analyst notes and manual investigation status.
- Distinguish investigation flags from confirmed malicious classifications.

### Report generation

- JSON export.
- CSV export.
- Scan summary.
- Unique report filenames.

---

## 5. System Architecture

The project uses the original dnstwist engine with a custom Streamlit dashboard.

```text
                 USER
                   |
                   v
          STREAMLIT DASHBOARD
              dashboard.py
                   |
                   v
            DOMAIN VALIDATION
               validators.py
                   |
                   v
             SCANNER MODULE
                scanner.py
                   |
                   v
          DNSTWIST SCANNING ENGINE
                dnstwist.py
                   |
                   v
          DOMAIN PERMUTATION
                   |
                   v
               DNS LOOKUP
                   |
                   v
              JSON OUTPUT
                   |
                   v
              JSON PARSER
                parser.py
                   |
          +--------+---------+
          |        |         |
          v        v         v
       RESULTS  ANALYTICS  HISTORY
                   |         |
                   v         v
               PLOTLY     LOCAL STORAGE
                   |
                   v
             REPORT EXPORT
                reports.py
                   |
                   v
             JSON / CSV FILES
```

### Main architecture components

| Component       | Responsibility                                  |
| --------------- | ----------------------------------------------- |
| `dnstwist.py`   | Original domain permutation and scanning engine |
| `dashboard.py`  | Main Streamlit application                      |
| `scanner.py`    | Executes the scanner using a subprocess         |
| `validators.py` | Validates domain input                          |
| `parser.py`     | Parses scanner JSON output                      |
| `analytics.py`  | Calculates statistics and generates charts      |
| `history.py`    | Manages local scan history                      |
| `reports.py`    | Generates downloadable reports                  |

The dashboard invokes the original scanner using the Python interpreter from the active virtual environment.

The original scanning engine is preserved.

---

## 6. How the Project Works

### Step 1: Enter a target domain

The user enters a domain name in the Domain Scanner page.

Example:

`example.com`

### Step 2: Validate the domain

The application checks the submitted domain and rejects invalid input.

Internationalized domain names are handled through supported IDN conversion.

### Step 3: Generate permutations

The dnstwist engine generates possible domain variations using different permutation techniques.

### Step 4: Perform DNS analysis

The scanner checks available DNS records for generated candidates.

### Step 5: Parse results

The dashboard reads the scanner's JSON output and converts it into structured data.

### Step 6: Analyze results

The dashboard calculates statistics and identifies candidates requiring additional investigation according to documented rules.

### Step 7: Display results

The user can view, search, filter, and inspect generated domains.

### Step 8: Save and export

The scan is stored locally and can be downloaded in JSON and CSV formats.

---

## 7. Domain Permutation Techniques

The project uses domain variation techniques supported by dnstwist.

| Technique     | Description                                       |
| ------------- | ------------------------------------------------- |
| Addition      | Adds an extra character                           |
| Bitsquatting  | Changes a character through a bit-level variation |
| Homoglyph     | Uses visually similar characters                  |
| Hyphenation   | Inserts hyphens into the domain                   |
| Insertion     | Inserts a character at a position                 |
| Omission      | Removes a character                               |
| Repetition    | Repeats a character                               |
| Replacement   | Replaces one character with another               |
| Subdomain     | Generates variations involving subdomain labels   |
| Transposition | Swaps adjacent characters                         |
| Vowel-swap    | Changes one vowel to another                      |
| Plural        | Generates plural-form variations                  |
| Cyrillic      | Generates Cyrillic-character variations           |
| Dictionary    | Uses dictionary-based variations                  |
| TLD swap      | Changes the top-level domain                      |
| Various       | Other supported variations                        |

---

## 8. DNS Records Explained

The scanner can retrieve the following DNS information.

| Record | Description                                             |
| ------ | ------------------------------------------------------- |
| A      | Maps a domain to an IPv4 address                        |
| AAAA   | Maps a domain to an IPv6 address                        |
| NS     | Identifies the domain's nameservers                     |
| MX     | Identifies mail servers responsible for receiving email |

### Example

```text
Domain: example.com

IPv4: Available
IPv6: Available
Nameservers: Available
Mail Exchange: Available
```

DNS information helps analysts understand the infrastructure associated with a domain.

It does not independently establish whether the domain is malicious.

---

## 9. Dashboard Pages

The Streamlit dashboard contains seven main pages.

### 1. Overview

Displays:

- Total scans.
- Generated domain candidates.
- Resolved domains.
- Unresolved domains.
- DNS errors.
- IPv4 and IPv6 availability.
- MX record availability.
- Recent scan history.
- Interactive charts.

Statistics are calculated from available scan history.

### 2. Domain Scanner

Allows users to:

- Enter a target domain.
- Confirm authorization.
- Configure supported scanning options.
- Start a scan.
- View scanning status.
- View elapsed time.
- Retrieve actual scanner output.

The scanner runs through a subprocess with argument validation, timeout handling, and safe output-file handling.

### 3. Scan Results

Displays:

- Generated domain.
- Permutation type.
- DNS status.
- Analysis status.
- IPv4 addresses.
- IPv6 addresses.
- Nameservers.
- MX records.
- Available similarity information.

Features include:

- Domain search.
- Permutation filters.
- DNS status filters.
- Sorting.
- Individual domain details.
- JSON and CSV downloads.

### 4. Threat Analysis

Provides an investigation interface for reviewing potential lookalike domains.

The current dashboard uses a documented rule:

`R1: resolves + has MX`

This flags a candidate when it resolves and has a mail exchange record.

This is an investigation indicator only, not a maliciousness score or phishing verdict.

Analysts can add notes and manually record their investigation decisions.

### 5. Similarity Analysis

Provides an interface for available similarity-analysis information.

Supported or optional capabilities:

- ssdeep fuzzy hashing.
- TLSH fuzzy hashing.
- pHash screenshot similarity.

The current implementation has ssdeep support available, but actual similarity scans have not yet been fully validated.

TLSH and pHash are optional and may remain unavailable until their dependencies and browser configuration are installed.

### 6. Scan History

Stores previous scan information locally.

Stored information includes:

- Target domain.
- Scan timestamp when available.
- Scan status.
- Candidate counts.
- Scan configuration.
- Result file location.
- Scan duration.

Previous results can be reopened.

### 7. Reports & Exports

Provides downloadable reports:

- JSON.
- CSV.
- Scan summary.

Reports are generated from actual scan results.

---

## 10. Technology Stack

| Technology          | Purpose                                |
| ------------------- | -------------------------------------- |
| Python 3.9          | Main programming language              |
| dnstwist            | Domain permutation and scanning engine |
| Streamlit           | Interactive web dashboard              |
| Pandas              | Data processing                        |
| Plotly              | Interactive charts                     |
| dnspython           | DNS operations                         |
| ppdeep              | Fuzzy hashing support                  |
| geoip2              | Optional GeoIP functionality           |
| tld                 | Domain and TLD handling                |
| idna                | Internationalized domain handling      |
| JSON                | Structured scan output and storage     |
| CSV                 | Tabular report export                  |
| SQLite / local JSON | Local history storage                  |
| HTML / CSS          | Dashboard presentation and styling     |

### Optional dependencies

| Dependency              | Purpose                            | Current status                      |
| ----------------------- | ---------------------------------- | ----------------------------------- |
| py-tlsh                 | TLSH fuzzy hashing                 | Not installed                       |
| Pillow                  | Image processing                   | Installed as a dashboard dependency |
| Selenium                | Browser automation for screenshots | Not installed                       |
| Chrome / browser driver | Screenshot functionality           | Requires configuration              |
| GeoLite2 database       | GeoIP information                  | Not configured                      |

---

## 11. Project Structure

```text
dnstwist/
│
├── dnstwist.py
├── setup.py
├── requirements.txt
├── README.md
│
├── dashboard.py
│
├── dashboard_modules/
│   ├── __init__.py
│   ├── validators.py
│   ├── scanner.py
│   ├── parser.py
│   ├── analytics.py
│   ├── history.py
│   └── reports.py
│
├── dashboard_assets/
│   └── style.css
│
├── .streamlit/
│   └── config.toml
│
├── scan_history/
│
├── reports/
│
├── requirements-dashboard.txt
├── DASHBOARD.md
├── docs/
├── dictionaries/
├── webapp/
│
└── venv/
```

Note: `venv/` is a local development environment and should not be committed to GitHub.

The `scan_history/` and `reports/` directories are local runtime storage. Do not publish private scan data or sensitive investigation notes.

---

## 12. System Requirements

Recommended environment:

- Operating system: Windows 10 or Windows 11.
- Python: 3.9.
- Git.
- Internet connection for DNS scanning.
- Google Chrome or another modern browser for dashboard access.
- Sufficient disk space for scan results and reports.

The current project was tested using Python 3.9.4.

---

## 13. Installation and Setup

### Step 1: Clone the repository

```powershell
git clone https://github.com/nnaidev02Amer/typosuatting-and-look-alike-domin-detector-94.git

cd typosuatting-and-look-alike-domin-detector-94
```

### Step 2: Create a virtual environment

If Python 3.9 is installed:

```powershell
py -3.9 -m venv venv
```

### Step 3: Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\venv\Scripts\Activate.ps1
```

### Step 4: Upgrade pip tools

```powershell
python -m pip install --upgrade pip setuptools wheel
```

### Step 5: Install the original dnstwist project

```powershell
python -m pip install -e .
```

### Step 6: Install the required scanning dependencies

```powershell
python -m pip install dnspython geoip2 ppdeep tld idna
```

### Step 7: Install dashboard dependencies

```powershell
python -m pip install -r requirements-dashboard.txt
```

### Step 8: Verify the installation

Check Python:

```powershell
python --version
```

Check dnstwist:

```powershell
dnstwist --version
```

Check Streamlit:

```powershell
streamlit --version
```

Check dashboard libraries:

```powershell
python -c "import streamlit, pandas, plotly; print('Dashboard dependencies installed successfully')"
```

---

## 14. Running the Dashboard

Make sure the virtual environment is activated.

From the project root, execute:

```powershell
streamlit run dashboard.py
```

The dashboard should open in your default browser.

Local URL:

`http://localhost:8501`

To use another port:

```powershell
streamlit run dashboard.py --server.port 8502
```

To stop the dashboard, press:

`CTRL + C`

in PowerShell.

---

## 15. Performing a Domain Scan

1. Start the dashboard.
2. Open the Domain Scanner page.
3. Enter a domain that you own or have permission to assess.
4. Confirm the authorization checkbox.
5. Select the supported scan options.
6. Click START SCAN.
7. Wait for the scan to complete.
8. Open Scan Results.
9. Review the generated domain variations.
10. Open Threat Analysis for additional investigation.
11. Export the results when required.

Example target for basic functionality testing:

`example.com`

Only use domains you own or have explicit permission to assess for real security investigations.

---

## 16. Understanding Scan Results

The dashboard distinguishes between DNS outcomes and investigation flags.

### Resolved

The DNS lookup returned usable DNS information.

### Unresolved

The scanner did not obtain usable DNS information for the candidate during the scan.

### DNS Error

The DNS lookup encountered an error, such as a server failure.

### Needs Investigation

A dashboard rule indicates that the candidate deserves additional review.

In the current implementation:

`R1: resolves + has MX`

This means the candidate resolved and has a mail exchange record.

It is not proof of phishing or malicious activity.

### Original domain

The original target domain is displayed separately and excluded from generated-candidate counts.

### Example result interpretation

A scan may generate thousands of candidate domains, while only a smaller number return usable DNS information.

The number of resolved candidates is not the number of confirmed phishing websites.

DNS resolution, domain similarity, nameservers, and mail records must be interpreted carefully.

---

## 17. Exporting Reports

The dashboard supports JSON and CSV exports.

### JSON

JSON stores structured scan data.

Example:

```json
[
  {
    "fuzzer": "addition",
    "domain": "example-candidate.com",
    "dns_a": [],
    "dns_aaaa": [],
    "dns_ns": [],
    "dns_mx": []
  }
]
```

The actual scanner output may include additional fields.

### CSV

CSV stores tabular scan results and can be opened using:

- Microsoft Excel.
- LibreOffice Calc.
- Google Sheets.
- Other spreadsheet applications.

Use the Reports & Exports page to download the available reports.

---

## 18. Scan History

Scan history is stored locally.

The history functionality helps users:

- Review previous scans.
- Reopen stored results.
- Compare scan records.
- Review scan statistics.
- Delete selected history entries.

Imported results without a known original timestamp are marked as imported rather than being assigned an invented timestamp.

Do not publish private scan history or sensitive analyst notes.

---

## 19. Optional Features

### A. ssdeep

ssdeep is a fuzzy-hashing technique used to compare content similarity.

The project has ssdeep support available through the existing dnstwist installation.

Actual similarity scanning should be tested separately because it may send HTTP requests to candidate websites.

### B. TLSH

TLSH stands for Trend Micro Locality Sensitive Hash.

It is an optional fuzzy-hashing method for comparing similar data.

Installation:

```powershell
python -m pip install py-tlsh
```

On Windows, installing this package may require Microsoft C++ Build Tools and a compatible compiler.

Verify:

```powershell
python -c "import tlsh; print('TLSH installed successfully')"
```

### C. pHash

pHash means perceptual hashing.

It can compare images based on their visual characteristics.

The screenshot functionality requires compatible image-processing and browser-automation dependencies.

Potential dependencies:

```powershell
python -m pip install Pillow selenium
```

A compatible browser and driver configuration are also required.

These optional features are not enabled or fully validated in the current project.

Do not automatically browse suspicious candidate websites.

---

## 20. Testing

The implemented dashboard was tested for the following areas:

| Test                        | Result                      |
| --------------------------- | --------------------------- |
| Python 3.9 compatibility    | Passed                      |
| Streamlit startup           | Passed                      |
| Dashboard HTTP response     | Passed                      |
| Seven dashboard pages       | Rendered without exceptions |
| Real scanner integration    | Passed                      |
| Domain validation           | Passed                      |
| IDN conversion              | Tested                      |
| JSON parsing                | Passed                      |
| Original-domain exclusion   | Passed                      |
| DNS error handling          | Passed                      |
| Empty MX handling           | Passed                      |
| Scan history saving         | Passed                      |
| Duplicate import prevention | Passed                      |
| JSON export                 | Passed                      |
| CSV export                  | Passed                      |
| Timeout handling            | Passed                      |
| Failed process handling     | Passed                      |
| Original dnstwist CLI       | Passed                      |

### Tests not fully completed

- Actual ssdeep similarity scan.
- TLSH similarity scanning.
- pHash screenshot analysis.
- Visual inspection of every dashboard page.
- Manual browser verification of the cancel button.
- Empty-history screen verification.

Testing results should be updated when these additional tests are completed.

---

## 21. Security Considerations

- Scan only domains that you own or have permission to assess.
- Do not automatically open suspicious candidate websites.
- DNS resolution does not prove that a domain is malicious.
- Do not enter private credentials into candidate websites.
- Treat generated domains as untrusted data.
- Keep investigation notes and private reports secure.
- Do not upload sensitive scan data or API credentials to public repositories.
- Use an isolated environment for further website inspection.
- Review the output before sharing it.

The dashboard runs locally and is configured to listen on `127.0.0.1` during the tested setup.

---

## 22. Current Project Limitations

1. The project primarily performs domain permutation generation and DNS analysis.
2. DNS resolution does not establish malicious intent.
3. Automated phishing confirmation is not implemented.
4. Actual ssdeep similarity scanning has not been fully validated.
5. TLSH is not installed in the current environment.
6. pHash screenshot functionality is not configured.
7. GeoIP functionality requires a suitable GeoLite2 database.
8. DNS results can vary depending on resolver behavior and scan time.
9. Additional investigation is required to confirm whether a domain is being used for phishing or impersonation.

---

## 23. Future Enhancements

Possible future improvements include:

- Complete TLSH integration.
- Screenshot-based pHash comparison.
- More comprehensive website-content comparison.
- Domain registration and reputation investigation.
- Integration with trusted threat-intelligence sources.
- Historical domain comparison.
- Improved investigation workflows.
- Additional report formats.
- More advanced security analytics.
- Analyst review and case management.

These are proposed enhancements, not claims about current functionality.

---

## 24. Troubleshooting

### Problem 1: Streamlit command not found

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

Then install dashboard dependencies:

```powershell
python -m pip install -r requirements-dashboard.txt
```

### Problem 2: ModuleNotFoundError

Install the missing package inside the active virtual environment.

Example:

```powershell
python -m pip install dnspython
```

### Problem 3: TLSH installation fails

The package may require Microsoft C++ Build Tools on Windows.

Install a compatible compiler before retrying.

TLSH is optional for the main dashboard.

### Problem 4: Port 8501 is already in use

Use another port:

```powershell
streamlit run dashboard.py --server.port 8502
```

### Problem 5: DNS errors appear

DNS errors may result from resolver problems, nameserver issues, or temporary network failures.

They should not automatically be classified as malicious domains.

### Problem 6: Dashboard does not start

Check:

```powershell
python --version

python -m pip show streamlit

python -m pip show pandas

python -m pip show plotly
```

Make sure the terminal is in the project root and the correct virtual environment is activated.

---

## 25. Acknowledgements

This project uses the open-source **dnstwist** project developed by [elceef](https://github.com/elceef/dnstwist).

Original repository:

https://github.com/elceef/dnstwist

The custom Streamlit dashboard integrates the existing scanner and provides additional visualization, filtering, scan-history, and reporting functionality.

Please retain the original project's license and attribution notices when redistributing the code.

---

## Project Summary

**Project:** Typosquatting and Lookalike Domain Detection System

**Main Language:** Python

**Scanning Engine:** dnstwist

**Dashboard:** Streamlit

**Data Processing:** Pandas

**Visualization:** Plotly

**Output Formats:** JSON and CSV

**Execution:** Local web dashboard

**Primary Purpose:** Automated generation of potential lookalike domains and DNS-based investigation.

**Final Note:** This project is intended as a cybersecurity research and domain-monitoring tool. It identifies potential domain impersonation candidates and does not independently confirm phishing or malicious activity.
