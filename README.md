# 🔍 SAGE — Subdomain Acquisition & Ghost Enumeration

**SAGE** is an advanced, asynchronous subdomain takeover detection framework. It automates the full reconnaissance pipeline — from subdomain discovery to DNS chain resolution, cloud provider fingerprinting, and active HTTP-level vulnerability verification.

Built for speed and accuracy, SAGE eliminates the false negatives common in traditional DNS-only reconnaissance tools by confirming dangling resources at the application layer, not just the DNS layer.

---

## 📖 Table of Contents

- [The SAGE Methodology](#-the-sage-methodology-solving-the-shared-ip-flaw)
- [Core Architecture & Pipeline](#️-core-architecture--pipeline)
- [Installation](#-installation)
- [Usage](#-usage-guidelines)
- [Directory Structure](#-directory-structure)
- [Output Formats](#-output-formats)
- [Contributing](#-contributing)
- [Disclaimer](#️-disclaimer)

---

## 🧠 The SAGE Methodology: Solving the "Shared IP" Flaw

Traditional subdomain takeover tools typically rely on pure DNS analysis — for example, checking whether a CNAME points to a target with no corresponding A/AAAA record.

Testing against modern cloud infrastructure has shown this approach produces **false negatives**:

- Providers like **GitHub Pages** and **Netlify** use shared edge servers.
- When a user deletes a deployed site, the underlying A/AAAA IP records often remain active globally.
- As a result, DNS resolution alone cannot reliably confirm whether a resource is actually unclaimed.

**The only reliable way to confirm a takeover is to inspect the HTTP response body for exact "resource not found" signatures.**

SAGE enforces HTTP-level signature verification for all known providers, ensuring that every "High Risk" finding is immediately actionable and backed by concrete evidence — not just DNS inference.

---

## ⚙️ Core Architecture & Pipeline

SAGE processes every target through a strict, five-phase pipeline:

### 1. Discovery Engine (`core/enumerator.py`)
Combines passive and active enumeration methodologies:
- Automatically invokes `subfinder` for passive OSINT gathering (if installed).
- Merges results seamlessly with active DNS brute-forcing using a customizable wordlist.

### 2. DNS Resolution Engine (`core/dns_engine.py`)
A highly concurrent `aiodns`-based resolver that:
- Follows CNAME chains through to their final target.
- Flags CNAMEs as potential dangling candidates without incorrectly dropping them due to shared A-records.
- Actively detects and filters wildcard DNS misconfigurations to prevent false positives.

### 3. Provider Fingerprinting (`providers/`)
- Matches the final CNAME target against a centralized, easily updatable registry (`config/providers.json`).
- Classifies the cloud service in use (e.g., AWS S3, Heroku, Azure, Vercel, GitHub Pages).
- Unknown providers are explicitly flagged for manual review rather than silently discarded.

### 4. HTTP Signature Verification (`providers/*`)
- Sends an asynchronous HTTP/HTTPS request directly to the target subdomain.
- Scans the response body against known provider error signatures (e.g., GitHub's *"There isn't a GitHub Pages site here."*) to definitively confirm the resource is unclaimed.

### 5. Scoring & Reporting (`core/scorer.py` & `reports/`)
- Evaluates combined DNS and HTTP evidence to assign a confidence tier: **High**, **Medium**, or **Low**.
- Generates structured JSON reports for automation/CI pipelines.
- Generates stylized HTML dashboards suitable for penetration testing deliverables.

---

## 🚀 Installation

SAGE is built for **Kali Linux** and **Windows** environments and installs as a native global CLI command.

### Prerequisites
- Python 3.10+
- [Subfinder](https://github.com/projectdiscovery/subfinder) *(optional, but recommended for passive enumeration)*

### Setup

Clone the repository and install the framework globally using pip:

```bash
git clone https://github.com/yourusername/SAGE.git
cd SAGE
pip install -r requirements.txt
pip install -e .
```

> **Note:** Using `-e` (editable mode) allows you to update provider fingerprint signatures without needing to reinstall the tool.

---

## 💻 Usage Guidelines

Once installed, SAGE can be invoked globally from any terminal directory.

### Standard Scan (Subfinder + Default Wordlist)

```bash
sage -d example.com
```

### Advanced Scan with a Custom Wordlist

Bypass the default wordlist in favor of a larger, custom dictionary:

```bash
sage -d example.com -w /usr/share/wordlists/amass/subdomains.txt
```

### Stealth / Active-Only Mode

Disable passive Subfinder integration and rely solely on direct DNS brute-forcing:

```bash
sage -d example.com --no-subfinder
```

### Generate Deliverables

Output findings to both JSON (for CI/CD tool chaining) and HTML (for visual review):

```bash
sage -d example.com --json report.json --html dashboard.html
```

### Common CLI Flags

| Flag | Description |
|---|---|
| `-d`, `--domain` | Target domain to scan (required) |
| `-w`, `--wordlist` | Path to a custom subdomain wordlist |
| `--no-subfinder` | Disable passive OSINT enumeration; DNS brute-force only |
| `--json <file>` | Write structured findings to a JSON report |
| `--html <file>` | Write a stylized HTML dashboard report |

---

## 📁 Directory Structure

```
SAGE/
├── config/
│   ├── providers.json               # Cloud provider fingerprinting rules
│   └── subdomains_wordlist.txt      # Default active brute-force dictionary
├── core/
│   ├── dns_engine.py                # Asynchronous CNAME chain resolution
│   ├── enumerator.py                # OSINT & brute-force logic
│   └── scorer.py                    # Confidence evaluation logic
├── docs/
│   ├── methodology.md               # Technical overview of the HTTP verification requirement
│   └── usage.md                     # Extended CLI usage examples
├── providers/
│   ├── __init__.py                  # Provider classification engine
│   ├── _base.py                     # Shared HTTP request logic
│   └── github.py, aws.py, etc.      # Individual provider signature modules
├── reports/
│   ├── json_reporter.py             # Structured CI/CD output
│   └── html_reporter.py             # Presentation deliverables
├── templates/
│   └── report_template.html         # HTML dashboard layout
├── tests/
│   └── test_.py                     # Unit testing environment
├── requirements.txt                 # Project dependencies
├── setup.py                         # Global package installation configuration
└── sage.py                          # Master orchestration engine (CLI entrypoint)
```

---

## 📊 Output Formats

| Format | Use Case |
|---|---|
| **JSON** | Machine-readable output for CI/CD pipelines and automated triage |
| **HTML** | Stylized, human-readable dashboard for client-facing pentest deliverables |

Each finding includes the subdomain, resolved CNAME chain, identified provider, confidence tier (High/Medium/Low), and the HTTP evidence used to reach that conclusion.

---

## 🤝 Contributing

Contributions are welcome, particularly for:
- New provider fingerprint signatures (`config/providers.json`)
- Additional HTTP verification modules under `providers/`
- Wordlist improvements

Please open an issue or pull request describing the change before submitting large modifications.

---

## ⚠️ Disclaimer

SAGE is intended **solely for authorized security testing** — including penetration tests, bug bounty engagements, and audits of infrastructure you own or have explicit written permission to test. Running SAGE against domains or infrastructure without authorization may violate the law. Users are solely responsible for ensuring they have proper authorization before scanning any target.