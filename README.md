# Subdomain-Acquisition-Ghost-Enumeration
SAGE is a Subdomain Takeover Detection Framework. You give it a domain (like example.com), and it finds all subdomains (blog.example.com, api.example.com, etc.), checks if any of them point to cloud services that no longer exist, and tells you which ones an attacker could hijack.

## Project Status

🚧 **In active development.** Being built in phases as part of an internship project.

| Phase | Component | Status |
|---|---|---|
| 1 | DNS Resolution Engine (async CNAME chain resolution, wildcard detection) | ✅ Done |
| 2 | Cloud Provider Fingerprinting | ✅ Done |
| 3 | HTTP/HTTPS Active Verification (signature-based) | 🚧 In progress |
| 4 | Confidence Scoring Engine | ⬜ Not started |
| 5 | JSON/HTML Reporting | ⬜ Not started |
| 6 | Subdomain Enumeration (wordlist + subfinder integration) | ⬜ Not started |

## What works right now

### Phase 1 — DNS Resolution Engine (`core/dns_engine.py`)
Takes one or more hostnames and:
- Resolves CNAME records asynchronously
- Follows multi-hop CNAME chains to their final target
- Checks whether the final target still resolves to an A/AAAA record
- Flags subdomains as **CNAME candidates** when they have a CNAME pointing to a target with no live A/AAAA record — the DNS-level signature of a potentially dangling resource
- Detects wildcard DNS on a domain (to avoid false positives)

### Phase 2 — Cloud Provider Fingerprinting (`providers/__init__.py`, `config/providers.json`)
Takes a CNAME candidate's final target hostname and classifies which cloud provider it belongs to (GitHub Pages, Heroku, AWS S3, Azure App Service, Vercel, Netlify), by matching against domain patterns defined in `config/providers.json`. Unknown providers are flagged for manual review rather than discarded or misclassified.

**Note:** DNS-level flagging + provider identification alone are *not* proof of a takeover — they identify candidates worth investigating further. Confirming an actual vulnerability requires HTTP-level signature verification (Phase 3, in progress).

### Real-world validated finding
During authorized testing (see Testing section below), it was confirmed that DNS-level checking alone produces a **false negative** for GitHub Pages specifically: GitHub's shared Pages infrastructure keeps answering on the same IPs regardless of whether a specific site exists, so a deleted site still shows an A record. The only reliable signal is the HTTP response body, which returns `"There isn't a GitHub Pages site here."` for unclaimed hostnames. This directly confirms why HTTP-level signature verification (Phase 3) is necessary rather than optional.

### Usage

```bash
pip install -r requirements.txt
python core/dns_engine.py subdomain1.example.com subdomain2.example.com
python providers/__init__.py hostname1 hostname2
```

### Testing

Validated against a real, authorized subdomain — the domain owner granted explicit permission to test a specific subdomain end-to-end (live CNAME → confirmed not vulnerable → resource deleted → confirmed correctly flagged as a dangling GitHub Pages CNAME).