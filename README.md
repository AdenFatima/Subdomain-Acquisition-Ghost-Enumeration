# Subdomain-Acquisition-Ghost-Enumeration
SAGE is a Subdomain Takeover Detection Framework. You give it a domain (like example.com), and it finds all subdomains (blog.example.com, api.example.com, etc.), checks if any of them point to cloud services that no longer exist, and tells you which ones an attacker could hijack.

## Project Status

🚧 **In active development.** Being built in phases as part of an internship project.

| Phase | Component | Status |
|---|---|---|
| 1 | DNS Resolution Engine (async CNAME chain resolution, wildcard detection) | ✅ Done |
| 2 | Cloud Provider Fingerprinting | ✅ Done |
| 3 | HTTP/HTTPS Active Verification (signature-based) | ✅ Done |
| 4 | Confidence Scoring Engine | ⬜ Not started |
| 5 | JSON/HTML Reporting | ⬜ Not started |
| 6 | Subdomain Enumeration (wordlist + subfinder integration) | ⬜ Not started |

## What works right now

### Phase 1 — DNS Resolution Engine (`core/dns_engine.py`)
Takes one or more hostnames and:
- Resolves CNAME records asynchronously
- Follows multi-hop CNAME chains to their final target
- Checks whether the final target has an A/AAAA record (DNS-level only — see important note below)
- Flags subdomains as **CNAME candidates** when they have a CNAME pointing to a target with no A/AAAA record
- Detects wildcard DNS on a domain (to avoid false positives)

### Phase 2 — Cloud Provider Fingerprinting (`providers/__init__.py`, `config/providers.json`)
Takes a CNAME candidate's final target hostname and classifies which cloud provider it belongs to (GitHub Pages, Heroku, AWS S3, Azure App Service, Vercel, Netlify), by matching against domain patterns defined in `config/providers.json`. Unknown providers are flagged for manual review rather than discarded or misclassified.

### Phase 3 — HTTP Signature Verification (`providers/github.py`, `heroku.py`, `aws.py`, `azure.py`, `vercel.py`, `netlify.py`)
For each candidate with a known provider, sends a real HTTP request and checks the response body against that provider's documented "resource not found" signature (e.g. GitHub Pages' `"There isn't a GitHub Pages site here."`). This is the step that actually confirms a takeover is possible — DNS and provider matching alone only narrow down candidates.

**Run a provider verifier directly with:**
```bash
python -m providers.github hostname.github.io
python -m providers.netlify hostname.netlify.app
```
(Use `-m` and dotted notation, not a direct file path — these modules share code via `providers/_base.py`.)

## Important finding: why DNS-only detection isn't enough

During authorized testing (see below), it was confirmed **twice, on two independent providers**, that DNS-level checking alone produces a **false negative**:

- **GitHub Pages** and **Netlify** both run shared infrastructure — the same small set of IPs serves *every* customer's site. Deleting a specific site does **not** remove the A/AAAA record, because the shared servers keep answering regardless of whether that particular site still exists.
- The only reliable signal is the **HTTP response body**, which contains a distinct "not found" message once the underlying resource is gone.

This directly validates why the project's methodology treats HTTP-level signature verification as mandatory, not optional — a DNS-only tool would have reported both of these real, confirmed-dangling subdomains as safe.

### Testing

Validated against real, authorized subdomains — the domain owner granted explicit permission to test specific subdomains end-to-end (live CNAME → confirmed not vulnerable → underlying resource deleted → confirmed correctly flagged as dangling via HTTP signature match) on:
- **GitHub Pages** — confirmed dangling, signature: `"There isn't a GitHub Pages site here."`
- **Netlify** — confirmed dangling, signature: `"Not Found - Request ID"`

The remaining four providers (Heroku, AWS S3, Azure App Service, Vercel) use the same documented public signature patterns used by established open-source recon tools, but have not yet been validated against a live, authorized dangling instance.

### Usage

```bash
pip install -r requirements.txt
python core/dns_engine.py subdomain1.example.com subdomain2.example.com
python providers/__init__.py hostname1 hostname2
python -m providers.github hostname.github.io
```