# Subdomain-Acquisition-Ghost-Enumeration
SAGE is a Subdomain Takeover Detection Framework. You give it a domain (like example.com), and it finds all subdomains (blog.example.com, api.example.com, etc.), checks if any of them point to cloud services that no longer exist, and tells you which ones an attacker could hijack.

## Project Status

🚧 **In active development.** Being built in phases as part of an internship project.

| Phase | Component | Status |
|---|---|---|
| 1 | DNS Resolution Engine (async CNAME chain resolution, wildcard detection) | ✅ Done |
| 2 | Cloud Provider Fingerprinting | ⬜ Not started |
| 3 | HTTP/HTTPS Active Verification (signature-based) | ⬜ Not started |
| 4 | Confidence Scoring Engine | ⬜ Not started |
| 5 | JSON/HTML Reporting | ⬜ Not started |
| 6 | Subdomain Enumeration (wordlist + subfinder integration) | ⬜ Not started |

## What works right now (Phase 1)

`core/dns_engine.py` takes one or more hostnames and:
- Resolves CNAME records asynchronously
- Follows multi-hop CNAME chains to their final target
- Checks whether the final target still resolves to an A/AAAA record
- Flags subdomains as **CNAME candidates** when they have a CNAME pointing to a target with no live A/AAAA record — the DNS-level signature of a potentially dangling resource
- Detects wildcard DNS on a domain (to avoid false positives)

**Note:** DNS-level flagging alone is *not* proof of a takeover — it identifies candidates worth investigating further. Confirming an actual vulnerability requires HTTP-level signature verification (Phase 3), which hasn't been built yet.

### Usage

```bash
pip install -r requirements.txt
python core/dns_engine.py subdomain1.example.com subdomain2.example.com
```

### Testing

Validated using a local mock DNS server (`tests/mock_dns_server.py`) with controlled "live" and "dangling" CNAME test cases, confirming the engine correctly distinguishes between the two. See `tests/` for details.
