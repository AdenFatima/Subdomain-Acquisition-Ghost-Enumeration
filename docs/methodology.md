# Methodology: The SAGE Pipeline

SAGE (Subdomain Acquisition & Ghost Enumeration) is designed to solve a specific flaw in traditional attack surface management tools: **DNS-level checks alone produce false negatives on modern cloud infrastructure**[cite: 8].

## The Shared Infrastructure Problem
During authorized testing, it was confirmed that cloud providers like GitHub Pages and Netlify utilize shared infrastructure[cite: 8]. The same small set of IP addresses serves every customer's site[cite: 8]. 

When a user deletes a site or repository, the underlying A/AAAA record is **not** removed because the shared edge servers remain active and continue answering DNS queries[cite: 8]. A legacy recon tool that only checks if a CNAME target lacks an A record (NXDOMAIN) will completely miss these vulnerabilities[cite: 8].

## The Verification Solution
To eliminate these false negatives, SAGE operates in strict phases:
1. **DNS Resolution Engine:** Finds all subdomains with a CNAME pointing to an external domain[cite: 8]. It ignores A-record resolution status because shared IPs will still respond[cite: 8].
2. **Cloud Provider Fingerprinting:** Matches the CNAME target against known patterns (e.g., `*.github.io`)[cite: 8].
3. **HTTP Signature Verification:** The only reliable way to confirm a takeover on shared infrastructure is by checking the HTTP response body[cite: 8]. SAGE issues a live web request and checks for exact, documented error strings (e.g., `"There isn't a GitHub Pages site here."`)[cite: 8]. 

This methodology guarantees that high-confidence findings are immediately actionable.