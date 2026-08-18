"""
providers/github.py

Phase 3: HTTP-level verification for GitHub Pages.

DNS alone cannot confirm a GitHub Pages subdomain takeover - GitHub's
Pages infrastructure keeps answering on the same shared IPs whether a
site exists or not (see docs/methodology.md for the real-world case
that proved this). The only reliable signal is the HTTP response BODY,
which contains a specific error string when no site is published for
that hostname.

This module sends a real HTTP GET request to the candidate hostname and
checks for that exact signature.
"""

import aiohttp
from aiohttp.resolver import ThreadedResolver

# The exact, stable error string GitHub Pages returns when no site is
# published for the requested hostname. Confirmed against a real,
# authorized test case (see docs/methodology.md).
SIGNATURE = "There isn't a GitHub Pages site here."

REQUEST_TIMEOUT_SECONDS = 10


async def verify(hostname: str, session: aiohttp.ClientSession) -> dict:
    """
    Check whether `hostname` shows GitHub Pages' "site not found" signature.

    Returns a dict:
        {
            "hostname": str,
            "reachable": bool,     # did we get any HTTP response at all?
            "status_code": int | None,
            "signature_found": bool,
            "verdict": "DANGLING" | "ACTIVE" | "UNREACHABLE",
        }

    We try HTTPS first, then fall back to HTTP, since not every dangling
    subdomain will have a valid TLS cert (in fact, a broken/absent cert
    on an otherwise-live CNAME is itself a secondary hint something's off,
    though we don't use that as a scoring signal here - the SIGNATURE
    string is the only thing we treat as authoritative).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
                ssl=False,  # don't fail on self-signed/misconfigured certs - we still want the body
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="ignore")
                signature_found = SIGNATURE in body

                return {
                    "hostname": hostname,
                    "reachable": True,
                    "status_code": resp.status,
                    "signature_found": signature_found,
                    "verdict": "DANGLING" if signature_found else "ACTIVE",
                }
        except (aiohttp.ClientError, TimeoutError, OSError):
            # Try the next scheme (http after https fails) before giving up.
            continue

    # Neither https nor http worked at all.
    return {
        "hostname": hostname,
        "reachable": False,
        "status_code": None,
        "signature_found": False,
        "verdict": "UNREACHABLE",
    }


# Quick manual test hook, same pattern as the other modules.
if __name__ == "__main__":
    import asyncio
    import sys

    async def _demo():
        test_hosts = sys.argv[1:] or ["adenfatima.github.io"]
        # ThreadedResolver avoids a Windows-specific issue where aiodns
        # (used automatically by aiohttp when installed) fails to read
        # the system's configured DNS servers correctly.
        connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            for host in test_hosts:
                result = await verify(host, session)
                print("=" * 60)
                print(f"Hostname       : {result['hostname']}")
                print(f"Reachable      : {result['reachable']}")
                print(f"Status Code    : {result['status_code']}")
                print(f"Signature Found: {result['signature_found']}")
                print(f"Verdict        : {result['verdict']}")
                print("=" * 60)

    asyncio.run(_demo())