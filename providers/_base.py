"""
providers/_base.py

Shared HTTP-fetch logic used by every provider verification module
(github.py, heroku.py, aws.py, azure.py, vercel.py, netlify.py).

Each provider module just needs to define its own list of SIGNATURES
(the error text specific to that provider) and call verify_signatures()
- this avoids duplicating the same "try https, fall back to http,
handle timeouts/connection errors" logic six times.
"""

import aiohttp

REQUEST_TIMEOUT_SECONDS = 10


async def fetch_body(hostname: str, session: aiohttp.ClientSession) -> dict:
    """
    Fetches the HTTP response body for a hostname, trying HTTPS then
    HTTP. Returns a dict with reachable/status_code/body, or
    reachable=False if neither scheme worked.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
                ssl=False,  # don't fail on self-signed/misconfigured certs
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="ignore")
                return {"reachable": True, "status_code": resp.status, "body": body}
        except (aiohttp.ClientError, TimeoutError, OSError):
            continue

    return {"reachable": False, "status_code": None, "body": ""}


async def verify_signatures(hostname: str, session: aiohttp.ClientSession, signatures: list) -> dict:
    """
    Generic signature-matching verifier: fetches the page, checks the
    body against a list of known "resource doesn't exist" strings for
    a given provider. Matching ANY one of them counts as dangling -
    providers often have multiple historical variants of their error
    page (e.g. Heroku has changed its wording over time).
    """
    fetch_result = await fetch_body(hostname, session)

    if not fetch_result["reachable"]:
        return {
            "hostname": hostname,
            "reachable": False,
            "status_code": None,
            "signature_found": False,
            "matched_signature": None,
            "verdict": "UNREACHABLE",
        }

    body = fetch_result["body"]
    matched = next((sig for sig in signatures if sig in body), None)

    return {
        "hostname": hostname,
        "reachable": True,
        "status_code": fetch_result["status_code"],
        "signature_found": matched is not None,
        "matched_signature": matched,
        "verdict": "DANGLING" if matched else "ACTIVE",
    }