"""
providers/github.py
Phase 3: HTTP-level verification for GitHub Pages.
"""
from providers._base import verify_signatures

SIGNATURES = [
    "There isn't a GitHub Pages site here."
]

async def verify(hostname: str, session) -> dict:
    return await verify_signatures(hostname, session, SIGNATURES)