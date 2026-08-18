"""
providers/netlify.py - HTTP-level verification for Netlify.
"""

from providers._base import verify_signatures

SIGNATURES = [
    "Not Found - Request ID",
]


async def verify(hostname: str, session) -> dict:
    return await verify_signatures(hostname, session, SIGNATURES)


if __name__ == "__main__":
    import asyncio
    import sys
    import aiohttp
    from aiohttp.resolver import ThreadedResolver

    async def _demo():
        test_hosts = sys.argv[1:] or ["this-site-should-not-exist-xyz123.netlify.app"]
        connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            for host in test_hosts:
                result = await verify(host, session)
                print("=" * 60)
                for k, v in result.items():
                    print(f"{k:16}: {v}")
                print("=" * 60)

    asyncio.run(_demo())