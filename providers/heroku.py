"""
providers/heroku.py - HTTP-level verification for Heroku.

Heroku has used a couple of different error page variants over time
when an app name is unclaimed/deleted, so we check for either.
"""

from providers._base import verify_signatures

SIGNATURES = [
    "No such app",
    "There's nothing here, yet.",
]


async def verify(hostname: str, session) -> dict:
    return await verify_signatures(hostname, session, SIGNATURES)


if __name__ == "__main__":
    import asyncio
    import sys
    import aiohttp
    from aiohttp.resolver import ThreadedResolver

    async def _demo():
        test_hosts = sys.argv[1:] or ["this-app-should-not-exist-xyz123.herokuapp.com"]
        connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            for host in test_hosts:
                result = await verify(host, session)
                print("=" * 60)
                for k, v in result.items():
                    print(f"{k:16}: {v}")
                print("=" * 60)

    asyncio.run(_demo())