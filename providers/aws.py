"""
providers/aws.py - HTTP-level verification for AWS S3.

S3 has two relevant endpoint types with slightly different error bodies:
- REST API endpoints return XML with a <Code>NoSuchBucket</Code> element
- Static website endpoints return an HTML "404 Not Found" page whose body
  also contains the bucket-not-existing message

We check for signatures from both, since dns_engine.py's CNAME target
could be either kind of endpoint.
"""

from providers._base import verify_signatures

SIGNATURES = [
    "NoSuchBucket",
    "The specified bucket does not exist",
]


async def verify(hostname: str, session) -> dict:
    return await verify_signatures(hostname, session, SIGNATURES)


if __name__ == "__main__":
    import asyncio
    import sys
    import aiohttp
    from aiohttp.resolver import ThreadedResolver

    async def _demo():
        test_hosts = sys.argv[1:] or ["this-bucket-should-not-exist-xyz123.s3.amazonaws.com"]
        connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
        async with aiohttp.ClientSession(connector=connector) as session:
            for host in test_hosts:
                result = await verify(host, session)
                print("=" * 60)
                for k, v in result.items():
                    print(f"{k:16}: {v}")
                print("=" * 60)

    asyncio.run(_demo())