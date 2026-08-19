"""
core/dns_engine.py

Async DNS resolution engine for SAGE.

Responsibilities:
    1. Resolve a list of subdomains concurrently (using asyncio + aiodns).
    2. For each subdomain, determine if it has a CNAME record.
    3. Follow CNAME chains to their final target.
    4. Discard subdomains that only have A/AAAA records (not takeover candidates).
    5. Detect wildcard DNS on the parent domain, so we don't chase false positives.

Output of this module feeds Phase 3 (Provider Identification).
"""

import asyncio
import random
import string
import sys
import warnings
import logging
from dataclasses import dataclass, field

import aiodns

# aiodns (via pycares) does not work with asyncio's default "Proactor"
# event loop on Windows. This switches to the "Selector" loop, which does
# work. This line does nothing on Linux/Mac, so it's safe to always run.
# (The DeprecationWarning it raises on newer Python is harmless - we just
# don't want it cluttering scan output, so we suppress it.)
if sys.platform == "win32":
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger("sage.dns_engine")

# Safety limit: if a CNAME chain is longer than this, something is
# misconfigured (or looping) - we stop following it rather than hang forever.
MAX_CNAME_CHAIN_DEPTH = 8

# How many DNS lookups we allow to run at the same time. Too high and we
# risk getting rate-limited or overwhelming the resolver; too low and
# scanning thousands of subdomains gets slow.
DEFAULT_CONCURRENCY = 50


@dataclass
class DNSResult:
    """
    Holds the outcome of resolving a single subdomain.

    subdomain:      the hostname we looked up, e.g. "blog.company.com"
    cname_chain:    ordered list of CNAME hops, e.g.
                    ["blog.company.com", "old-project.herokuapp.com"]
                    Empty list means no CNAME was found (A/AAAA only, or NXDOMAIN).
    final_target:   the last hostname in the CNAME chain (what we'll fingerprint
                    against known providers in Phase 3). None if there's no CNAME.
    has_a_record:   True if the subdomain (or the end of its CNAME chain)
                    also resolves to an A/AAAA record. If it does, the
                    service is still "live" at the DNS level, which changes
                    how we interpret the result later.
    error:          set if resolution failed outright (NXDOMAIN, timeout, etc.)
    """
    subdomain: str
    cname_chain: list = field(default_factory=list)
    final_target: str | None = None
    has_a_record: bool = False
    error: str | None = None

    @property
    def is_cname_candidate(self) -> bool:
        """
        True if this subdomain has a CNAME pointing somewhere.
        We do NOT check self.has_a_record here because shared providers 
        (like GitHub/Netlify) keep their IPs active even when dangling.
        """
        return bool(self.final_target)

# Reliable public resolvers used as a fallback. On some systems (notably
# Windows), the underlying c-ares library fails to correctly read the
# OS's configured DNS servers, which causes lookups to silently fail
# (returning "no record found" even for domains that definitely have one).
# Pinning explicit resolvers avoids that whole class of problem, and is
# also just good practice for a recon tool (consistent results regardless
# of what network/DNS config the operator's machine has).
DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


class DNSEngine:
    def __init__(
        self,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = 5.0,
        nameservers: list | None = None,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        # aiodns.DNSResolver wraps c-ares, which is what makes this async
        # and fast even with hundreds/thousands of subdomains.
        self.resolver = aiodns.DNSResolver(
            timeout=timeout,
            nameservers=nameservers or DEFAULT_NAMESERVERS,
        )

    async def _query(self, host: str, record_type: str):
        """
        Thin wrapper so we use the modern aiodns API (query_dns) when it's
        available, but still work on older aiodns versions that only have
        query(). Keeps the rest of the engine agnostic to this detail.
        """
        if hasattr(self.resolver, "query_dns"):
            return await self.resolver.query_dns(host, record_type)
        return await self.resolver.query(host, record_type)

    async def _resolve_cname(self, host: str) -> str | None:
        """Look up a single CNAME record. Returns the target hostname, or None."""
        try:
            answer = await self._query(host, "CNAME")
            # New query_dns() API: answer.answer is a list of records,
            # each with a .data object holding the actual field (e.g. .cname).
            if hasattr(answer, "answer"):
                records = answer.answer
                if not records:
                    return None
                return records[0].data.cname.rstrip(".")
            # Legacy query() API: answer has .cname directly.
            return answer.cname.rstrip(".")
        except aiodns.error.DNSError:
            # No CNAME record (could be NXDOMAIN, or it's an A record instead) — that's fine, not an error for us.
            return None

    async def _resolve_a_or_aaaa(self, host: str) -> bool:
        """Check whether a host resolves to an A or AAAA record. Returns True/False."""
        for record_type in ("A", "AAAA"):
            try:
                answer = await self._query(host, record_type)
                # New API returns an answer list - as long as it's non-empty,
                # the record exists. Legacy API just returning without
                # raising is enough confirmation on its own.
                if hasattr(answer, "answer"):
                    if answer.answer:
                        return True
                    continue
                return True
            except aiodns.error.DNSError:
                continue
        return False

    async def _follow_chain(self, subdomain: str) -> DNSResult:
        """
        Starting from `subdomain`, follow CNAME hops one at a time until:
          - we hit a host with no further CNAME (this is our final_target), or
          - we hit MAX_CNAME_CHAIN_DEPTH (safety stop), or
          - the very first lookup has no CNAME at all (not a candidate).
        """
        chain = []
        current = subdomain

        for _ in range(MAX_CNAME_CHAIN_DEPTH):
            next_hop = await self._resolve_cname(current)
            if next_hop is None:
                break
            chain.append(next_hop)
            current = next_hop

        if not chain:
            # No CNAME anywhere - check if it's a plain A/AAAA record instead.
            has_a = await self._resolve_a_or_aaaa(subdomain)
            return DNSResult(subdomain=subdomain, has_a_record=has_a)

        final_target = chain[-1]
        # Does the END of the chain still resolve to an IP? If yes, the
        # third-party resource is still alive and this is NOT dangling.
        has_a = await self._resolve_a_or_aaaa(final_target)

        return DNSResult(
            subdomain=subdomain,
            cname_chain=chain,
            final_target=final_target,
            has_a_record=has_a,
        )

    async def resolve_one(self, subdomain: str, semaphore: asyncio.Semaphore) -> DNSResult:
        """Wraps _follow_chain with concurrency control and error handling."""
        async with semaphore:
            try:
                return await self._follow_chain(subdomain)
            except Exception as exc:
                logger.debug(f"Resolution failed for {subdomain}: {exc}")
                return DNSResult(subdomain=subdomain, error=str(exc))

    async def resolve_many(self, subdomains: list[str]) -> list[DNSResult]:
        """
        Main entry point: resolve a whole list of subdomains concurrently.
        A semaphore caps how many run at once so we don't flood the resolver.
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self.resolve_one(sd, semaphore) for sd in subdomains]
        return await asyncio.gather(*tasks)

    async def detect_wildcard(self, base_domain: str) -> bool:
        """
        Wildcard DNS check: query a random, almost-certainly-nonexistent
        subdomain of base_domain. If it resolves anyway, the whole domain
        has wildcard DNS configured, meaning ANY subdomain will "resolve" -
        this would otherwise flood us with false positives, so callers
        should check this before trusting individual results.
        """
        junk_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        probe = f"{junk_label}.{base_domain}"

        cname = await self._resolve_cname(probe)
        if cname is not None:
            return True
        return await self._resolve_a_or_aaaa(probe)


# Quick manual test hook - lets you run this file directly to sanity check
# the engine against a couple of hostnames before wiring it into the CLI.
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    def _print_result(r: "DNSResult"):
        print("=" * 60)
        print(f"Subdomain     : {r.subdomain}")

        if r.error:
            print(f"Status        : ERROR - {r.error}")
            print("=" * 60)
            return

        if not r.cname_chain:
            record_status = "A/AAAA record found (live host)" if r.has_a_record else "No record found (NXDOMAIN)"
            print("CNAME Chain   : none")
            print(f"Record Status : {record_status}")
            print(f"Takeover Risk : N/A (no CNAME present)")
        else:
            print(f"CNAME Chain   : {len(r.cname_chain)} hop(s)")
            hop_source = r.subdomain
            for i, hop in enumerate(r.cname_chain, start=1):
                print(f"    {i}. {hop_source}  ->  {hop}")
                hop_source = hop
            print(f"Final Target  : {r.final_target}")
            print(f"Still Live?   : {'Yes (A/AAAA record exists)' if r.has_a_record else 'No (nothing resolves here)'}")

            if r.is_cname_candidate:
                print("Takeover Risk : ** CANDIDATE - dangling CNAME, worth investigating **")
            else:
                print("Takeover Risk : None (target still resolves)")

        print("=" * 60)

    async def _demo():
        engine = DNSEngine()
        test_hosts = sys.argv[1:] or ["www.google.com", "this-should-not-exist-xyz123.com"]
        results = await engine.resolve_many(test_hosts)
        print(f"\nResolved {len(results)} subdomain(s)\n")
        for r in results:
            _print_result(r)
        candidates = [r for r in results if r.is_cname_candidate]
        print(f"\nSummary: {len(candidates)}/{len(results)} subdomain(s) flagged as CNAME candidates\n")

    asyncio.run(_demo())