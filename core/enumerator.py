"""
core/enumerator.py

Phase 6: Subdomain Enumeration.

Takes a single base domain (e.g. "example.com") and discovers real,
existing subdomains, using two methods:

    1. Wordlist-based brute-forcing (always runs) - tries common
       subdomain names from a wordlist file against the base domain,
       checking whether each one resolves at all (any record type).

    2. subfinder integration (optional, auto-detected) - if the
       `subfinder` binary is installed and found on the system PATH,
       it's used for broader passive enumeration (Certificate
       Transparency logs, search engines, etc.). Silently skipped if
       subfinder isn't installed - this keeps the same code working on
       both Windows (no subfinder) and Linux (with subfinder) without
       any code changes.

Output: a deduplicated, sorted list of real subdomains, ready to be
handed to core/dns_engine.py for CNAME/takeover analysis.

The wordlist itself lives in config/subdomains_wordlist.txt (data, not
hardcoded in this file) - anyone can edit that file directly, or supply
a completely different one via the --wordlist CLI flag, without
touching any Python code.
"""

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

import aiodns

if sys.platform == "win32":
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "subdomains_wordlist.txt"
DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
DEFAULT_CONCURRENCY = 100


def load_wordlist(path: Path | None = None) -> list[str]:
    """Loads subdomain name candidates from a wordlist file, one per line."""
    path = path or DEFAULT_WORDLIST_PATH
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


async def _resolves(hostname: str, resolver: aiodns.DNSResolver) -> bool:
    """
    Checks whether `hostname` exists in DNS at all - tries A, AAAA, and
    CNAME in turn. We only care about existence here (does this
    subdomain exist?), not the CNAME chain details - that's
    dns_engine.py's job, which runs afterward on whatever this function
    finds.
    """
    for record_type in ("A", "AAAA", "CNAME"):
        try:
            if hasattr(resolver, "query_dns"):
                await resolver.query_dns(hostname, record_type)
            else:
                await resolver.query(hostname, record_type)
            return True
        except aiodns.error.DNSError:
            continue
    return False


async def brute_force(base_domain: str, wordlist: list[str], concurrency: int = DEFAULT_CONCURRENCY) -> list[str]:
    """
    Tries every word in `wordlist` as a subdomain of `base_domain`,
    concurrently (capped by `concurrency`), and returns the ones that
    actually resolve.
    """
    resolver = aiodns.DNSResolver(nameservers=DEFAULT_NAMESERVERS, timeout=5.0)
    semaphore = asyncio.Semaphore(concurrency)

    async def _check(word: str) -> str | None:
        candidate = f"{word}.{base_domain}"
        async with semaphore:
            try:
                if await _resolves(candidate, resolver):
                    return candidate
            except Exception:
                pass
        return None

    results = await asyncio.gather(*[_check(w) for w in wordlist])
    return [r for r in results if r is not None]


def run_subfinder(base_domain: str, timeout_seconds: int = 60) -> list[str]:
    """
    Runs subfinder (if installed) for passive enumeration and returns
    its results. Returns an empty list - without erroring - if
    subfinder isn't found on this system (e.g. on Windows, where it's
    typically not installed).
    """
    if shutil.which("subfinder") is None:
        return []

    try:
        result = subprocess.run(
            ["subfinder", "-d", base_domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return subdomains
    except (subprocess.SubprocessError, OSError):
        # subfinder is installed but failed to run for some reason -
        # don't let that break the whole enumeration, just skip it.
        return []


async def enumerate_subdomains(
    base_domain: str,
    wordlist_path: Path | None = None,
    use_subfinder: bool = True,
) -> list[str]:
    """
    Main entry point: combines wordlist brute-forcing with optional
    subfinder passive enumeration, deduplicates, and returns a sorted
    list of real subdomains for `base_domain`.
    """
    wordlist = load_wordlist(wordlist_path)

    brute_force_results = await brute_force(base_domain, wordlist)

    subfinder_results = []
    if use_subfinder:
        subfinder_results = run_subfinder(base_domain)

    combined = set(brute_force_results) | set(subfinder_results)
    return sorted(combined)


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python core/enumerator.py <domain> [--wordlist path/to/list.txt] [--no-subfinder]")
        sys.exit(1)

    domain = args[0]
    wordlist_path = None
    use_subfinder = True

    if "--wordlist" in args:
        idx = args.index("--wordlist")
        wordlist_path = Path(args[idx + 1])
    if "--no-subfinder" in args:
        use_subfinder = False

    print(f"Enumerating subdomains for: {domain}")
    print(f"Wordlist: {wordlist_path or DEFAULT_WORDLIST_PATH}")
    print(f"subfinder: {'enabled (if installed)' if use_subfinder else 'disabled'}\n")

    results = asyncio.run(enumerate_subdomains(domain, wordlist_path, use_subfinder))

    print(f"Found {len(results)} subdomain(s):\n")
    for r in results:
        print(f"  {r}")


if __name__ == "__main__":
    main()