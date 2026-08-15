"""
providers/__init__.py

Phase 2: Cloud Provider Fingerprinting.

This module takes a `final_target` hostname (the end of a CNAME chain,
as produced by core/dns_engine.py) and figures out which cloud provider
it belongs to, by matching it against patterns defined in
config/providers.json.

It does NOT verify whether the resource is actually dangling - that's
Phase 3 (HTTP signature verification), which will live in the individual
providers/github.py, providers/heroku.py, etc. modules. This module's
only job is classification: "which provider's rulebook applies here?"

Design note: provider patterns live in config/providers.json (data),
not hardcoded in this file (code). This means adding support for a new
provider, or tweaking an existing pattern, never requires touching
Python - just editing the JSON file.
"""

import fnmatch
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("sage.providers")

# config/providers.json lives one level up from this file (providers/ -> project root -> config/)
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "providers.json"


@dataclass
class ProviderMatch:
    """
    Result of classifying a hostname.

    provider_id:      internal key, e.g. "github_pages" (used to look up
                       the right verification module in later phases)
    display_name:      human-readable name, e.g. "GitHub Pages" (used in reports)
    matched_pattern:   which pattern in the config actually matched, e.g. "*.github.io"
                       (useful for debugging / showing your work in reports)
    """
    provider_id: str
    display_name: str
    matched_pattern: str


class ProviderRegistry:
    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path or _CONFIG_PATH
        self._providers: dict = self._load_config()

    def _load_config(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Provider config not found at {self.config_path}. "
                "Expected config/providers.json in the project root."
            )
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def classify(self, hostname: str) -> ProviderMatch | None:
        """
        Check `hostname` against every known provider's patterns.
        Returns the first ProviderMatch found, or None if no provider
        matches (this is the "flag for manual review" case your
        proposal calls for - unknown providers are NOT discarded by
        the caller, just not auto-classified).
        """
        hostname = hostname.rstrip(".").lower()

        for provider_id, info in self._providers.items():
            for pattern in info["patterns"]:
                if fnmatch.fnmatch(hostname, pattern.lower()):
                    return ProviderMatch(
                        provider_id=provider_id,
                        display_name=info["display_name"],
                        matched_pattern=pattern,
                    )
        return None

    def classify_many(self, hostnames: list) -> dict:
        """
        Convenience batch version: classify a list of hostnames at once.
        Returns {hostname: ProviderMatch | None}.
        """
        return {host: self.classify(host) for host in hostnames}

    @property
    def known_providers(self) -> list:
        """List of all provider_ids currently loaded from config."""
        return list(self._providers.keys())


# Quick manual test hook, same pattern as dns_engine.py.
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    registry = ProviderRegistry()

    print(f"Loaded {len(registry.known_providers)} providers: {registry.known_providers}\n")

    test_hosts = sys.argv[1:] or [
        "someproject.herokuapp.com",
        "myuser.github.io",
        "mybucket.s3.amazonaws.com",
        "myapp.azurewebsites.net",
        "d1wg1w6p5q8555.cloudfront.net",  # intentionally NOT in our provider list
    ]

    for host in test_hosts:
        result = registry.classify(host)
        print("=" * 60)
        print(f"Target        : {host}")
        if result:
            print(f"Provider      : {result.display_name} ({result.provider_id})")
            print(f"Matched Rule  : {result.matched_pattern}")
        else:
            print("Provider      : UNKNOWN - flag for manual review")
        print("=" * 60)