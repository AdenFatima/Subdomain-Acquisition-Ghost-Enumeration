"""
core/scorer.py

Phase 4: Confidence Scoring Engine.

Takes the combined results from DNS resolution (Phase 1), provider
fingerprinting (Phase 2), and HTTP signature verification (Phase 3),
and assigns a confidence tier - High, Medium, or Low - per the
methodology defined in the project proposal:

    High Confidence:   CNAME confirmed + provider matched + 404 status
                        + exact body signature match
    Medium Confidence: CNAME confirmed + provider matched + error
                        response + partial/ambiguous signature
    Low Confidence:    CNAME confirmed + unusual response + manual
                        review recommended

This module has no network calls of its own - it's pure logic on data
already gathered by the earlier phases, which is why it's fast to
build and safe to run without needing new test infrastructure.
"""

from dataclasses import dataclass
from enum import Enum


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"  # not a candidate at all - no takeover risk to score


@dataclass
class ScoredResult:
    subdomain: str
    confidence: Confidence
    reason: str


# HTTP status codes that are strong, unambiguous "resource doesn't
# exist" signals for most providers. A 404 with a matching signature
# is the strongest possible evidence; other 4xx/5xx codes are treated
# as weaker/ambiguous even alongside a signature match.
STRONG_STATUS_CODES = {404}


def score(
    is_cname_candidate: bool,
    provider_matched: bool,
    http_reachable: bool | None,
    http_status_code: int | None,
    signature_found: bool | None,
    subdomain: str = "",
) -> ScoredResult:
    """
    Assigns a confidence tier based on the combined signals from all
    three earlier phases.

    Parameters mirror what sage.py already collects per subdomain:
      is_cname_candidate : from DNSResult.is_cname_candidate (Phase 1)
      provider_matched    : whether Phase 2 identified a known provider
      http_reachable       : whether Phase 3 could reach the host at all
                              (None if HTTP verification wasn't run,
                              e.g. unknown provider / no verifier yet)
      http_status_code    : the HTTP status code returned, if any
      signature_found      : whether the provider's exact "not found"
                              signature was matched in the response body
    """
    if not is_cname_candidate:
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.NONE,
            reason="Not a CNAME candidate - target still resolves at the DNS level",
        )

    if not provider_matched:
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.LOW,
            reason="CNAME candidate, but provider unknown - manual review recommended",
        )

    if http_reachable is None:
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.LOW,
            reason="Provider identified, but no HTTP verifier implemented yet for this provider - manual review recommended",
        )

    if not http_reachable:
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.LOW,
            reason="Provider identified, but host unreachable over HTTP/HTTPS - manual review recommended",
        )

    if signature_found and http_status_code in STRONG_STATUS_CODES:
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.HIGH,
            reason=f"Exact signature match with status {http_status_code} - high-confidence takeover candidate",
        )

    if signature_found:
        # Signature matched, but on an unusual status code (not a
        # clean 404) - still meaningful, but slightly less certain
        # than the textbook case.
        return ScoredResult(
            subdomain=subdomain,
            confidence=Confidence.MEDIUM,
            reason=f"Signature matched, but on non-standard status {http_status_code} - likely vulnerable, verify manually",
        )

    # Reachable, provider known, but no signature match - probably
    # still active, but flagged low rather than "None" since the DNS
    # candidate signal is still present and providers occasionally
    # change their error page wording (see docs/methodology.md).
    return ScoredResult(
        subdomain=subdomain,
        confidence=Confidence.LOW,
        reason=f"No known signature matched (status {http_status_code}) - likely active, but provider error pages can change; manual spot-check recommended",
    )


# Quick manual test hook, same pattern as the other modules.
if __name__ == "__main__":
    test_cases = [
        # (label, kwargs)
        ("Not a candidate", dict(is_cname_candidate=False, provider_matched=False, http_reachable=None, http_status_code=None, signature_found=None)),
        ("Unknown provider", dict(is_cname_candidate=True, provider_matched=False, http_reachable=None, http_status_code=None, signature_found=None)),
        ("Known provider, no verifier yet", dict(is_cname_candidate=True, provider_matched=True, http_reachable=None, http_status_code=None, signature_found=None)),
        ("Unreachable host", dict(is_cname_candidate=True, provider_matched=True, http_reachable=False, http_status_code=None, signature_found=False)),
        ("High confidence (real GitHub Pages case)", dict(is_cname_candidate=True, provider_matched=True, http_reachable=True, http_status_code=404, signature_found=True)),
        ("Medium confidence (odd status, matched sig)", dict(is_cname_candidate=True, provider_matched=True, http_reachable=True, http_status_code=403, signature_found=True)),
        ("Low confidence (reachable, no match)", dict(is_cname_candidate=True, provider_matched=True, http_reachable=True, http_status_code=200, signature_found=False)),
    ]

    for label, kwargs in test_cases:
        result = score(subdomain=label, **kwargs)
        print("=" * 60)
        print(f"Case          : {label}")
        print(f"Confidence    : {result.confidence.value}")
        print(f"Reason        : {result.reason}")
    print("=" * 60)