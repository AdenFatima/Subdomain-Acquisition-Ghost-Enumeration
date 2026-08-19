"""
core package

Contains the core resolution, enumeration, and scoring engines for SAGE.
"""

from core.dns_engine import DNSEngine, DNSResult
from core.enumerator import enumerate_subdomains
from core.scorer import score, Confidence, ScoredResult

__all__ = [
    "DNSEngine",
    "DNSResult",
    "enumerate_subdomains",
    "score",
    "Confidence",
    "ScoredResult",
]