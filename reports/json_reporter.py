"""
reports/json_reporter.py

Phase 5: JSON Reporting.

Takes a list of finding dicts (one per scanned subdomain, combining
results from all earlier phases) and writes a structured JSON report -
suitable for feeding into other tools, or as a raw-data appendix in a
pentest deliverable.

Each finding dict is expected to look like:
    {
        "subdomain": "sagetest.insighthubtech.com",
        "is_candidate": True,
        "final_target": "adenfatima.github.io",
        "provider": "GitHub Pages",              # or None
        "http_status_code": 404,                  # or None
        "confidence": "High",                     # "High" / "Medium" / "Low" / "None"
        "reason": "Exact signature match with status 404 - high-confidence takeover candidate",
    }

This module doesn't care HOW that dict was built (whether from sage.py,
or manually for testing) - it just needs that shape, which keeps it
decoupled from the rest of the pipeline and independently testable.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def build_report_data(target_domain: str, findings: list[dict]) -> dict:
    """
    Assembles the full report structure: metadata + findings, with
    findings grouped by confidence level for quick scanning.
    """
    candidates = [f for f in findings if f.get("is_candidate")]

    by_confidence = {"High": [], "Medium": [], "Low": [], "None": []}
    for f in findings:
        level = f.get("confidence", "None")
        by_confidence.setdefault(level, []).append(f)

    provider_counts = {}
    for f in candidates:
        provider = f.get("provider") or "Unknown"
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

    return {
        "metadata": {
            "target_domain": target_domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_subdomains_scanned": len(findings),
            "cname_candidates_found": len(candidates),
            "findings_by_confidence": {
                level: len(items) for level, items in by_confidence.items()
            },
            "provider_breakdown": provider_counts,
        },
        "findings": findings,
    }


def generate_json_report(target_domain: str, findings: list[dict], output_path: str | Path) -> Path:
    """
    Writes the report to `output_path` as formatted JSON and returns
    the path written to.
    """
    output_path = Path(output_path)
    report_data = build_report_data(target_domain, findings)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return output_path


# Quick manual test hook using realistic sample data, mirroring the
# real validated GitHub Pages / Netlify findings from earlier phases.
if __name__ == "__main__":
    sample_findings = [
        {
            "subdomain": "sagetest.insighthubtech.com",
            "is_candidate": True,
            "final_target": "adenfatima.github.io",
            "provider": "GitHub Pages",
            "http_status_code": 404,
            "confidence": "High",
            "reason": "Exact signature match with status 404 - high-confidence takeover candidate",
        },
        {
            "subdomain": "netlifytest.insighthubtech.com",
            "is_candidate": True,
            "final_target": "dreamy-granita-b16a1c.netlify.app",
            "provider": "Netlify",
            "http_status_code": 404,
            "confidence": "High",
            "reason": "Exact signature match with status 404 - high-confidence takeover candidate",
        },
        {
            "subdomain": "dev.insighthubtech.com",
            "is_candidate": False,
            "final_target": None,
            "provider": None,
            "http_status_code": None,
            "confidence": "None",
            "reason": "Not a CNAME candidate - target still resolves at the DNS level",
        },
    ]

    out_path = generate_json_report("insighthubtech.com", sample_findings, "sample_report.json")
    print(f"Report written to: {out_path}")
    print(json.dumps(build_report_data("insighthubtech.com", sample_findings)["metadata"], indent=2))