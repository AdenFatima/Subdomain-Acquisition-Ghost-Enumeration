"""
reports/json_reporter.py

Phase 5: JSON Reporting.

Takes a list of finding dicts (one per scanned subdomain, combining
results from all earlier phases) and writes a structured JSON report.
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