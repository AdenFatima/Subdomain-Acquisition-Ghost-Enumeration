"""
reports/html_reporter.py

Phase 5: HTML Reporting.

Renders the same report data used by json_reporter.py into a
human-readable HTML page, using the Jinja2 template at
templates/report_template.html. This is the format suitable for
including directly in a penetration test deliverable, or for opening
in a browser to review findings at a glance.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from reports.json_reporter import build_report_data

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def generate_html_report(target_domain: str, findings: list[dict], output_path: str | Path) -> Path:
    """
    Renders the HTML report and writes it to `output_path`, returning
    the path written to.
    """
    output_path = Path(output_path)
    report_data = build_report_data(target_domain, findings)

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report_template.html")
    html = template.render(**report_data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path