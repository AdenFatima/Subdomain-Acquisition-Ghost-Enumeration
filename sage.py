#!/usr/bin/env python3
import argparse
import asyncio
import sys
from pathlib import Path
import aiohttp
from aiohttp.resolver import ThreadedResolver

from providers import ProviderRegistry, github, heroku, aws, azure, vercel, netlify
from core.enumerator import enumerate_subdomains
from core.dns_engine import DNSEngine
from core.scorer import score
from reports.json_reporter import generate_json_report
from reports.html_reporter import generate_html_report

# Terminal Colors — Recon Theme
PRIMARY = "\033[38;5;39m"    # Electric Cyan (Banner & Step Indicators)
ALERT   = "\033[38;5;196m"   # Vivid Crimson (High-Risk Takeovers)
MUTED   = "\033[38;5;244m"   # Slate Grey (Headers & Tree lines)
WHITE   = "\033[38;5;255m"   # Pure White (Hosts & Targets)
RESET   = "\033[0m"

# Direct mapping to individual provider verification modules
VERIFIERS = {
    "github_pages": github.verify,
    "heroku": heroku.verify,
    "aws_s3": aws.verify,
    "azure_app_service": azure.verify,
    "vercel": vercel.verify,
    "netlify": netlify.verify,
}

def print_banner():
    """Displays the SAGE ASCII art banner."""
    banner = f"""{PRIMARY}
     _____   ___  ____________ 
    /  ___| / _ \\ |  __  |  ___|
    \\ `--. / /_\\ \\| |  \\/| |__  
     `--. \\|  _  || | __ |  __| 
    /\\__/ /| | | || |_\\ \\| |___ 
    \\____/ \\_| |_/ \\____/\\____/ 
    {MUTED}Subdomain Acquisition & Ghost Enumeration Framework{RESET}
    """
    print(banner)

async def process_subdomain(subdomain: str, dns_engine: DNSEngine, provider_registry: ProviderRegistry, session: aiohttp.ClientSession) -> dict:
    """Pipelines a single subdomain through DNS analysis, fingerprinting, HTTP checks, and scoring."""
    dns_res = await dns_engine._follow_chain(subdomain)
    
    provider_match = None
    http_data = {"reachable": None, "status_code": None, "signature_found": None}

    # Phase 2 & 3: Match provider and verify HTTP signature if dangling candidate
    if dns_res.is_cname_candidate and dns_res.final_target:
        provider_match = provider_registry.classify(dns_res.final_target)
        
        if provider_match and provider_match.provider_id in VERIFIERS:
            verify_func = VERIFIERS[provider_match.provider_id]
            # Use the original subdomain for the request, NOT the CNAME target
            http_data = await verify_func(subdomain, session)

    # Phase 4: Confidence Scoring
    scored = score(
        is_cname_candidate=dns_res.is_cname_candidate,
        provider_matched=bool(provider_match),
        http_reachable=http_data.get("reachable"),
        http_status_code=http_data.get("status_code"),
        signature_found=http_data.get("signature_found"),
        subdomain=subdomain,
    )

    return {
        "subdomain": subdomain,
        "is_candidate": dns_res.is_cname_candidate,
        "final_target": dns_res.final_target,
        "provider": provider_match.display_name if provider_match else None,
        "http_status_code": http_data.get("status_code"),
        "confidence": scored.confidence.value,
        "reason": scored.reason,
    }

async def run_sage(domain: str, wordlist: Path | None, use_subfinder: bool, json_path: Path | None, html_path: Path | None):
    print_banner()
    
    print(f"{MUTED}[*]{RESET} Target Domain : {WHITE}{domain}{RESET}")
    print(f"{MUTED}[*]{RESET} Subfinder     : {WHITE}{'Enabled' if use_subfinder else 'Disabled'}{RESET}")
    print(f"{MUTED}[*]{RESET} Wordlist      : {WHITE}{wordlist or 'Default (config/subdomains_wordlist.txt)'}{RESET}\n")
    
    # Phase 1: Subdomain Enumeration
    print(f"{PRIMARY}[+]{RESET} Phase 1/5: Discovering subdomains...")
    subdomains = await enumerate_subdomains(
        base_domain=domain,
        wordlist_path=wordlist,
        use_subfinder=use_subfinder,
    )
    print(f"    {MUTED}└─{RESET} Total active subdomains identified: {WHITE}{len(subdomains)}{RESET}\n")

    if not subdomains:
        print(f"{MUTED}[-]{RESET} No subdomains found to analyze. Exiting.")
        return

    dns_engine = DNSEngine()
    
    print(f"{PRIMARY}[+]{RESET} Checking for wildcard DNS configurations...")
    if await dns_engine.detect_wildcard(domain):
        print(f"{ALERT}[!] Wildcard DNS detected for {domain}. This may result in false-positive flooding.{RESET}\n")

    provider_registry = ProviderRegistry()

    # Phases 2-4: DNS -> Fingerprint -> HTTP -> Scorer
    print(f"{PRIMARY}[+]{RESET} Phase 2-4/5: Running DNS resolution, fingerprinting, and HTTP verification...")
    
    # Use ThreadedResolver to prevent silent connection drops on Windows
    connector = aiohttp.TCPConnector(resolver=ThreadedResolver())
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [process_subdomain(sd, dns_engine, provider_registry, session) for sd in subdomains]
        findings = await asyncio.gather(*tasks)

    # Phase 5: Summarize and Report
    candidates = [f for f in findings if f["is_candidate"]]
    print(f"    {MUTED}└─{RESET} Scan complete. {WHITE}{len(candidates)}{RESET} potential dangling targets detected.\n")

    if candidates:
        print(f"{ALERT}[!] Takeover Vulnerability Report:{RESET}")
        for candidate in candidates:
            risk_color = ALERT if candidate['confidence'] == 'High' else MUTED
            
            print(f"  {risk_color}►{RESET} {WHITE}{candidate['subdomain']}{RESET}")
            print(f"    {MUTED}├─ Target:{RESET} {candidate['final_target']} ({candidate['provider']})")
            print(f"    {MUTED}└─ Risk:  {RESET} {risk_color}{candidate['confidence']} Risk{RESET} - {candidate['reason']}\n")

    if json_path:
        out_json = generate_json_report(domain, findings, json_path)
        print(f"{MUTED}[*] JSON Report saved to: {out_json}{RESET}")

    if html_path:
        out_html = generate_html_report(domain, findings, html_path)
        print(f"{MUTED}[*] HTML Report saved to: {out_html}{RESET}")

def cli():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="sage",
        description="SAGE — Subdomain Acquisition & Ghost Enumeration Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", type=Path, default=None, help="Path to custom subdomain wordlist")
    parser.add_argument("--no-subfinder", action="store_true", help="Disable passive Subfinder discovery")
    parser.add_argument("--json", type=Path, default=None, help="Save structured report to JSON file")
    parser.add_argument("--html", type=Path, default=None, help="Save styled report to HTML file")

    args = parser.parse_args()

    # Ensure Windows uses the correct asyncio event loop policy for aiodns
    if sys.platform == "win32":
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(
        run_sage(
            domain=args.domain,
            wordlist=args.wordlist,
            use_subfinder=not args.no_subfinder,
            json_path=args.json,
            html_path=args.html,
        )
    )

if __name__ == "__main__":
    cli()