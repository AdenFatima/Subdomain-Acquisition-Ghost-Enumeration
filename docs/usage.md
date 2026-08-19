# SAGE Usage Guide

SAGE is a fully automated CLI tool designed for Kali Linux and Windows environments.

## Basic Execution
Run SAGE against a target domain using the default internal wordlist and Subfinder passive enumeration.
```bash
sage -d example.com
sage -d example.com -w /usr/share/wordlists/amass/subdomains.txt
sage -d example.com --no-subfinder
sage -d example.com --json report.json --html full_report.html