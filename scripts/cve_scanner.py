#!/usr/bin/env python3
"""
RetailShield — CVE Vulnerability Scanner
Scans a simulated retail infrastructure asset inventory against a
curated database of retail-specific CVEs.

Usage:
    python cve_scanner.py [--mode quick|deep] [--output text|json] [--dry-run]

Requires: Python 3.9+ (stdlib only, no third-party dependencies)
"""

import json
import sys
import argparse
import os
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
CVE_DB_PATH = SCRIPT_DIR / "cve_database.json"
OUTPUT_DIR = SCRIPT_DIR.parent / "scan-results"

# ── ANSI colour codes ──────────────────────────────────────────────────────────
COLOURS = {
    "red":      "\033[91m",
    "orange":   "\033[93m",
    "yellow":   "\033[33m",
    "green":    "\033[92m",
    "blue":     "\033[94m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "reset":    "\033[0m",
}

SEV_COLOUR = {
    "critical": COLOURS["red"],
    "high":     COLOURS["orange"],
    "medium":   COLOURS["yellow"],
    "low":      COLOURS["green"],
}

# ── Simulated retail asset inventory ──────────────────────────────────────────
ASSETS = [
    # POS Systems
    {"id": "POS-TILL-01", "product": "Oracle Xstore POS",
     "version": "8.1",  "location": "Hounslow Branch",    "cat": "pos"},
    {"id": "POS-TILL-03", "product": "NCR Aloha POS",
     "version": "12.3", "location": "Hammersmith Branch", "cat": "pos"},
    {"id": "POS-TILL-05", "product": "Toshiba TCx POS",
     "version": "5.2",  "location": "Ealing Branch",      "cat": "pos"},
    {"id": "POS-TILL-06", "product": "Verifone POS",
     "version": "3.4",  "location": "Ealing Branch",      "cat": "pos"},
    # Stock Management
    {"id": "ERP-DYN-01",  "product": "Microsoft Dynamics Retail",
     "version": "10.0.28", "location": "Head Office",     "cat": "stock"},
    {"id": "ERP-ORA-01",  "product": "Oracle Retail Merchandising",
     "version": "21.0",    "location": "Head Office",     "cat": "stock"},
    {"id": "ERP-SAP-01",  "product": "SAP Retail",
     "version": "S/4HANA 2021", "location": "Head Office", "cat": "stock"},
    {"id": "ERP-JDA-01",  "product": "JDA Supply Chain",
     "version": "9.2",    "location": "Head Office",      "cat": "stock"},
    # Payment Terminals
    {"id": "TERM-VFN-01", "product": "Verifone VX520",
     "version": "2.1.0", "location": "Hounslow Branch",   "cat": "terminal"},
    {"id": "TERM-PAX-01", "product": "PAX S920",
     "version": "1.2",   "location": "Hounslow Branch",   "cat": "terminal"},
    {"id": "TERM-ING-01", "product": "Ingenico iCT250",
     "version": "6.0.0", "location": "Ealing Branch",     "cat": "terminal"},
    {"id": "TERM-VFN-02", "product": "Verifone P400",
     "version": "3.0.1", "location": "Hammersmith Branch", "cat": "terminal"},
    # Retail Platforms
    {"id": "PLAT-SHP-01", "product": "Shopify POS",
     "version": "9.1.0", "location": "Online",            "cat": "platform"},
    {"id": "PLAT-SQR-01", "product": "Square POS",
     "version": "5.28",  "location": "Online",            "cat": "platform"},
    {"id": "PLAT-LSP-01", "product": "Lightspeed Retail",
     "version": "2024.1", "location": "Online",           "cat": "platform"},
    {"id": "PLAT-RVL-01", "product": "Revel POS",
     "version": "4.7",   "location": "Online",            "cat": "platform"},
    # Network Infrastructure
    {"id": "NET-FW-01",   "product": "Cisco ASA Firewall",
     "version": "9.16",  "location": "Head Office",       "cat": "network"},
    {"id": "NET-SW-01",   "product": "Cisco Catalyst Switch",
     "version": "16.12", "location": "Hounslow Branch",   "cat": "network"},
]

QUICK_CATEGORIES = {"pos", "terminal"}


def load_cve_database(path):
    if not os.path.exists(path):
        print(f"[ERROR] CVE database not found at: {path}", file=sys.stderr)
        print("[ERROR] Ensure cve_database.json is in the scripts/ directory.",
              file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def match_product(asset_product, cve_product):
    """Return True if the CVE product name is contained within the asset product name."""
    return cve_product.lower() in asset_product.lower()


def scan_asset(asset, cve_db):
    """Return list of matching CVEs for a given asset."""
    findings = []
    for entry in cve_db:
        if match_product(asset["product"], entry["product"]):
            findings.append(entry)
    return findings


def severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev.lower(), 4)


def print_text_report(results, scan_meta):
    """Print colour-coded terminal report."""
    B = COLOURS["bold"]
    R = COLOURS["reset"]
    D = COLOURS["dim"]

    print(f"\n{B}{'=' * 64}{R}")
    print(f"{B}  RETAILSHIELD CVE VULNERABILITY SCANNER{R}")
    print(f"{B}{'=' * 64}{R}")
    print(f"  Scan mode : {scan_meta['mode']}")
    print(f"  Timestamp : {scan_meta['timestamp']}")
    print(f"  Assets    : {scan_meta['assets_scanned']}")
    print(f"  CVE DB    : {scan_meta['cve_db_size']} entries")
    print(f"{B}{'=' * 64}{R}\n")

    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for item in results:
        asset = item["asset"]
        findings = item["findings"]
        if not findings:
            print(f"{D}  [{asset['id']}] {asset['product']} v{asset['version']} — No CVEs found{R}")
            continue

        sev_label = findings[0]["severity"].upper()
        sev_col = SEV_COLOUR.get(findings[0]["severity"], "")
        print(f"\n{sev_col}{B}  [{asset['id']}] {asset['product']} "
              f"v{asset['version']} — {sev_label}{R}")
        print(f"  Location: {asset['location']}")

        for cve in findings:
            sev = cve["severity"]
            col = SEV_COLOUR.get(sev, "")
            exploit_flag = f" {COLOURS['red']}[EXPLOIT AVAILABLE]{R}" if cve.get("exploit") else ""
            print(f"\n    {col}{B}{cve['cve_id']}{R} — CVSS {cve['cvss_score']} "
                  f"({sev.upper()}){exploit_flag}")
            print(f"    {cve['title']}")
            print(f"    {D}MITRE: {cve.get('mitre_technique', 'N/A')} — "
                  f"Patch: {'Available' if cve.get('patch_available') else 'None'}{R}")
            total_vulns += 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n{B}{'=' * 64}{R}")
    print(f"{B}  SUMMARY{R}")
    print(f"{'=' * 64}")
    for sev in ["critical", "high", "medium", "low"]:
        col = SEV_COLOUR.get(sev, "")
        n = severity_counts[sev]
        bar = "#" * min(n, 40)
        print(f"  {col}{sev.upper():8s}{R}  {n:3d}  {col}{bar}{R}")
    print(f"  {'TOTAL':8s}  {total_vulns:3d}")
    print(f"{B}{'=' * 64}{R}\n")


def build_json_output(results, scan_meta):
    """Build JSON-serialisable output dict."""
    output = {
        "scan_metadata": scan_meta,
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
    }
    for item in results:
        if not item["findings"]:
            continue
        output["findings"].append({
            "asset_id": item["asset"]["id"],
            "product": item["asset"]["product"],
            "version": item["asset"]["version"],
            "location": item["asset"]["location"],
            "vulnerabilities": item["findings"],
        })
        for cve in item["findings"]:
            sev = cve["severity"]
            output["summary"][sev] = output["summary"].get(sev, 0) + 1
            output["summary"]["total"] += 1
    return output


def main():
    parser = argparse.ArgumentParser(
        description="RetailShield CVE Vulnerability Scanner"
    )
    parser.add_argument(
        "--mode", choices=["quick", "deep"], default="deep",
        help="quick = POS + terminals only; deep = all categories (default)",
    )
    parser.add_argument(
        "--output", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print to console only — do not write JSON file",
    )
    args = parser.parse_args()

    cve_db = load_cve_database(CVE_DB_PATH)

    assets_to_scan = [
        a for a in ASSETS
        if args.mode == "deep" or a["cat"] in QUICK_CATEGORIES
    ]

    scan_meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "assets_scanned": len(assets_to_scan),
        "cve_db_size": len(cve_db),
    }

    results = []
    for asset in assets_to_scan:
        findings = scan_asset(asset, cve_db)
        findings.sort(key=lambda c: severity_order(c["severity"]))
        results.append({"asset": asset, "findings": findings})

    if args.output == "text":
        print_text_report(results, scan_meta)
    else:
        output = build_json_output(results, scan_meta)
        json_str = json.dumps(output, indent=2)
        if args.dry_run:
            print(json_str)
        else:
            OUTPUT_DIR.mkdir(exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            out_path = OUTPUT_DIR / f"scan_{ts}.json"
            out_path.write_text(json_str, encoding="utf-8")
            print(f"Scan results written to: {out_path}")


if __name__ == "__main__":
    main()
