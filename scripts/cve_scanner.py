"""
RetailShield — Retail CVE Vulnerability Scanner
ShieldTech Ltd | Tanvir Farhad | 2026
github.com/TFT444/RetailShield

Scans simulated retail infrastructure against a retail-specific CVE database.
Identifies known vulnerabilities in POS systems, payment terminals, stock
management platforms, and retail applications before attackers exploit them.

Usage:
  python cve_scanner.py --mode deep --output text
  python cve_scanner.py --mode quick --output json
  python cve_scanner.py --dry-run
  python cve_scanner.py --mode deep --output json --out-file report.json
"""

import argparse
import datetime
import json
import os
import sys

CVE_DATABASE_PATH = os.path.join(os.path.dirname(__file__), "cve_database.json")

RETAIL_ASSETS = [
    # ── POS Systems ──────────────────────────────────────────────────────────
    {
        "asset_id": "POS-TILL-01", "product": "Oracle Xstore POS", "vendor": "Oracle",
        "version": "8.1", "category": "pos_system",
        "location": "Hounslow Branch", "ip": "10.1.1.101",
    },
    {
        "asset_id": "POS-TILL-02", "product": "Oracle Xstore POS", "vendor": "Oracle",
        "version": "8.1", "category": "pos_system",
        "location": "Hounslow Branch", "ip": "10.1.1.102",
    },
    {
        "asset_id": "POS-TILL-03", "product": "NCR Aloha POS", "vendor": "NCR",
        "version": "12.3", "category": "pos_system",
        "location": "Hammersmith Branch", "ip": "10.2.1.101",
    },
    {
        "asset_id": "POS-TILL-04", "product": "NCR Aloha POS", "vendor": "NCR",
        "version": "12.3", "category": "pos_system",
        "location": "Hammersmith Branch", "ip": "10.2.1.102",
    },
    {
        "asset_id": "POS-TILL-05", "product": "Toshiba TCx POS", "vendor": "Toshiba",
        "version": "5.2", "category": "pos_system",
        "location": "Ealing Branch", "ip": "10.3.1.101",
    },
    {
        "asset_id": "POS-TILL-06", "product": "Verifone POS", "vendor": "Verifone",
        "version": "3.4", "category": "pos_system",
        "location": "Ealing Branch", "ip": "10.3.1.102",
    },
    # ── Stock Management ─────────────────────────────────────────────────────
    {
        "asset_id": "ERP-SAP-01", "product": "SAP Retail", "vendor": "SAP",
        "version": "S/4HANA 2021", "category": "stock_management",
        "location": "Head Office", "ip": "10.0.1.10",
    },
    {
        "asset_id": "ERP-DYN-01", "product": "Microsoft Dynamics Retail", "vendor": "Microsoft",
        "version": "10.0.28", "category": "stock_management",
        "location": "Head Office", "ip": "10.0.1.11",
    },
    {
        "asset_id": "ERP-ORA-01", "product": "Oracle Retail Merchandising", "vendor": "Oracle",
        "version": "21.0", "category": "stock_management",
        "location": "Head Office", "ip": "10.0.1.12",
    },
    {
        "asset_id": "ERP-JDA-01", "product": "JDA Supply Chain", "vendor": "JDA",
        "version": "9.2", "category": "stock_management",
        "location": "Head Office", "ip": "10.0.1.13",
    },
    # ── Payment Terminals ────────────────────────────────────────────────────
    {
        "asset_id": "TERM-VFN-01", "product": "Verifone VX520", "vendor": "Verifone",
        "version": "2.1.0", "category": "payment_terminal",
        "location": "Hounslow Branch", "ip": "10.1.2.10",
    },
    {
        "asset_id": "TERM-VFN-02", "product": "Verifone P400", "vendor": "Verifone",
        "version": "3.0.1", "category": "payment_terminal",
        "location": "Hammersmith Branch", "ip": "10.2.2.10",
    },
    {
        "asset_id": "TERM-ING-01", "product": "Ingenico iCT250", "vendor": "Ingenico",
        "version": "6.0.0", "category": "payment_terminal",
        "location": "Ealing Branch", "ip": "10.3.2.10",
    },
    {
        "asset_id": "TERM-PAX-01", "product": "PAX S920", "vendor": "PAX",
        "version": "1.2", "category": "payment_terminal",
        "location": "Hounslow Branch", "ip": "10.1.2.11",
    },
    # ── Retail Platforms ─────────────────────────────────────────────────────
    {
        "asset_id": "PLAT-SHP-01", "product": "Shopify POS", "vendor": "Shopify",
        "version": "9.1.0", "category": "retail_platform",
        "location": "Online", "ip": "N/A",
    },
    {
        "asset_id": "PLAT-SQR-01", "product": "Square POS", "vendor": "Square",
        "version": "5.28", "category": "retail_platform",
        "location": "Online", "ip": "N/A",
    },
    {
        "asset_id": "PLAT-LSP-01", "product": "Lightspeed Retail", "vendor": "Lightspeed",
        "version": "2024.1", "category": "retail_platform",
        "location": "Online", "ip": "N/A",
    },
    {
        "asset_id": "PLAT-RVL-01", "product": "Revel POS", "vendor": "Revel",
        "version": "4.7", "category": "retail_platform",
        "location": "Online", "ip": "N/A",
    },
]

QUICK_CATEGORIES = {"pos_system", "payment_terminal"}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOURS = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[93m",   # yellow
    "medium":   "\033[94m",   # blue
    "low":      "\033[92m",   # green
    "reset":    "\033[0m",
}


def load_cve_database(path):
    if not os.path.exists(path):
        print(f"[ERROR] CVE database not found at: {path}", file=sys.stderr)
        print("[ERROR] Ensure cve_database.json is in the same directory as cve_scanner.py.", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def match_product(asset_product, cve_product):
    """Return True if the CVE product name is contained within the asset product name."""
    return cve_product.lower() in asset_product.lower()


def scan_asset(asset, cve_db):
    """Return list of CVE dicts that match this asset's product and version."""
    matches = []
    for cve in cve_db["cves"]:
        if match_product(asset["product"], cve["product"]):
            if asset["version"] in cve["affected_versions"]:
                matches.append(cve)
    matches.sort(key=lambda c: SEV_ORDER.get(c["severity"], 99))
    return matches


def run_scan(mode, cve_db, dry_run=False):
    """Scan RETAIL_ASSETS against the CVE database and return a structured report."""
    scan_id = datetime.datetime.utcnow().strftime("RS-SCAN-%Y%m%d-%H%M%S")
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    assets_to_scan = [
        a for a in RETAIL_ASSETS
        if mode == "deep" or a["category"] in QUICK_CATEGORIES
    ]

    findings = []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for asset in assets_to_scan:
        vulns = scan_asset(asset, cve_db)
        if vulns:
            for v in vulns:
                sev = v.get("severity", "low")
                summary[sev] = summary.get(sev, 0) + 1
            findings.append({
                "asset_id":        asset["asset_id"],
                "product":         asset["product"],
                "vendor":          asset["vendor"],
                "version":         asset["version"],
                "location":        asset["location"],
                "ip":              asset["ip"],
                "category":        asset["category"],
                "vuln_count":      len(vulns),
                "vulnerabilities": vulns,
            })

    total_vulns = sum(summary.values())

    return {
        "scan_id":             scan_id,
        "timestamp":           timestamp,
        "mode":                mode,
        "dry_run":             dry_run,
        "total_assets":        len(RETAIL_ASSETS),
        "assets_scanned":      len(assets_to_scan),
        "assets_vulnerable":   len(findings),
        "vulnerabilities_found": total_vulns,
        "summary":             summary,
        "findings":            findings,
    }


def _sev_colour(severity):
    return SEV_COLOURS.get(severity, "") + severity.upper() + SEV_COLOURS["reset"]


def print_text_report(report):
    """Print a human-readable scan report to stdout."""
    sep = "─" * 72

    print()
    print("╔" + "═" * 70 + "╗")
    print("║  RetailShield CVE Vulnerability Scanner — Scan Report             ║")
    print("║  ShieldTech Ltd · Tanvir Farhad · 2026                            ║")
    print("╚" + "═" * 70 + "╝")
    print()
    print(f"  Scan ID    : {report['scan_id']}")
    print(f"  Timestamp  : {report['timestamp']}")
    print(f"  Mode       : {report['mode'].upper()}")
    print(f"  Assets     : {report['assets_scanned']} scanned / {report['total_assets']} total")
    print(f"  Vulnerable : {report['assets_vulnerable']} assets")
    print(f"  CVEs found : {report['vulnerabilities_found']}")
    print()

    s = report["summary"]
    print("  Severity Breakdown:")
    print(f"    {_sev_colour('critical'):30s} {s.get('critical', 0):>3}")
    print(f"    {_sev_colour('high'):30s} {s.get('high', 0):>3}")
    print(f"    {_sev_colour('medium'):30s} {s.get('medium', 0):>3}")
    print(f"    {_sev_colour('low'):30s} {s.get('low', 0):>3}")
    print()

    if not report["findings"]:
        print("  No vulnerabilities found.")
        return

    print(sep)
    print(f"  {'ASSET ID':<22} {'PRODUCT':<32} {'CVEs':>4}")
    print(sep)

    for finding in report["findings"]:
        print(
            f"  {finding['asset_id']:<22} {finding['product']:<32} "
            f"{finding['vuln_count']:>4}"
        )
        for cve in finding["vulnerabilities"]:
            sev_label = _sev_colour(cve["severity"])
            patch = "✓ Patch available" if cve.get("patch_available") else "✗ No patch"
            exploit = " [EXPLOIT PUBLIC]" if cve.get("exploit_available") else ""
            print(
                f"    {cve['cve_id']:<20} CVSS {cve['cvss_score']:<5} "
                f"{sev_label:<20} {patch}{exploit}"
            )
            print(f"    MITRE: {cve['mitre_technique']} — {cve['mitre_tactic']}")
            print(f"    {cve['description'][:90]}...")
            print()

    print(sep)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="RetailShield CVE Vulnerability Scanner — ShieldTech Ltd"
    )
    parser.add_argument(
        "--mode",
        choices=["quick", "deep"],
        default="deep",
        help="quick: POS + payment terminals only | deep: all categories (default)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format: text (default) or json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run scan and print first 3 findings to console; do not write any file",
    )
    parser.add_argument(
        "--out-file",
        default="cve_report.json",
        help="Output filename for JSON mode (default: cve_report.json)",
    )
    args = parser.parse_args()

    print("RetailShield CVE Scanner — ShieldTech Ltd")
    print(f"Mode: {args.mode} | Output: {args.output} | Dry run: {args.dry_run}")
    print()

    cve_db = load_cve_database(CVE_DATABASE_PATH)
    print(f"Loaded CVE database: {cve_db['total_cves']} retail CVEs ({cve_db['last_updated']})")

    report = run_scan(args.mode, cve_db, dry_run=args.dry_run)

    if args.dry_run:
        preview = {**report, "findings": report["findings"][:3]}
        print("[DRY RUN] Scan complete — showing first 3 findings:\n")
        print(json.dumps(preview, indent=2))
        print("\n[DRY RUN] No files written.")
        return

    if args.output == "json":
        with open(args.out_file, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"JSON report written to: {args.out_file}")
        print(
            f"Summary: {report['vulnerabilities_found']} CVEs | "
            f"Critical: {report['summary'].get('critical', 0)} | "
            f"High: {report['summary'].get('high', 0)}"
        )
    else:
        print_text_report(report)

    print("Done!")


if __name__ == "__main__":
    main()
