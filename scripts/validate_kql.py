"""
RetailShield — KQL Rule Static Validator
Runs in CI to catch missing metadata, unclosed brackets, and
placeholder files before they reach the Sentinel workspace.
Exit code 0 = all rules valid. Exit code 1 = one or more failures.
"""

import sys
import re
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "detection-rules"

REQUIRED_METADATA = [
    "MITRE ATT&CK",
    "Severity",
    "Frequency",
    "Author",
]

PLACEHOLDER_PATTERN = re.compile(r"placeholder", re.IGNORECASE)

KNOWN_TABLES = [
    "EmailAttachmentInfo", "EmailEvents", "EmailUrlInfo",
    "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs",
    "SecurityEvent", "WindowsEvent", "DeviceProcessEvents",
    "DeviceFileEvents", "DeviceNetworkEvents", "DeviceLogonEvents",
    "CommonSecurityLog", "Syslog", "DnsEvents",
    "OfficeActivity", "AzureActivity", "AzureDiagnostics",
    "RetailShield_Logs_CL",
]


def is_placeholder(content: str) -> bool:
    return bool(PLACEHOLDER_PATTERN.search(content))


def check_rule(path: Path) -> list[str]:
    errors = []
    content = path.read_text(encoding="utf-8")

    # Required metadata comments
    for key in REQUIRED_METADATA:
        pattern = rf"//\s*{re.escape(key)}\s*:"
        if not re.search(pattern, content, re.IGNORECASE):
            errors.append(f"Missing metadata comment: '// {key} :'")

    # Must reference at least one known Sentinel table
    if not any(table in content for table in KNOWN_TABLES):
        errors.append(
            f"No recognised Sentinel table found. Expected one of: {', '.join(KNOWN_TABLES[:5])}..."
        )

    # Balanced parentheses
    if content.count("(") != content.count(")"):
        errors.append(
            f"Unbalanced parentheses: {content.count('(')} open, {content.count(')')} close"
        )

    # Balanced square brackets
    if content.count("[") != content.count("]"):
        errors.append(
            f"Unbalanced square brackets: {content.count('[') } open, {content.count(']')} close"
        )

    # Must have a time filter (prevent unbounded full-table scans)
    if not re.search(r"ago\s*\(", content):
        errors.append("No time filter found — add 'ago()' to prevent unbounded table scans")

    # Must project output fields (not return raw *)
    if re.search(r"^\s*\|\s*project\s+\*", content, re.MULTILINE):
        errors.append("Rule uses 'project *' — explicitly list output fields instead")

    return errors


def main() -> int:
    kql_files = sorted(RULES_DIR.glob("*.kql"))

    if not kql_files:
        print("⚠  No .kql files found in detection-rules/ — nothing to validate")
        return 0

    failed = 0
    for path in kql_files:
        content = path.read_text(encoding="utf-8")
        if is_placeholder(content):
            print(f"⚠   {path.name}  (placeholder — skipped)")
            continue
        errors = check_rule(path)
        if errors:
            print(f"\n❌  {path.name}")
            for err in errors:
                print(f"     • {err}")
            failed += 1
        else:
            print(f"✅  {path.name}")

    print(f"\n{'─' * 50}")
    total = len(kql_files)
    passed = total - failed
    print(f"Results: {passed}/{total} rules passed")

    if failed:
        print(f"\n{failed} rule(s) failed validation. Fix errors before merging.")
        return 1

    print("All rules passed validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
