"""
RetailShield — KQL Rule Validation Test Suite
Validates syntax structure, required metadata, and logic correctness
for all detection-rules/*.kql files without a live Sentinel connection.
"""

import re
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent.parent / "detection-rules"


def load_rule(filename: str) -> str:
    path = RULES_DIR / filename
    assert path.exists(), f"Rule file not found: {path}"
    return path.read_text(encoding="utf-8")


# ── Helpers ───────────────────────────────────────────────────────────────────

def assert_metadata(content: str, key: str, value: str):
    pattern = rf"//\s*{re.escape(key)}\s*:.*{re.escape(value)}"
    assert re.search(pattern, content, re.IGNORECASE), (
        f"Missing or incorrect metadata '{key}: {value}'"
    )


def assert_contains(content: str, *fragments: str):
    for fragment in fragments:
        assert fragment in content, f"Expected '{fragment}' not found in rule"


def assert_not_contains(content: str, *fragments: str):
    for fragment in fragments:
        assert fragment not in content, f"Unexpected fragment '{fragment}' found in rule"


# ── phishing_detection.kql ────────────────────────────────────────────────────

class TestPhishingDetection:
    RULE = "phishing_detection.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1566.001")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Initial Access")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_queries_email_attachment_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "EmailAttachmentInfo")

    def test_queries_email_events_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "EmailEvents")

    def test_filters_inbound_delivered_emails(self):
        content = load_rule(self.RULE)
        assert_contains(content, '"Delivered"', '"Inbound"')

    def test_suspicious_extensions_defined(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "SuspiciousExtensions",
            '".exe"',
            '".ps1"',
            '".vbs"',
            '".docm"',
        )

    def test_suppresses_approved_senders(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ApprovedSenderDomains", "leftanti")

    def test_lure_classification_present(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "LureCategory",
            "Financial",
            "Credential",
        )

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "quarantine_email")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        # Tenant IDs follow xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx pattern
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content), (
            "Rule contains a hardcoded GUID — use a watchlist or parameter instead"
        )

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        required_fields = [
            "SenderAddress",
            "RecipientEmailAddress",
            "Subject",
            "AttachmentFileName",
            "AttachmentSHA256",
            "NetworkMessageId",
            "AlertSeverity",
        ]
        for field in required_fields:
            assert_contains(content, field)


# ── ransomware_indicator.kql ──────────────────────────────────────────────────

class TestRansomwareIndicator:
    RULE = "ransomware_indicator.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1486")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Impact")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "Critical")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_mass_file_rename_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DeviceFileEvents", "FileRenamed", "MassRenameThresh")

    def test_shadow_copy_deletion_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "vssadmin delete shadows",
            "wmic shadowcopy delete",
            "bcdedit /set recoveryenabled no",
            "ShadowCopyDeletion",
        )

    def test_known_ransomware_process_names(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "lockbit",
            "blackcat",
            "conti",
            "ryuk",
            "KnownRansomwareProcess",
        )

    def test_c2_beacon_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "DeviceNetworkEvents",
            "RetailIOCWatchlist",
            "BeaconThresh",
            "C2BeaconToRansomwareIP",
        )

    def test_ioc_watchlist_used(self):
        content = load_rule(self.RULE)
        assert_contains(content, '_GetWatchlist("RetailIOCWatchlist")')

    def test_private_ip_exclusions(self):
        content = load_rule(self.RULE)
        assert_contains(content, '"10."', '"192.168."', '"127.0.0.1"')

    def test_union_combines_all_signals(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "MassFileRename",
            "ShadowCopyDeletion",
            "RansomwareProcesses",
            "C2Beaconing",
        )

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "isolate_endpoint")

    def test_risk_score_is_100(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "100")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content), (
            "Rule contains a hardcoded GUID — use a watchlist or parameter instead"
        )

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        required_fields = [
            "DeviceName",
            "DeviceId",
            "ThreatSignal",
            "ProcessCommandLine",
            "RenameCount",
            "SampleFiles",
            "AffectedFolders",
            "RemoteIP",
            "BeaconCount",
            "AlertSeverity",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "RiskScore",
        ]
        for field in required_fields:
            assert_contains(content, field)
