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


# ── credential_stuffing.kql ───────────────────────────────────────────────────

class TestCredentialStuffing:
    RULE = "credential_stuffing.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1110.004")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Credential Access")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_distributed_login_failure_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "DistributedLoginFailure",
            "FailThreshPerAcct",
            "MinSourceIPs",
            "SigninLogs",
        )

    def test_distinguishes_from_brute_force(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MinSourceIPs")
        assert "MinSourceIPs" in content

    def test_account_takeover_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AccountTakeoverAfterStuffing", "SuccessAfterFail")

    def test_blacklisted_ip_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "StuffingFromBlacklistedIP",
            "AbuseIPDBWatchlist",
        )

    def test_risky_signin_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskySigninAfterStuffing", "RiskLevelDuringSignIn")

    def test_mfa_prompts_excluded(self):
        content = load_rule(self.RULE)
        assert_contains(content, '"50074"', '"50076"')

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "block_ip")

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
            "UserPrincipalName",
            "ThreatSignal",
            "FailCount",
            "SourceIPs",
            "AlertSeverity",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "RiskScore",
        ]
        for field in required_fields:
            assert_contains(content, field)


# ── after_hours_access.kql ────────────────────────────────────────────────────

class TestAfterHoursAccess:
    RULE = "after_hours_access.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1078")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Persistence")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "Medium")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_configurable_business_hours(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BusinessHourStart", "BusinessHourEnd")

    def test_after_hours_interactive_login_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AfterHoursInteractiveLogin",
            "SigninLogs",
            "IsInteractive",
        )

    def test_privileged_operation_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AfterHoursPrivilegedOperation",
            "AuditLogs",
            "RoleManagement",
        )

    def test_sensitive_device_logon_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AfterHoursSensitiveDeviceLogon",
            "DeviceLogonEvents",
            "pos-",
        )

    def test_service_accounts_excluded(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "ServiceAccountExclusions",
            "RetailServiceAccounts",
            "leftanti",
        )

    def test_sensitive_system_names_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "payroll", "finance", "erpserver")

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

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
            "AccountName",
            "ThreatSignal",
            "LoginCount",
            "SourceIPs",
            "Devices",
            "AlertSeverity",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "RiskScore",
        ]
        for field in required_fields:
            assert_contains(content, field)
