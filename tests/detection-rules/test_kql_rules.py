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


# ── Helpers ─────────────────────────────────────────────────────────────────────────────

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


# ── phishing_detection.kql ─────────────────────────────────────────────────────────────────────

class TestPhishingDetection:
    RULE = "retail/phishing_detection.kql"

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


# ── ransomware_indicator.kql ──────────────────────────────────────────────────────────────────

class TestRansomwareIndicator:
    RULE = "retail/ransomware_indicator.kql"

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


# ── pos_anomaly.kql ─────────────────────────────────────────────────────────────────────────────

class TestPosAnomaly:
    RULE = "retail/pos_anomaly.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1056.001")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Collection")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "15 minutes")

    def test_pos_process_names_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "POSProcessNames", "xstore.exe", "aloha.exe", "posready.exe")

    def test_retail_terminal_prefix_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RetailTerminalPrefix", '"pos-"', '"till-"', '"kiosk-"')

    def test_unknown_dll_injection_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "UnknownDLLInjection", "DeviceEvents", "ImageLoaded")

    def test_abnormal_transaction_volume_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AbnormalTransactionVolume",
            "RetailShield_Logs_CL",
            "TransactionVolumeThreshold",
        )

    def test_process_memory_dump_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "ProcessMemoryDump",
            "ProcessDumped",
            "ProcDump",
        )

    def test_suspicious_network_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "SuspiciousNetworkFromPOS",
            "DeviceNetworkEvents",
            "RetailIOCWatchlist",
        )

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "suspend_terminal")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content), (
            "Rule contains a hardcoded GUID — use a watchlist or parameter instead"
        )

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        required_fields = [
            "AlertTitle",
            "DeviceName",
            "DeviceId",
            "AlertSeverity",
            "RiskScore",
            "SignalCount",
            "Signals",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "FirstSeen",
            "LastSeen",
        ]
        for field in required_fields:
            assert_contains(content, field)


# ── ai_voice_fraud.kql ─────────────────────────────────────────────────────────────────────

class TestAiVoiceFraud:
    RULE = "retail/ai_voice_fraud.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1598")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Reconnaissance")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "30 minutes")

    def test_ai_confidence_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AIConfidenceThreshold")

    def test_fraud_keywords_defined(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "FraudKeywords",
            '"urgent"',
            '"override"',
            '"bypass"',
            '"transfer"',
        )

    def test_business_hours_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BusinessHoursStart", "BusinessHoursEnd")

    def test_high_confidence_voice_fraud_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "HighConfidenceVoiceFraud",
            "RetailShield_Logs_CL",
            "AI_Voice_Fraud",
        )

    def test_urgent_financial_request_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "UrgentFinancialRequest")

    def test_spoofed_caller_id_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SpoofedCallerID")

    def test_after_hours_voice_fraud_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursVoiceFraud", "hourofday")

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content), (
            "Rule contains a hardcoded GUID — use a watchlist or parameter instead"
        )

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        required_fields = [
            "AlertTitle",
            "DeviceName",
            "TargetEmployee",
            "ImpersonatingEntity",
            "RequestMade",
            "AlertSeverity",
            "RiskScore",
            "SignalCount",
            "Signals",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "FirstSeen",
            "LastSeen",
        ]
        for field in required_fields:
            assert_contains(content, field)


# ── supply_chain_anomaly.kql ──────────────────────────────────────────────────────────────────

class TestSupplyChainAnomaly:
    RULE = "retail/supply_chain_anomaly.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1195")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Initial Access")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "30 minutes")

    def test_admin_endpoints_defined(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AdminEndpoints",
            '"/admin"',
            '"/management"',
            '"/config"',
        )

    def test_agreeable_endpoints_defined(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "AgreeableEndpoints",
            '"/inventory"',
            '"/orders"',
        )

    def test_bulk_export_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BulkExportThreshold")

    def test_supplier_admin_access_signal(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "SupplierAdminAccess",
            "AzureDiagnostics",
            "supplier_api_key",
        )

    def test_new_service_principal_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "NewServicePrincipal", "AuditLogs")

    def test_unauthorised_endpoint_access_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "UnauthorisedEndpointAccess")

    def test_mass_data_export_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MassDataExport", "BulkExportThreshold")

    def test_playbook_trigger_field_exposed(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content), (
            "Rule contains a hardcoded GUID — use a watchlist or parameter instead"
        )

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        required_fields = [
            "AlertTitle",
            "DeviceName",
            "SupplierKey",
            "AlertSeverity",
            "RiskScore",
            "SignalCount",
            "Signals",
            "MitreTechnique",
            "MitreTactic",
            "PlaybookTrigger",
            "FirstSeen",
            "LastSeen",
        ]
        for field in required_fields:
            assert_contains(content, field)


# ── pos_void_refund.kql ──────────────────────────────────────────────────────────────────

class TestPosVoidRefund:
    RULE = "retail/pos_void_refund.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1056.001")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Collection")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RetailShield_POS_CL")

    def test_business_hours_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BusinessHourStart", "BusinessHourEnd")

    def test_threshold_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "VoidRefundThresh", "HighValueThresh")

    def test_after_hours_void_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursVoidRefund")

    def test_high_volume_void_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighVolumeVoidRefund")

    def test_high_value_void_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighValueVoidNoOverride")

    def test_tender_mismatch_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "TenderMismatchRefund", "CASH", "GIFT_CARD")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "80")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "OperatorId_s", "StoreId_s", "TerminalId_s", "ThreatSignal",
            "TotalValue", "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── gift_card_fraud.kql ──────────────────────────────────────────────────────────────────

class TestGiftCardFraud:
    RULE = "retail/gift_card_fraud.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1657")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Impact")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RetailShield_POS_CL")

    def test_activation_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GiftCardActivThresh")

    def test_structuring_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "StructuringThreshold", "StructuringBand")

    def test_multi_terminal_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MultiTerminalThresh")

    def test_high_velocity_activation_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighVelocityGiftCardActivation")

    def test_structured_purchase_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "StructuredGiftCardPurchase")

    def test_drain_and_reload_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GiftCardDrainAndReload")

    def test_multi_terminal_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GiftCardMultiTerminalUse")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "85")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "GiftCardNumber_s", "OperatorId_s", "StoreId_s", "TerminalId_s",
            "ThreatSignal", "ActivationCount", "UniqueCards", "TotalValue",
            "TerminalCount", "TerminalList", "AlertSeverity", "MitreTechnique",
            "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── mfa_fatigue.kql ──────────────────────────────────────────────────────────────────

class TestMfaFatigue:
    RULE = "retail/mfa_fatigue.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1621")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Credential Access")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SigninLogs")

    def test_mfa_prompt_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MFAPromptThresh")

    def test_mfa_result_codes(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MFAResultCodes", "50074", "50076", "50079")

    def test_prompt_flood_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MFAPromptFlood")

    def test_fatigue_acceptance_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "FatigueAcceptance")

    def test_distributed_mfa_flood_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DistributedMFAFlood")

    def test_risky_signin_post_flood_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskySigninPostMFAFlood")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "block_ip")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "85")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "UserPrincipalName", "ThreatSignal", "PromptCount", "SourceIPs",
            "SourceIPList", "Locations", "AppNames", "SuccessIP", "SuccessCountry",
            "RiskLevel", "RiskyIP", "AlertSeverity", "MitreTechnique",
            "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── credential_stuffing.kql ──────────────────────────────────────────────────────────────────

class TestCredentialStuffing:
    RULE = "retail/credential_stuffing.kql"

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

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SigninLogs")

    def test_abuse_ipdb_watchlist(self):
        content = load_rule(self.RULE)
        assert_contains(content, '_GetWatchlist("AbuseIPDBWatchlist")')

    def test_threshold_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "FailThreshPerAcct", "MinSourceIPs")

    def test_distributed_login_failure_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DistributedLoginFailure")

    def test_account_takeover_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AccountTakeoverAfterStuffing")

    def test_blacklisted_ip_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "StuffingFromBlacklistedIP")

    def test_risky_signin_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskySigninAfterStuffing")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "block_ip")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "80")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "UserPrincipalName", "ThreatSignal", "FailCount", "SourceIPs",
            "SourceIPList", "IPAddress", "TargetAccts", "TargetList",
            "SuccessIP", "SuccessCountry", "RiskLevel", "AppNames",
            "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── after_hours_access.kql ──────────────────────────────────────────────────────────────────

class TestAfterHoursAccess:
    RULE = "retail/after_hours_access.kql"

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

    def test_source_tables(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SigninLogs", "AuditLogs", "DeviceLogonEvents")

    def test_service_accounts_watchlist(self):
        content = load_rule(self.RULE)
        assert_contains(content, '_GetWatchlist("RetailServiceAccounts")', "leftanti")

    def test_business_hours_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BusinessHourStart", "BusinessHourEnd")

    def test_after_hours_interactive_login_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursInteractiveLogin")

    def test_after_hours_privileged_operation_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursPrivilegedOperation")

    def test_after_hours_device_logon_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursSensitiveDeviceLogon")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "60")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "Timestamp", "AccountName", "ThreatSignal", "LoginCount",
            "SourceIPs", "Locations", "AppNames", "Devices",
            "RemoteIP", "Operations", "TargetObjects", "AlertSeverity",
            "MitreTechnique", "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── data_exfiltration.kql ──────────────────────────────────────────────────────────────────

class TestDataExfiltration:
    RULE = "retail/data_exfiltration.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1048")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Exfiltration")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "Critical")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_source_tables(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DeviceNetworkEvents", "DeviceFileEvents")

    def test_ioc_watchlist(self):
        content = load_rule(self.RULE)
        assert_contains(content, '_GetWatchlist("RetailIOCWatchlist")')

    def test_threshold_params(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DNSQueryThresh", "SubdomainLenThresh",
                         "OutboundMBThresh", "StagingFileThresh")

    def test_private_ip_exclusions(self):
        content = load_rule(self.RULE)
        assert_contains(content, '"10."', '"192.168."', '"172."', '"127.0.0.1"')

    def test_dns_tunneling_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DNSTunneling")

    def test_large_outbound_transfer_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LargeOutboundTransfer")

    def test_ioc_matched_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "IOCMatchedExfilTarget")

    def test_data_staging_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DataStagingToExfil")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "data_exfil_contain")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "90")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "Timestamp", "DeviceName", "DeviceId", "AccountName", "ThreatSignal",
            "NormalisedTarget", "QueryCount", "UniqueSubdomains", "TotalSentMB",
            "TotalSentBytes", "FileReadCount", "SampleFiles", "UniqueFolders",
            "ExfilTargets", "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── supplier_impossible_travel.kql ──────────────────────────────────────────────────────────

class TestSupplierImpossibleTravel:
    RULE = "retail/supplier_impossible_travel.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1199")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Initial Access")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "Medium")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "15 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SigninLogs")

    def test_supplier_accounts_watchlist(self):
        content = load_rule(self.RULE)
        assert_contains(content, '_GetWatchlist("RetailSupplierAccounts")')

    def test_impossible_speed_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ImpossibleSpeedKmph", "900")

    def test_high_risk_countries(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighRiskCountries", '"RU"', '"CN"', '"KP"', '"IR"')

    def test_geo_distance_function(self):
        content = load_rule(self.RULE)
        assert_contains(content, "geo_distance_2points")

    def test_impossible_travel_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ImpossibleTravel", "RequiredSpeedKmph")

    def test_new_country_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "NewCountryForSupplier")

    def test_high_risk_country_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighRiskCountrySignin")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "70")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "Timestamp", "UserPrincipalName", "SupplierName", "ThreatSignal",
            "IPAddress", "CountryCode", "City", "SecondCountry", "SecondCity",
            "RequiredSpeedKmph", "DistanceKm", "AlertSeverity", "MitreTechnique",
            "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── privileged_role_addition.kql ──────────────────────────────────────────────────────────

class TestPrivilegedRoleAddition:
    RULE = "retail/privileged_role_addition.kql"

    def test_file_exists(self):
        assert (RULES_DIR / self.RULE).exists()

    def test_mitre_technique_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "MITRE ATT&CK", "T1098")

    def test_mitre_tactic_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Tactic", "Persistence")

    def test_severity_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Severity", "High")

    def test_frequency_metadata(self):
        content = load_rule(self.RULE)
        assert_metadata(content, "Frequency", "5 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AuditLogs")

    def test_sensitive_roles_defined(self):
        content = load_rule(self.RULE)
        assert_contains(
            content,
            "SensitiveRoles",
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
        )

    def test_sensitive_role_assigned_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SensitiveRoleAssigned")

    def test_after_hours_role_addition_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursRoleAddition", "HourOfDay")

    def test_mfa_change_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RoleAdditionFollowedByMFAChange")

    def test_sensitive_group_member_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "SensitiveGroupMemberAdded")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "notify_soc")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "85")

    def test_mitre_fields_in_output(self):
        content = load_rule(self.RULE)
        assert_contains(content, "MitreTechnique", "MitreTactic")

    def test_no_hardcoded_tenant_ids(self):
        content = load_rule(self.RULE)
        tenant_pattern = re.compile(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            re.IGNORECASE,
        )
        assert not tenant_pattern.search(content)

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "Timestamp", "InitiatedByUser", "TargetUser", "RoleDisplayName",
            "ThreatSignal", "HourOfDay", "MFAOperation", "AlertSeverity",
            "MitreTechnique", "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)
