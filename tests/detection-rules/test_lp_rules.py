"""
RetailShield — Loss Prevention KQL Rule Test Suite
Validates syntax structure, required metadata, detection signals, and
output fields for all Loss Prevention detection rules without a live
Sentinel connection.
"""

import re
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent.parent / "detection-rules"


def load_rule(filename: str) -> str:
    path = RULES_DIR / filename
    assert path.exists(), f"Rule file not found: {path}"
    return path.read_text(encoding="utf-8")


# ── Helpers ──────────────────────────────────────────────────────────────────

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


# ── LP-001: lp-pos-void-refund-abuse.kql ─────────────────────────────────────

class TestLPPosVoidRefundAbuse:
    RULE = "retail/lp-pos-void-refund-abuse.kql"

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

    def test_lookback_period_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LookbackPeriod", "30m")

    def test_volume_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "VolumeThreshold", "10")

    def test_burst_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BurstThreshold", "5")

    def test_value_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ValueThreshold", "500.0")

    def test_high_volume_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighVolumeVoidRefund")

    def test_burst_abuse_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RapidVoidBurst")

    def test_high_value_no_override_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighValueVoidNoOverride")

    def test_filters_void_refund_return(self):
        content = load_rule(self.RULE)
        assert_contains(content, '"VOID"', '"REFUND"', '"RETURN"')

    def test_manager_override_check(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ManagerOverrideId_s", "HasManagerOverride")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "lp-incident-response")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "95", "80")

    def test_is_critical_field(self):
        content = load_rule(self.RULE)
        assert_contains(content, "IsCritical")

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

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2", "datetime(1")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "TimeGenerated", "OperatorId_s", "StoreId_s", "TerminalIDs",
            "DetectionSignal", "TransactionCount", "TransactionTypes",
            "TotalValueVoided", "HasManagerOverride", "LastTransaction",
            "IsCritical", "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── LP-002: lp-gift-card-rapid-redemption.kql ────────────────────────────────

class TestLPGiftCardRapidRedemption:
    RULE = "retail/lp-gift-card-rapid-redemption.kql"

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
        assert_metadata(content, "Frequency", "10 minutes")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RetailShield_POS_CL")

    def test_lookback_period_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LookbackPeriod", "60m")

    def test_bulk_activation_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BulkActivationThresh", "5")

    def test_rapid_redemption_window_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RapidRedemptionMins", "30")

    def test_value_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ValueThreshold", "200.0")

    def test_bulk_activation_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BulkGiftCardActivation")

    def test_rapid_cross_channel_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RapidCrossChannelRedemption")

    def test_high_value_session_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighValueActivationSession")

    def test_filters_gift_card_activate(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GIFT_CARD_ACTIVATE")

    def test_filters_gift_card_redeem(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GIFT_CARD_REDEEM")

    def test_cross_channel_detection(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ActivationStore", "ONLINE")

    def test_join_on_gift_card_id(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GiftCardId_s", "join kind=inner")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "lp-incident-response")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "90", "80")

    def test_is_critical_field(self):
        content = load_rule(self.RULE)
        assert_contains(content, "IsCritical")

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

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2", "datetime(1")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "TimeGenerated", "OperatorId_s", "StoreId_s", "TerminalIDs",
            "DetectionSignal", "ActivationCount", "CardBatchIDs",
            "TotalValueLoaded", "IsCritical", "AlertSeverity",
            "MitreTechnique", "MitreTactic", "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── LP-003: lp-sweethearting.kql ─────────────────────────────────────────────

class TestLPSweethearting:
    RULE = "retail/lp-sweethearting.kql"

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
        assert_metadata(content, "Frequency", "24 hours")

    def test_source_table(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RetailShield_POS_CL")

    def test_lookback_period_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LookbackPeriod", "7d")

    def test_repeat_transactions_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RepeatTransactions", "5")

    def test_discount_rate_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DiscountRateThreshold", "0.30")

    def test_basket_ratio_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BasketRatioThreshold", "0.60")

    def test_discount_share_threshold(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DiscountShareThresh", "0.40")

    def test_repeat_discount_relationship_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RepeatHighDiscountRelationship")

    def test_below_average_basket_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "BelowAverageBasketForCustomer")

    def test_discount_concentration_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HighDiscountConcentrationAtTerminal")

    def test_loyalty_card_tracking(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LoyaltyCardId_s")

    def test_store_basket_average_join(self):
        content = load_rule(self.RULE)
        assert_contains(content, "StoreBasketAverage", "StoreAvgBasket")

    def test_terminal_discount_totals_join(self):
        content = load_rule(self.RULE)
        assert_contains(content, "TerminalDiscountTotals", "TerminalTotalDiscount")

    def test_discount_amount_field(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DiscountAmount_d", "DiscountRate")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "lp-incident-response")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "75", "70")

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

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2", "datetime(1")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "TimeGenerated", "OperatorId_s", "StoreId_s", "LoyaltyCardId_s",
            "DetectionSignal", "TransactionCount", "AvgDiscountRate",
            "TotalDiscountValue", "AvgBasketValue", "LastSeen",
            "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)


# ── LP-004: lp-after-hours-pos-transaction.kql ───────────────────────────────

class TestLPAfterHoursPOSTransaction:
    RULE = "retail/lp-after-hours-pos-transaction.kql"

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

    def test_lookback_period_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "LookbackPeriod", "30m")

    def test_store_hours_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "StoreOpenHour", "6", "StoreCloseHour", "22")

    def test_value_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ValueThreshold", "100.0")

    def test_terminal_burst_threshold_defined(self):
        content = load_rule(self.RULE)
        assert_contains(content, "TerminalBurstThresh", "3")

    def test_after_hours_sale_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "AfterHoursHighValueSale")

    def test_ghost_employee_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "GhostEmployeeAfterHours")

    def test_terminal_burst_signal(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ClosedStoreTerminalBurst")

    def test_hour_of_day_filter(self):
        content = load_rule(self.RULE)
        assert_contains(content, "hourofday(TimeGenerated)", "HourOfDay")

    def test_daytime_operators_leftanti_join(self):
        content = load_rule(self.RULE)
        assert_contains(content, "DaytimeOperators", "leftanti")

    def test_daytime_lookback_one_day(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ago(1d)")

    def test_after_hours_condition(self):
        content = load_rule(self.RULE)
        assert_contains(content, "HourOfDay < StoreOpenHour", "HourOfDay >= StoreCloseHour")

    def test_playbook_trigger(self):
        content = load_rule(self.RULE)
        assert_contains(content, "PlaybookTrigger", "lp-incident-response")

    def test_risk_score(self):
        content = load_rule(self.RULE)
        assert_contains(content, "RiskScore", "92", "80")

    def test_is_critical_field(self):
        content = load_rule(self.RULE)
        assert_contains(content, "IsCritical")

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

    def test_uses_ingestion_time_not_static_timestamp(self):
        content = load_rule(self.RULE)
        assert_contains(content, "ingestion_time()")
        assert_not_contains(content, "datetime(2", "datetime(1")

    def test_output_contains_required_fields(self):
        content = load_rule(self.RULE)
        for field in [
            "TimeGenerated", "OperatorId_s", "StoreId_s", "TerminalId_s",
            "DetectionSignal", "TransactionCount", "TotalValue",
            "IsCritical", "AlertSeverity", "MitreTechnique", "MitreTactic",
            "PlaybookTrigger", "RiskScore",
        ]:
            assert_contains(content, field)
