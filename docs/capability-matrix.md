# RetailShield Capability Matrix

This document maps every detection rule and response playbook to its threat coverage, MITRE ATT&CK alignment, data sources, and current implementation status.

**Status key:**

| Status | Meaning |
|--------|---------|
| ✅ Complete | Full KQL/ARM implementation, tested |
| 🔶 ARM template pending | KQL complete; Sentinel ARM template not yet in Content Hub package |
| ⬜ Placeholder | File exists with MITRE comment only; KQL logic not yet written |

---

## Retail Detection Rules (13)

These rules are tailored to UK retail environments and ingest from both standard Sentinel tables and RetailShield custom tables.

| Rule | File | MITRE Technique | Tactic | Severity | Frequency | Data Sources | Playbook | Status |
|------|------|----------------|--------|----------|-----------|-------------|----------|--------|
| Retail Phishing Email Detection | `phishing_detection.kql` | T1566.001 | Initial Access | High | 5 min | EmailAttachmentInfo, EmailEvents | quarantine_email | ✅ Complete |
| POS Void/Refund Fraud Pattern | `pos_void_refund.kql` | T1056.001 | Collection | High | 5 min | RetailShield_POS_CL | notify_soc | ✅ Complete |
| MFA Fatigue / Push Bombing | `mfa_fatigue.kql` | T1621 | Credential Access | High | 5 min | SigninLogs | block_ip | ✅ Complete |
| Data Exfiltration via Alt Protocol | `data_exfiltration.kql` | T1048 | Exfiltration | Critical | 5 min | DeviceNetworkEvents, DeviceFileEvents, RetailIOCWatchlist | data_exfil_contain | ✅ Complete |
| AI-Assisted Voice Fraud (Vishing) | `ai_voice_fraud.kql` | T1598 | Reconnaissance | High | 30 min | RetailShield_Logs_CL | notify_soc | ✅ Complete |
| Credential Stuffing Attack | `credential_stuffing.kql` | T1110.004 | Credential Access | High | 5 min | SigninLogs, AbuseIPDBWatchlist | block_ip | ✅ Complete |
| After-Hours System Access | `after_hours_access.kql` | T1078 | Persistence | Medium | 5 min | SigninLogs, AuditLogs, DeviceLogonEvents, RetailServiceAccounts | notify_soc | ✅ Complete |
| Gift Card Fraud Pattern | `gift_card_fraud.kql` | T1657 | Impact | High | 5 min | RetailShield_POS_CL | notify_soc | ✅ Complete |
| POS Terminal Anomaly | `pos_anomaly.kql` | T1056.001 | Collection | High | 15 min | DeviceEvents, RetailShield_Logs_CL, DeviceNetworkEvents | suspend_terminal | ✅ Complete |
| Ransomware Indicator | `ransomware_indicator.kql` | T1486 | Impact | Critical | 5 min | DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents, RetailIOCWatchlist | isolate_endpoint | ✅ Complete |
| Supply Chain / Third-Party Anomaly | `supply_chain_anomaly.kql` | T1195 | Initial Access | High | 30 min | AzureDiagnostics, AuditLogs | notify_soc | ✅ Complete |
| Supplier Impossible Travel | `supplier_impossible_travel.kql` | T1199, T1078 | Initial Access | Medium | 15 min | SigninLogs, RetailSupplierAccounts | notify_soc | ✅ Complete |
| Privileged Role Assignment | `privileged_role_addition.kql` | T1098, T1078 | Persistence, Privilege Escalation | High | 5 min | AuditLogs | notify_soc | ✅ Complete |

---

## Generic Detection Rules (6)

These rules cover cross-industry threats applicable to any Sentinel workspace. All are currently placeholder stubs — the MITRE mapping is defined but the KQL logic has not been written yet.

| Rule | File | MITRE Technique | Tactic | Status |
|------|------|----------------|--------|--------|
| Brute Force Login | `brute-force-login.kql` | T1110 | Credential Access | ⬜ Placeholder |
| Bulk File Access | `bulk-file-access.kql` | T1005 | Collection | ⬜ Placeholder |
| C2 Beacon Detection | `c2-beacon.kql` | T1041 | Command and Control | ⬜ Placeholder |
| DNS Exfiltration | `dns-exfil.kql` | T1048 | Exfiltration | ⬜ Placeholder |
| RDP Lateral Movement | `rdp-lateral-movement.kql` | T1021.001 | Lateral Movement | ⬜ Placeholder |
| Suspicious PowerShell | `suspicious-powershell.kql` | T1059.001 | Execution | ⬜ Placeholder |

---

## Response Playbooks (5)

| Playbook | Directory | Trigger | Description | Status |
|----------|-----------|---------|-------------|--------|
| block-ip | `logic-apps/block-ip/` | block_ip | Blocks attacker IP via Microsoft Defender for Endpoint custom indicators | ✅ Complete |
| isolate-endpoint | `logic-apps/isolate-endpoint/` | isolate_endpoint | Network-isolates an endpoint via Microsoft Defender for Endpoint | ✅ Complete |
| quarantine-email | `logic-apps/quarantine-email/` | quarantine_email | Quarantines a malicious email via Microsoft Defender for Office 365 | ✅ Complete |
| suspend-terminal | `logic-apps/suspend-terminal/` | suspend_terminal | Disables a compromised POS terminal via a custom webhook | ✅ Complete |
| incident-reporting | `logic-apps/incident-reporting/` | High/Critical severity | UK compliance assistant: drafts ICO/NCSC report, calculates 24h/72h deadlines, emails internal compliance contact | ✅ Complete |

---

## MITRE ATT&CK Tactic Coverage

| Tactic | Rules Covering It |
|--------|-----------------|
| Initial Access | phishing_detection, supply_chain_anomaly, supplier_impossible_travel |
| Execution | (generic) suspicious-powershell ⬜ |
| Persistence | after_hours_access, privileged_role_addition |
| Privilege Escalation | privileged_role_addition |
| Credential Access | mfa_fatigue, credential_stuffing, (generic) brute-force-login ⬜ |
| Collection | pos_void_refund, pos_anomaly, (generic) bulk-file-access ⬜ |
| Exfiltration | data_exfiltration, (generic) dns-exfil ⬜ |
| Command and Control | (generic) c2-beacon ⬜ |
| Lateral Movement | (generic) rdp-lateral-movement ⬜ |
| Impact | gift_card_fraud, ransomware_indicator |
| Reconnaissance | ai_voice_fraud |

---

## Watchlist Dependencies

| Watchlist | Rules Using It |
|-----------|---------------|
| RetailIOCWatchlist | data_exfiltration, ransomware_indicator |
| AbuseIPDBWatchlist | credential_stuffing |
| RetailServiceAccounts | after_hours_access |
| RetailSupplierAccounts | supplier_impossible_travel |
| RetailApprovedSenders | *(reserved for future phishing allowlist use)* |

---

## Custom Table Dependencies

| Table | Rules Using It |
|-------|---------------|
| RetailShield_POS_CL | pos_void_refund, gift_card_fraud, pos_anomaly |
| RetailShield_Logs_CL | ai_voice_fraud, pos_anomaly |
