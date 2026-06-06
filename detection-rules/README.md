# Detection Rules

KQL analytics rules for Microsoft Sentinel, tuned to retail threat patterns and mapped to MITRE ATT&CK.

Each `.kql` file corresponds to a single Sentinel Scheduled Analytics Rule. Rules are split into two subfolders:

- **`retail/`** — rules specific to retail threat patterns (POS, gift cards, supply chain, insider fraud)
- **`generic/`** — general-purpose SOC rules applicable to any Sentinel deployment

---

## Retail Rules (`retail/`)

| Rule ID | File | MITRE Technique | Tactic | Severity | Playbook Trigger |
|---|---|---|---|---|---|
| RS-PHI-001 | `retail/phishing_detection.kql` | T1566.001 | Initial Access | High | `quarantine_email` |
| RS-POS-001 | `retail/pos_anomaly.kql` | T1056.001 | Collection | High | `suspend_terminal` |
| RS-POS-002 | `retail/pos_void_refund.kql` | T1056.001 | Collection | High | `notify_soc` |
| RS-GCF-001 | `retail/gift_card_fraud.kql` | T1657 | Impact | High | `notify_soc` |
| RS-VOI-001 | `retail/ai_voice_fraud.kql` | T1598 | Reconnaissance | High | `notify_soc` |
| RS-MFA-001 | `retail/mfa_fatigue.kql` | T1621 | Credential Access | High | `block_ip` |
| RS-CRD-001 | `retail/credential_stuffing.kql` | T1110.004 | Credential Access | High | `block_ip` |
| RS-AHA-001 | `retail/after_hours_access.kql` | T1078 | Persistence | Medium | `notify_soc` |
| RS-EXF-001 | `retail/data_exfiltration.kql` | T1048 | Exfiltration | Critical | `data_exfil_contain` |
| RS-RAN-001 | `retail/ransomware_indicator.kql` | T1486 | Impact | Critical | `isolate_endpoint` |
| RS-SUP-001 | `retail/supply_chain_anomaly.kql` | T1195 | Initial Access | High | `notify_soc` |
| RS-SUP-002 | `retail/supplier_impossible_travel.kql` | T1199, T1078 | Initial Access | Medium | `notify_soc` |
| RS-PRA-001 | `retail/privileged_role_addition.kql` | T1098, T1078 | Persistence / Privilege Escalation | High | `notify_soc` |

---

## Generic Rules (`generic/`)

These rules are placeholders for standard SOC detections not specific to retail. Logic will be implemented in a future sprint.

| Rule ID | File | MITRE Technique | Tactic | Status |
|---|---|---|---|---|
| GEN-001 | `generic/brute-force-login.kql` | T1110 | Credential Access | Placeholder |
| GEN-002 | `generic/bulk-file-access.kql` | T1005 | Collection | Placeholder |
| GEN-003 | `generic/c2-beacon.kql` | T1041 | Command and Control | Placeholder |
| GEN-004 | `generic/dns-exfil.kql` | T1048 | Exfiltration | Placeholder |
| GEN-005 | `generic/rdp-lateral-movement.kql` | T1021.001 | Lateral Movement | Placeholder |
| GEN-006 | `generic/suspicious-powershell.kql` | T1059.001 | Execution | Placeholder |

---

## Deploying Rules to Sentinel

Each `.kql` file is intended to be deployed as a **Scheduled Analytics Rule** in Microsoft Sentinel. Use the deployment script:

```bash
python scripts/deploy_rules.py \
  --workspace-name "<SENTINEL_WORKSPACE>" \
  --resource-group "<RESOURCE_GROUP>"
```

Or deploy manually via the Sentinel Analytics blade — create a new Scheduled Rule and paste in the KQL query.

## Watchlists required

Several rules reference Sentinel watchlists. These must be populated before the rules produce meaningful results:

| Watchlist | Used by |
|---|---|
| `RetailApprovedSenders` | RS-PHI-001 |
| `RetailIOCWatchlist` | RS-POS-001, RS-EXF-001, RS-RAN-001 |
| `AbuseIPDBWatchlist` | RS-CRD-001 |
| `RetailSupplierAccounts` | RS-SUP-002 |
| `RetailServiceAccounts` | RS-AHA-001 |

Sample CSV templates are in `sentinel/watchlists/`.
