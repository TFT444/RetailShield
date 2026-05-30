# RetailShield — Sentinel Analytics Rule Library

Scheduled analytics rules for Microsoft Sentinel, targeting the **Scattered Spider / UNC3944 TTPs** behind the 2025 M&S, Co-op, and JLR incidents. All rules are MITRE ATT&CK-mapped and tuned for low false-positive rates in retail Entra ID environments.

Each `.yaml` file is a complete Sentinel scheduled-rule definition — deployable via the Sentinel content hub, ARM template, or `az sentinel alert-rule create`.

---

## Rules

| ID | Name | MITRE Technique | Severity | Data Sources |
|----|------|-----------------|----------|--------------|
| [RS-SSE-001](RS-SSE-001-helpdesk-mfa-manipulation.yaml) | Helpdesk Social Engineering — MFA Method Added After Password Reset | T1098.005, T1556.006 | High | AuditLogs, SigninLogs |
| [RS-SSE-002](RS-SSE-002-mfa-fatigue-push-bombing.yaml) | MFA Fatigue / Push Bombing — Denials Followed by Approval | T1621 | High | SigninLogs |
| [RS-SSE-003](RS-SSE-003-privileged-role-addition.yaml) | Suspicious Privileged Role or Group Addition | T1098, T1078 | High | AuditLogs |
| [RS-SSE-004](RS-SSE-004-supplier-impossible-travel.yaml) | Supplier / Third-Party Account — Impossible Travel or New Geolocation | T1199, T1078 | Medium | SigninLogs |
| [RS-POS-002](RS-POS-002-offhours-void-refund.yaml) | POS Off-Hours Void / Refund Anomaly | Custom | Medium | RetailShield_POS_CL *(custom table)* |
| [RS-FRD-001](RS-FRD-001-giftcard-refund-fraud.yaml) | Gift-Card / High-Velocity Refund Fraud | Custom | Medium | RetailShield_POS_CL *(custom table)* |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Rule |
|--------|-----------|------|
| Initial Access | T1199 — Trusted Relationship | RS-SSE-004 |
| Persistence | T1098.005 — Device Registration | RS-SSE-001 |
| Persistence | T1098 — Account Manipulation | RS-SSE-003 |
| Credential Access | T1556.006 — Modify MFA | RS-SSE-001 |
| Credential Access | T1621 — MFA Request Generation | RS-SSE-002 |
| Defense Evasion | T1078 — Valid Accounts | RS-SSE-003, RS-SSE-004 |

---

## Required Data Sources

### Identity Rules (RS-SSE-001 — RS-SSE-004)

| Table | Connector | Notes |
|-------|-----------|-------|
| `AuditLogs` | Azure Active Directory | Free tier; includes MFA registration and role-change events |
| `SigninLogs` | Azure Active Directory | Requires at least P1 licence for full sign-in detail |
| `AADNonInteractiveUserSignInLogs` | Azure Active Directory | Needed for service-principal sign-ins in RS-SSE-004 |

Enable the **Azure Active Directory** connector in Sentinel:  
`Sentinel → Data connectors → Azure Active Directory → Connect`

### POS / Fraud Rules (RS-POS-002, RS-FRD-001)

These rules target a **custom log table** (`RetailShield_POS_CL`) that you ingest from your POS system.

**Expected schema:**

| Column | Type | Example | Notes |
|--------|------|---------|-------|
| `TimeGenerated` | datetime | `2025-05-01T22:14:00Z` | UTC transaction timestamp |
| `TerminalID_s` | string | `POS-TILL-03` | Terminal / till identifier |
| `CashierID_s` | string | `EMP-0042` | Cashier employee ID |
| `TransactionType_s` | string | `VOID`, `REFUND`, `SALE` | Transaction classification |
| `TransactionAmount_d` | real | `149.99` | Amount in GBP |
| `PaymentMethod_s` | string | `GIFTCARD`, `CASH`, `CARD` | Payment method |
| `GiftCardNumber_s` | string | `GC-***-4823` | Masked gift card number |
| `StoreID_s` | string | `STORE-HOUNSLOW` | Store / branch identifier |

Ingest via the **Custom Logs** or **Azure Monitor Agent** connector. Map your POS log fields to these column names in the DCR transformation rule.

---

## Deployment Notes

### Deploy a single rule via Azure CLI

```bash
az sentinel alert-rule create \
  --resource-group <rg> \
  --workspace-name <sentinel-workspace> \
  --rule-id <uuid-from-yaml-id-field> \
  --rule-file RS-SSE-001-helpdesk-mfa-manipulation.yaml
```

### Deploy all rules via ARM template

Wrap each YAML as a `Microsoft.SecurityInsights/alertRules` ARM resource and deploy with `az deployment group create`. The RetailShield workbook template in `../workbooks/` provides a starting ARM skeleton.

### Watchlists referenced

| Watchlist alias | Used by | Purpose |
|-----------------|---------|----------|
| `RetailApprovedSenders` | phishing_detection.kql | Approved email sender domains |
| `RetailIOCWatchlist` | pos_anomaly.kql | Malicious IPs / hashes |

### Tuning

Every rule exposes named `let` variables at the top of the KQL query for easy tuning without modifying rule logic:
- Time windows (`LookbackWindow`, `CorrelationWindow`)
- Thresholds (`MFADenialThreshold`, `VoidCountThreshold`, `HighValueRefundAmount`)
- Geo lists (`KnownThreatGeos`, `ApprovedSupplierCountries`)
