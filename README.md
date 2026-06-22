<p align="center">
  <img src="retailshield_logo.png" width="120" alt="RetailShield Logo">
</p>

# RetailShield

[![CI](https://github.com/TFT444/RetailShield/actions/workflows/ci.yml/badge.svg)](https://github.com/TFT444/RetailShield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![Azure Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoftazure)](https://azure.microsoft.com/en-gb/products/microsoft-sentinel)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Built With KQL](https://img.shields.io/badge/Language-KQL-orange)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Status](https://img.shields.io/badge/Status-Active%20MVP-brightgreen)]()
[![Author](https://img.shields.io/badge/Author-Tanvir%20Farhad%20%7C%20ShieldTech%20Ltd-informational)]()

> **A retail threat detection and incident response content pack for Microsoft Sentinel.**

RetailShield provides KQL analytics rules, Azure Logic App playbooks, and a Sentinel workbook — all purpose-built for the retail threat landscape and deployable directly on top of a Microsoft Sentinel workspace.

---

## Table of Contents

1. [What this is / What this is not](#what-this-is--what-this-is-not)
2. [Why retail needs its own rules](#why-retail-needs-its-own-rules)
3. [Architecture](#architecture)
4. [Content overview](#content-overview)
5. [MITRE ATT&CK coverage](#mitre-attck-coverage)
6. [Folder structure](#folder-structure)
7. [Quick start](#quick-start)
8. [Contributing](#contributing)
9. [Author](#author)
10. [License](#license)

---

## What this is / What this is not

| | |
|---|---|
| **This IS** | A content pack for Microsoft Sentinel — KQL detection rules, Logic App playbooks, and a workbook that you deploy into your existing Sentinel workspace |
| **This IS** | Opinionated detection logic tuned to retail-specific TTPs: POS RAM scraping, gift card fraud, supply chain compromise, AI voice fraud, MFA fatigue |
| **This IS** | Mapped to MITRE ATT&CK and linked to automated response playbooks so alerts trigger containment actions |
| **This IS NOT** | A standalone SIEM, SOC platform, or replacement for Microsoft Sentinel |
| **This IS NOT** | A generic threat detection library — rules are explicitly tuned for retail environments |
| **This IS NOT** | A managed service — you own the deployment and tuning in your own Azure tenant |

Microsoft Sentinel is the SIEM/SOAR platform. RetailShield is the retail-specific content that runs on top of it.

---

## Why retail needs its own rules

Retail is the most breach-targeted industry in the UK and globally. The consequences are no longer just reputational — they are existential.

| Incident | Organisation | Impact |
|---|---|---|
| Supply-chain ransomware (2025) | Marks & Spencer | **£300 M** operating-profit loss; online sales suspended for weeks |
| Coordinated social engineering (2025) | Co-op | Customer data exfiltrated; stores disrupted |
| Data exfiltration via third-party (2018) | Nike | **1.4 TB** of customer & IP data exposed |
| Point-of-Sale malware | Multiple UK retailers | Millions of payment cards compromised |
| Insider fraud | Retail sector average | £1,000+ loss per employee per year (CIFAS 2024) |

Retailers face a unique attack surface: fragmented POS networks, seasonal workforce spikes, large third-party supplier ecosystems, and high-volume transaction data that masks malicious activity. Generic Sentinel rules produce alert fatigue without retail-specific context.

RetailShield closes that gap.

---

## Architecture

```
                      RETAILSHIELD
    Retail-specific threat detection & automated response
             built natively for Microsoft Sentinel

┌─────────────────────────────────────────────────────────────────┐
│ 1. RETAIL DATA SOURCES                                          │
│ POS/Till · Identity (Azure AD) · Email/M365 · Network/Firewall │
│ Endpoints · Supply Chain & Suppliers                            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ INGESTION → Microsoft Sentinel Log Analytics Workspace          │
│ Standard tables + custom POS table (HMAC-SHA256 signed)         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. DETECTION — 20 KQL rules mapped to MITRE ATT&CK             │
│                                                                 │
│ Retail-specific (14): gift-card fraud · POS void/refund ·      │
│ credential stuffing · MFA fatigue · phishing · ransomware ·    │
│ supplier compromise · data exfil · AI voice fraud · POS        │
│ anomaly · privileged role abuse · after-hours · impossible      │
│ travel · TLS downgrade (PCI)                                    │
│                                                                 │
│ Generic SOC (6): brute force · bulk file access · C2 beacon ·  │
│ DNS exfil · RDP lateral movement · suspicious PowerShell        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
               Sentinel correlates alerts → INCIDENT (IP · account · host)
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. AUTOMATED RESPONSE & MITIGATION — 8 Logic App playbooks     │
│                                                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │    STEP 1      │──▶    STEP 2      │──▶     STEP 3       │  │
│  │   Triage &     │  │   Contain /    │  │  UK Compliance   │  │
│  │    Enrich      │  │    Mitigate    │  │    Assistant     │  │
│  │                │  │                │  │                  │  │
│  │  classify +    │  │   block IP ·   │  │  NCSC 24h +      │  │
│  │  severity ·    │  │ disable acct · │  │  ICO 72h tracking│  │
│  │  threat-intel  │  │ isolate host   │  │  · drafts report │  │
│  │ (VT/AbuseIPDB) │  │   (Defender)   │  │  (assists human) │  │
│  └────────────────┘  └────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

MODULES: [Threat Detection: LIVE] [Compliance Centre: LIVE] [Vulnerability Scanner: LIVE]
         [Loss Prevention: PLANNED] [ChainShield: PLANNED]

Validated in a controlled lab · published methodology (DOI 10.5281/zenodo.20608262) · avg ~22 min MTTD
A Sentinel-native content pack — not a standalone SIEM.
```

---

## Content overview

| Content type | Count | Description |
|---|---|---|
| **KQL Analytics Rules** | 13 retail + 6 generic | Scheduled analytics rules covering POS fraud, ransomware, exfiltration, identity abuse, supply chain, voice fraud |
| **Logic App Playbooks** | 3 | Triage & classify, threat-intel enrichment (AbuseIPDB / VirusTotal), containment (block IP / disable account / isolate host) |
| **Sentinel Workbook** | 1 | Live incident feed, TTP heatmap, analyst KPIs |
| **Watchlists** | 5 | RetailIOCWatchlist, RetailApprovedSenders, AbuseIPDBWatchlist, RetailSupplierAccounts, RetailServiceAccounts |
| **Hunting Queries** | Planned | Proactive threat hunting queries for retail TTPs |

---

## MITRE ATT&CK coverage

### Retail rules

| Tactic | Technique ID | Technique Name | Detection Rule | Playbook |
|---|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | `retail/phishing_detection.kql` | quarantine_email |
| Collection | T1056.001 | Input Capture — Keylogging | `retail/pos_anomaly.kql` | suspend_terminal |
| Collection | T1056.001 | Input Capture — Keylogging | `retail/pos_void_refund.kql` | notify_soc |
| Impact | T1657 | Financial Theft | `retail/gift_card_fraud.kql` | notify_soc |
| Reconnaissance | T1598 | Phishing for Information | `retail/ai_voice_fraud.kql` | notify_soc |
| Credential Access | T1621 | MFA Request Generation | `retail/mfa_fatigue.kql` | block_ip |
| Credential Access | T1110.004 | Credential Stuffing | `retail/credential_stuffing.kql` | block_ip |
| Persistence | T1078 | Valid Accounts | `retail/after_hours_access.kql` | notify_soc |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | `retail/data_exfiltration.kql` | data_exfil_contain |
| Impact | T1486 | Data Encrypted for Impact | `retail/ransomware_indicator.kql` | isolate_endpoint |
| Initial Access | T1195 | Supply Chain Compromise | `retail/supply_chain_anomaly.kql` | notify_soc |
| Initial Access | T1199 / T1078 | Trusted Relationship / Valid Accounts | `retail/supplier_impossible_travel.kql` | notify_soc |
| Persistence | T1098 / T1078 | Account Manipulation / Valid Accounts | `retail/privileged_role_addition.kql` | notify_soc |

### Generic rules

| Tactic | Technique ID | Technique Name | Detection Rule | Playbook |
|---|---|---|---|---|
| Credential Access | T1110 | Brute Force | `generic/brute-force-login.kql` | — |
| Collection | T1005 | Data from Local System | `generic/bulk-file-access.kql` | — |
| Command and Control | T1041 | Exfiltration Over C2 Channel | `generic/c2-beacon.kql` | — |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | `generic/dns-exfil.kql` | — |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | `generic/rdp-lateral-movement.kql` | — |
| Execution | T1059.001 | Command and Scripting Interpreter — PowerShell | `generic/suspicious-powershell.kql` | — |

---

## Folder structure

```
RetailShield/
├── .github/
│   └── workflows/
│       └── ci.yml                          # GitHub Actions CI pipeline
│
├── detection-rules/
│   ├── retail/                             # Retail-specific KQL analytics rules
│   │   ├── phishing_detection.kql          # RS-PHI-001 — T1566.001 — High
│   │   ├── pos_anomaly.kql                 # RS-POS-001 — T1056.001 — High
│   │   ├── pos_void_refund.kql             # RS-POS-002 — T1056.001 — High
│   │   ├── gift_card_fraud.kql             # RS-GCF-001 — T1657    — High
│   │   ├── ai_voice_fraud.kql              # RS-VOI-001 — T1598    — High
│   │   ├── mfa_fatigue.kql                 # RS-MFA-001 — T1621    — High
│   │   ├── credential_stuffing.kql         # RS-CRD-001 — T1110.004 — High
│   │   ├── after_hours_access.kql          # RS-AHA-001 — T1078    — Medium
│   │   ├── data_exfiltration.kql           # RS-EXF-001 — T1048    — Critical
│   │   ├── ransomware_indicator.kql        # RS-RAN-001 — T1486    — Critical
│   │   ├── supply_chain_anomaly.kql        # RS-SUP-001 — T1195    — High
│   │   ├── supplier_impossible_travel.kql  # RS-SUP-002 — T1199    — Medium
│   │   └── privileged_role_addition.kql    # RS-PRA-001 — T1098    — High
│   ├── generic/                            # General-purpose SOC rules
│   │   ├── brute-force-login.kql           # GEN-001 — T1110
│   │   ├── bulk-file-access.kql            # GEN-002 — T1005
│   │   ├── c2-beacon.kql                   # GEN-003 — T1041
│   │   ├── dns-exfil.kql                   # GEN-004 — T1048
│   │   ├── rdp-lateral-movement.kql        # GEN-005 — T1021.001
│   │   └── suspicious-powershell.kql       # GEN-006 — T1059.001
│   └── README.md                           # Rule index with MITRE mapping
│
├── logic-apps/
│   ├── triage-classify/
│   │   └── workflow.json                   # Auto-triage and severity classification
│   ├── threat-intel-enrich/
│   │   └── workflow.json                   # IOC enrichment (AbuseIPDB, VirusTotal)
│   ├── containment/
│   │   ├── workflow.json                   # Block IP / Disable account / Isolate host
│   │   └── README.md
│   └── DEPLOYMENT.md                       # Step-by-step Logic App deployment guide
│
├── sentinel/
│   ├── workbooks/
│   │   └── retailshield-workbook.json      # Sentinel Workbook ARM template
│   ├── watchlists/
│   │   └── retail-ioc-watchlist.csv        # Sample IOC watchlist
│   ├── data-connectors/
│   │   └── connectors.json                 # Data connector definitions
│   └── README.md
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── onboarding.md
│
├── scripts/
│   ├── validate_kql.py                     # KQL rule static validator (used by CI)
│   ├── validate_logicapps.py               # Logic App JSON validator (used by CI)
│   ├── retail_log_generator.py             # Sample retail log generator for testing
│   └── cve_scanner.py                      # CVE scanner utility
│
├── tests/
│   ├── detection-rules/
│   │   └── test_kql_rules.py
│   └── playbooks/
│       └── test_playbook_schema.py
│
├── CONTENT_PACK.md                         # How RetailShield maps to a Sentinel Solution
├── requirements.txt                        # Python dependencies for CI and tests
└── README.md                               # This file
```

---

## Quick start

### Prerequisites

| Requirement | Version |
|---|---|
| Azure Subscription | Active, with Microsoft Sentinel workspace |
| Azure CLI | Latest |
| Git | 2.40+ |
| Python 3.11+ | Only needed to run the local test suite |

### 1. Clone the repository

```bash
git clone https://github.com/tft444/retailshield.git
cd retailshield
git checkout dev
```

### 2. Deploy KQL analytics rules to Sentinel

Rules are deployed manually through the Microsoft Sentinel Analytics blade. There is no automated deployment script at this time.

For each `.kql` file in `detection-rules/retail/` (and optionally `detection-rules/generic/`):

1. In the Azure Portal, open your Sentinel workspace → **Analytics** → **+ Create** → **Scheduled query rule**
2. Set the rule name and description using the `// Rule ID` and `// Title` comments at the top of the file
3. Paste the full contents of the `.kql` file into the **Set rule query** box
4. Set **Run query every** and **Lookup data from the last** to match the `// Frequency` comment in the file
5. Set severity from the `// Severity` comment
6. Under **Automated response**, attach the relevant Logic App playbook (see the `// PlaybookTrigger` comment)
7. Save and enable the rule

Repeat for each rule you want to enable.

### 3. Deploy Logic App playbooks

See [logic-apps/DEPLOYMENT.md](logic-apps/DEPLOYMENT.md) for the full step-by-step guide.

```bash
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"

az deployment group create \
  --resource-group "<RESOURCE_GROUP>" \
  --template-file logic-apps/triage-classify/workflow.json
```

### 4. Run tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes, then submit a pull request against the `dev` branch.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit with clear messages
4. Push and open a pull request against `dev`

---

## Author

**Tanvir Farhad**  
Security Engineer — ShieldTech Ltd, London

---

## License

MIT © 2025 Tanvir Farhad — ShieldTech Ltd
