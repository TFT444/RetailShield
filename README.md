# RetailShield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Azure Sentinel](https://img.shields.io/badge/SIEM-Azure%20Sentinel-0078D4?logo=microsoftazure)](https://azure.microsoft.com/en-gb/products/microsoft-sentinel)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Built With KQL](https://img.shields.io/badge/Language-KQL-orange)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow)]()
[![Author](https://img.shields.io/badge/Author-Tamim%20%7C%20ShieldTech%20Ltd-informational)]()

> **Retail-focused threat detection, automated incident response, and live SOC dashboard — built on Microsoft Sentinel.**

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Architecture](#architecture)
3. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
4. [Features](#features)
5. [Folder Structure](#folder-structure)
6. [Quick Start](#quick-start)
7. [Contributing](#contributing)
8. [Author](#author)
9. [License](#license)

---

## Problem Statement

Retail is the most breach-targeted industry in the UK and globally. The consequences are no longer just reputational — they are existential.

| Incident | Organisation | Impact |
|---|---|---|
| Supply-chain ransomware (2025) | Marks & Spencer | **£300 M** operating-profit loss; online sales suspended for weeks |
| Data exfiltration (2018) | Nike (via third-party) | **1.4 TB** of customer & IP data exposed |
| Point-of-Sale malware | Multiple UK retailers | Millions of payment cards compromised |
| Insider threat & fraud | Retail sector average | £1,000+ loss per employee per year (CIFAS 2024) |

Retailers face a unique attack surface: fragmented POS networks, seasonal workforce spikes, large third-party supplier ecosystems, and high-volume transaction data that masks malicious activity. Generic SIEM rules produce alert fatigue without retail-specific context.

**RetailShield** closes that gap — purpose-built detection logic tuned to retail TTPs, automated Logic App playbooks that respond in seconds, and a dashboard that gives SOC analysts immediate situational awareness without drowning them in noise.

---

## Architecture

```
                        ┌─────────────────────────────────────────────────┐
                        │              RETAIL DATA SOURCES                │
                        │  POS Systems │ ERP/SAP │ IAM │ Cloud Apps │ EDR │
                        └───────────────────────┬─────────────────────────┘
                                                │  Log Ingestion
                                                ▼
                        ┌─────────────────────────────────────────────────┐
                        │           MICROSOFT SENTINEL (SIEM)             │
                        │                                                 │
                        │  ┌─────────────────┐   ┌─────────────────────┐ │
                        │  │  Data Connectors│   │   Analytics Rules   │ │
                        │  │  (CEF / Syslog  │──▶│   (KQL — Retail     │ │
                        │  │   / REST API)   │   │    TTPs mapped to   │ │
                        │  └─────────────────┘   │    MITRE ATT&CK)    │ │
                        │                        └──────────┬──────────┘ │
                        │                                   │ Alert      │
                        │                        ┌──────────▼──────────┐ │
                        │                        │    Incident Engine  │ │
                        │                        │  (Fusion + ML UEBA) │ │
                        │                        └──────────┬──────────┘ │
                        └───────────────────────────────────┼────────────┘
                                                            │ Trigger
                        ┌───────────────────────────────────▼────────────┐
                        │           AZURE LOGIC APPS (SOAR)              │
                        │                                                 │
                        │  ┌──────────────┐  ┌──────────┐  ┌──────────┐ │
                        │  │  Triage &    │  │  Enrich  │  │Containment│ │
                        │  │  Classify    │─▶│ (Threat  │─▶│(Block IP /│ │
                        │  │  Playbook    │  │  Intel)  │  │Disable AD)│ │
                        │  └──────────────┘  └──────────┘  └──────────┘ │
                        │                                                 │
                        │  ┌──────────────┐  ┌──────────────────────────┐│
                        │  │  Notify SOC  │  │  Create Ticket (JIRA /   ││
                        │  │  (Teams/PD)  │  │  ServiceNow)             ││
                        │  └──────────────┘  └──────────────────────────┘│
                        └───────────────────────────────────┬────────────┘
                                                            │ Status / Metrics
                        ┌───────────────────────────────────▼────────────┐
                        │         RETAILSHIELD DASHBOARD (React)         │
                        │                                                 │
                        │   Live Incident Feed │ TTP Heatmap │ KPIs      │
                        │   Analyst Workbench  │ Alert Drill-Down        │
                        └─────────────────────────────────────────────────┘
```

---

## MITRE ATT&CK Mapping

The detection rules in this project map to the following MITRE ATT&CK (Enterprise) techniques, prioritised for the retail threat landscape.

| Tactic | Technique ID | Technique Name | Detection Rule | Playbook |
|---|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | `phishing-email-attachment.kql` | `phishing-triage.json` |
| Initial Access | T1190 | Exploit Public-Facing Application | `web-exploit-attempt.kql` | `web-block-ip.json` |
| Execution | T1059.001 | PowerShell | `suspicious-powershell.kql` | `isolate-endpoint.json` |
| Persistence | T1078 | Valid Accounts (Credential Abuse) | `brute-force-login.kql` | `disable-account.json` |
| Persistence | T1136 | Create Account | `new-admin-account.kql` | `notify-soc.json` |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | `priv-esc-attempt.kql` | `isolate-endpoint.json` |
| Defence Evasion | T1562.001 | Disable or Modify Tools | `av-disabled.kql` | `notify-soc.json` |
| Credential Access | T1110 | Brute Force | `brute-force-login.kql` | `disable-account.json` |
| Discovery | T1046 | Network Service Scanning | `internal-port-scan.kql` | `notify-soc.json` |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | `rdp-lateral-movement.kql` | `isolate-endpoint.json` |
| Collection | T1005 | Data from Local System | `bulk-file-access.kql` | `data-exfil-contain.json` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `c2-beacon.kql` | `block-c2-ip.json` |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | `dns-exfil.kql` | `data-exfil-contain.json` |
| Impact | T1486 | Data Encrypted for Impact (Ransomware) | `ransomware-indicator.kql` | `ransomware-response.json` |
| Impact | T1485 | Data Destruction | `mass-delete-activity.kql` | `isolate-endpoint.json` |

---

## Features

| Feature | Description | Status |
|---|---|---|
| **Retail-Tuned KQL Rules** | 15+ detection rules pre-mapped to MITRE ATT&CK, calibrated for POS, ERP, and IAM log patterns | Planned |
| **Automated Triage Playbooks** | Logic App workflows that enrich, classify, and assign incidents without analyst intervention | Planned |
| **Containment Automation** | One-click and auto-triggered: block IP, disable AD account, isolate host via Defender | Planned |
| **Threat Intel Enrichment** | Auto-lookup of IOCs against Microsoft TI, VirusTotal, and AbuseIPDB | Planned |
| **SOAR Notification Layer** | Immediate alerts to Microsoft Teams channel and PagerDuty with full incident context | Planned |
| **Live SOC Dashboard** | React + TypeScript frontend consuming Sentinel APIs; incident feed, TTP heatmap, analyst KPIs | Planned |
| **JIRA / ServiceNow Integration** | Auto-create tickets with priority, assignee, and evidence attached | Planned |
| **Unit & Integration Tests** | KQL rule validation, playbook schema checks, and frontend component tests | Planned |
| **CI/CD Pipeline** | GitHub Actions: lint, test, and deploy Sentinel artefacts on merge to main | Planned |
| **Comprehensive Docs** | Architecture decision records, runbooks, and onboarding guides | Planned |

---

## Folder Structure

```
RetailShield/
├── .github/
│   └── workflows/
│       └── ci.yml                  # GitHub Actions CI pipeline (lint, test, deploy)
│
├── detection-rules/
│   ├── brute-force-login.kql       # T1110 — Brute Force credential attacks
│   ├── ransomware-indicator.kql    # T1486 — Ransomware staging indicators
│   ├── bulk-file-access.kql        # T1005 — Unusual bulk data access
│   ├── c2-beacon.kql               # T1041 — C2 beaconing over HTTP/S
│   ├── dns-exfil.kql               # T1048 — DNS-based data exfiltration
│   ├── suspicious-powershell.kql   # T1059.001 — Obfuscated PowerShell
│   ├── rdp-lateral-movement.kql    # T1021.001 — RDP lateral movement
│   └── README.md
│
├── logic-apps/
│   ├── triage-classify/
│   │   └── workflow.json           # Auto-triage and severity classification
│   ├── threat-intel-enrich/
│   │   └── workflow.json           # IOC enrichment (VT, AbuseIPDB, MSFT TI)
│   ├── containment/
│   │   └── workflow.json           # Block IP / Disable AD / Isolate host
│   └── README.md
│
├── playbooks/
│   ├── phishing-triage.md          # Analyst runbook — phishing incidents
│   ├── ransomware-response.md      # Analyst runbook — ransomware response
│   ├── data-exfil-contain.md       # Analyst runbook — data exfiltration
│   ├── insider-threat.md           # Analyst runbook — insider threat
│   └── README.md
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   └── api/
│   ├── package.json
│   └── README.md
│
├── sentinel/
│   ├── workbooks/
│   │   └── retailshield-workbook.json   # Sentinel Workbook ARM template
│   ├── data-connectors/
│   │   └── connectors.json
│   ├── watchlists/
│   │   └── retail-ioc-watchlist.csv
│   └── README.md
│
├── docs/
│   ├── architecture.md             # Full architecture decision record
│   ├── threat-model.md             # Retail threat model and assumptions
│   ├── onboarding.md               # New analyst / developer onboarding
│   ├── mitre-mapping.md            # Full MITRE ATT&CK coverage matrix
│   └── README.md
│
├── tests/
│   ├── detection-rules/
│   │   └── test_kql_rules.py       # KQL rule syntax and logic validation
│   ├── playbooks/
│   │   └── test_playbook_schema.py # Logic App JSON schema tests
│   ├── frontend/
│   │   └── dashboard.test.tsx      # React component unit tests
│   └── README.md
│
└── README.md                       # This file
```

---

## Quick Start

### Prerequisites

| Requirement | Version |
|---|---|
| Azure Subscription | Active, with Sentinel workspace |
| Python | 3.11+ |
| Node.js | 18+ |
| Azure CLI | Latest |
| Git | 2.40+ |

### 1. Clone the repository

```bash
git clone https://github.com/tft444/retailshield.git
cd retailshield
git checkout dev
```

### 2. Deploy detection rules to Sentinel

```bash
# Install dependencies
pip install -r requirements.txt

# Authenticate with Azure
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"

# Deploy all KQL analytics rules
python scripts/deploy_rules.py \
  --workspace-name "<SENTINEL_WORKSPACE>" \
  --resource-group "<RESOURCE_GROUP>"
```

### 3. Deploy Logic App playbooks

```bash
# Deploy all SOAR playbooks via ARM template
az deployment group create \
  --resource-group "<RESOURCE_GROUP>" \
  --template-file logic-apps/triage-classify/workflow.json \
  --parameters workspaceName="<SENTINEL_WORKSPACE>"
```

### 4. Run the SOC dashboard locally

```bash
cd frontend
npm install
npm run dev
# Dashboard available at http://localhost:5173
```

### 5. Run tests

```bash
# Python tests (KQL validation + playbook schema)
pytest tests/ -v

# Frontend tests
cd frontend && npm test
```

---

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes, then submit a pull request against the `dev` branch.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit with clear messages following the project convention
4. Push and open a pull request against `dev`

---

## Author

**Tamim**
Security Engineer — [ShieldTech Ltd](https://shieldtech.co.uk), London

> *"Security is not a product, but a process."* — Bruce Schneier

---

## License

[MIT](LICENSE) © 2025 Tamim — ShieldTech Ltd
