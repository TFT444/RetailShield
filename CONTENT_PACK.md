# RetailShield — Sentinel Content Pack

This document explains how RetailShield is structured as a Microsoft Sentinel Solution, how each component maps to a Sentinel content type, and what is required to publish it to the Microsoft Sentinel Content Hub.

---

## What is a Microsoft Sentinel Solution?

A **Microsoft Sentinel Solution** is a packaged collection of Sentinel content (analytics rules, playbooks, workbooks, watchlists, hunting queries, data connectors) distributed as a single deployable unit through the **Microsoft Sentinel Content Hub**.

When an organisation installs a Solution from Content Hub, all included content is deployed into their Sentinel workspace in one operation. Solutions are the standard way Microsoft and its partners distribute pre-built detection and response content.

RetailShield is structured to be publishable as a Solution. It can also be deployed component by component without going through Content Hub.

---

## Component mapping

Each RetailShield component maps to a specific Sentinel content type:

### Analytics Rules (KQL)

Sentinel content type: `Microsoft.SecurityInsights/alertRules`

Location in this repo: `detection-rules/retail/` and `detection-rules/generic/`

| Rule ID | File | Sentinel Rule Type |
|---|---|---|
| RS-PHI-001 | `retail/phishing_detection.kql` | Scheduled |
| RS-POS-001 | `retail/pos_anomaly.kql` | Scheduled |
| RS-POS-002 | `retail/pos_void_refund.kql` | Scheduled |
| RS-GCF-001 | `retail/gift_card_fraud.kql` | Scheduled |
| RS-VOI-001 | `retail/ai_voice_fraud.kql` | Scheduled |
| RS-MFA-001 | `retail/mfa_fatigue.kql` | Scheduled |
| RS-CRD-001 | `retail/credential_stuffing.kql` | Scheduled |
| RS-AHA-001 | `retail/after_hours_access.kql` | Scheduled |
| RS-EXF-001 | `retail/data_exfiltration.kql` | Scheduled |
| RS-RAN-001 | `retail/ransomware_indicator.kql` | Scheduled |
| RS-SUP-001 | `retail/supply_chain_anomaly.kql` | Scheduled |
| RS-SUP-002 | `retail/supplier_impossible_travel.kql` | Scheduled |
| RS-PRA-001 | `retail/privileged_role_addition.kql` | Scheduled |
| GEN-001–006 | `generic/*.kql` | Scheduled (placeholder) |

Each KQL file must be wrapped in a Sentinel ARM template (`Microsoft.SecurityInsights/alertRules`) to be included in a Solution. The ARM template defines the rule name, description, severity, frequency, lookback, and embeds the KQL query.

### Automation Playbooks (Logic Apps)

Sentinel content type: `Microsoft.Logic/workflows`

Location in this repo: `logic-apps/`

| Playbook | Trigger | Action |
|---|---|---|
| `triage-classify` | Sentinel incident created | Tags incident by retail category, sets severity |
| `threat-intel-enrich` | Sentinel incident created | Queries AbuseIPDB and VirusTotal for IP entities, raises severity on hits |
| `containment` | Sentinel incident created | Blocks IP in NSG, disables Azure AD account, isolates host via Defender for Endpoint |

Playbooks are Azure Logic Apps stored as ARM templates. For Content Hub packaging, each `workflow.json` must be wrapped in a Solution ARM template with the correct `Microsoft.Logic/workflows` resource type and a Sentinel `Microsoft.SecurityInsights/automationRules` trigger binding.

### Workbook

Sentinel content type: `Microsoft.Insights/workbooks`

Location in this repo: `sentinel/workbooks/retailshield-workbook.json`

The RetailShield workbook provides:
- Live incident feed filtered to RetailShield alert IDs
- TTP heatmap across MITRE ATT&CK tactics
- Analyst KPIs (MTTD, MTTR, alert-to-incident ratio)
- Per-rule alert volume over time

For Content Hub packaging, the workbook ARM template must include the `serializedData` field containing the full workbook JSON.

### Watchlists

Sentinel content type: `Microsoft.SecurityInsights/watchlists`

Location in this repo: `sentinel/watchlists/`

| Watchlist | Referenced by | Purpose |
|---|---|---|
| `RetailIOCWatchlist` | RS-POS-001, RS-EXF-001, RS-RAN-001 | Known malicious IPs, domains, hashes from retail sector threat intelligence |
| `RetailApprovedSenders` | RS-PHI-001 | Approved sender domains for phishing false-positive reduction |
| `AbuseIPDBWatchlist` | RS-CRD-001 | Known credential-stuffing infrastructure IPs |
| `RetailSupplierAccounts` | RS-SUP-002 | Supplier UPNs for impossible travel monitoring |
| `RetailServiceAccounts` | RS-AHA-001 | Service account UPNs excluded from after-hours alerts |

Watchlists must be populated with real data before the rules that reference them produce meaningful results. Sample CSV templates are in `sentinel/watchlists/`.

---

## Solution packaging structure

A Sentinel Solution ready for Content Hub submission has the following structure:

```
RetailShield-Solution/
├── createUiDefinition.json          # Azure Marketplace UI definition
├── mainTemplate.json               # Master ARM template referencing all resources
├── Package/
│   ├── analytic-rules/
│   │   ├── RS-PHI-001-PhishingDetection.json
│   │   ├── RS-POS-001-POSAnomaly.json
│   │   └── ... (one JSON per rule)
│   ├── playbooks/
│   │   ├── RetailShield-TriageClassify.json
│   │   ├── RetailShield-ThreatIntelEnrich.json
│   │   └── RetailShield-Containment.json
│   ├── workbooks/
│   │   └── RetailShield-Workbook.json
│   └── watchlists/
│       ├── RetailIOCWatchlist.json
│       └── ... (one JSON per watchlist)
└── SolutionMetadata.json            # Solution name, version, publisher, categories
```

### Key files

**`SolutionMetadata.json`** declares the solution identity:

```json
{
  "publisherId": "shieldtech",
  "offerId": "retailshield",
  "firstPublishDate": "2025-01-01",
  "lastPublishDate": "2025-06-01",
  "providers": ["ShieldTech Ltd"],
  "categories": {
    "domains": ["Security - Threat Protection"],
    "verticals": ["Retail"]
  }
}
```

**`createUiDefinition.json`** defines the deployment wizard shown to the customer in the Azure Portal when they click "Install" from Content Hub.

**`mainTemplate.json`** is the master ARM template that deploys all content resources into the customer’s workspace in a single `az deployment group create` call.

---

## Deployment options

### Option 1: Manual deployment (development / testing)

Deploy rules individually to a Sentinel workspace using the deployment script:

```bash
python scripts/deploy_rules.py \
  --workspace-name "<SENTINEL_WORKSPACE>" \
  --resource-group "<RESOURCE_GROUP>"
```

Or paste KQL directly into the Sentinel Analytics blade (New Scheduled Rule).

### Option 2: ARM template deployment

Deploy all content in one operation using the solution ARM template:

```bash
az deployment group create \
  --resource-group "<RESOURCE_GROUP>" \
  --template-file RetailShield-Solution/mainTemplate.json \
  --parameters workspaceName="<SENTINEL_WORKSPACE>"
```

### Option 3: Content Hub (future)

Once the Solution is submitted and approved by Microsoft, customers can discover and install RetailShield directly from the **Microsoft Sentinel Content Hub** in the Azure Portal, with no manual ARM deployment required.

---

## Content Hub submission requirements

To publish to the official Microsoft Sentinel Content Hub, a Solution must meet these requirements:

1. All content passes the [MSTIC validation pipeline](https://github.com/Azure/Azure-Sentinel/blob/master/docs/Solution_Validation.md)
2. `SolutionMetadata.json` is complete and valid
3. All ARM templates pass `az bicep build` (or ARM template validation)
4. All KQL queries are validated against real Log Analytics table schemas
5. PR submitted to the [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) repository under `Solutions/RetailShield/`
6. Microsoft content review and approval (typically 2–4 weeks)

> RetailShield is not yet submitted to Content Hub. The current repo is the development version. Content Hub packaging is planned for a future release.

---

## Related

- [Microsoft Sentinel Content Hub documentation](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog)
- [Build a Sentinel Solution](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-create)
- [Azure/Azure-Sentinel GitHub repository](https://github.com/Azure/Azure-Sentinel)
- [detection-rules/README.md](detection-rules/README.md) — full rule index with MITRE mapping
- [logic-apps/DEPLOYMENT.md](logic-apps/DEPLOYMENT.md) — Logic App deployment guide
