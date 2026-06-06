# RetailShield Deployment Guide

This guide walks through deploying RetailShield into a Microsoft Sentinel workspace from scratch.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Create the Sentinel Workspace](#1-create-the-sentinel-workspace)
3. [Connect Data Sources](#2-connect-data-sources)
4. [Deploy Custom Log Tables](#3-deploy-custom-log-tables)
5. [Configure Watchlists](#4-configure-watchlists)
6. [Deploy Detection Rules](#5-deploy-detection-rules)
7. [Deploy Logic App Playbooks](#6-deploy-logic-app-playbooks)
8. [Configure Automation Rules](#7-configure-automation-rules)
9. [Validate the Deployment](#8-validate-the-deployment)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Detail |
|---|---|
| Azure subscription | Contributor or Owner role |
| Microsoft Sentinel | Enabled on a Log Analytics workspace |
| Microsoft Defender for Endpoint | Required for endpoint detection rules |
| Microsoft Defender for Office 365 | Required for phishing / email rules |
| Microsoft Entra ID P2 | Required for sign-in risk and MFA rules |
| Azure CLI or PowerShell | For ARM template deployments |
| Git | To clone this repository |

Clone the repository:

```bash
git clone https://github.com/tft444/retailshield.git
cd retailshield
```

---

## 1. Create the Sentinel Workspace

Skip this section if you already have a Sentinel-enabled Log Analytics workspace.

1. In the Azure portal, search for **Microsoft Sentinel** and click **Create**.
2. Click **Create a new workspace**, fill in the resource group, name, and region.
3. Click **Review + Create**, then **Create**.
4. Once the workspace is provisioned, click **Add Microsoft Sentinel** to enable it on the workspace.

Note the **workspace name** and **resource group** — you will use them throughout this guide.

---

## 2. Connect Data Sources

RetailShield detection rules require the following data connectors. Enable each one in **Sentinel → Content hub** or **Data connectors**.

### Microsoft Entra ID (Azure AD)

Required for: `mfa_fatigue.kql`, `credential_stuffing.kql`, `after_hours_access.kql`, `supplier_impossible_travel.kql`, `privileged_role_addition.kql`

1. Go to **Sentinel → Data connectors**.
2. Search for **Microsoft Entra ID** and click **Open connector page**.
3. Enable **Sign-in logs** and **Audit logs**.
4. Tables populated: `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`

### Microsoft Defender for Endpoint (via Defender XDR)

Required for: `ransomware_indicator.kql`, `pos_anomaly.kql`, `data_exfiltration.kql`

1. Search for **Microsoft Defender XDR** in Data connectors.
2. Enable **Incidents & alerts** and **Advanced Hunting** tables.
3. Tables populated: `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceEvents`

### Microsoft Defender for Office 365

Required for: `phishing_detection.kql`

1. Search for **Microsoft Defender for Office 365** and open the connector page.
2. Enable **Alerts** and click **Apply changes**.
3. Tables populated: `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`

### Azure Activity

Required for: `supply_chain_anomaly.kql`

1. Search for **Azure Activity** and open the connector page.
2. Follow the instructions to connect your subscription via diagnostic settings.
3. Table populated: `AzureActivity`

---

## 3. Deploy Custom Log Tables

Two custom tables are required for RetailShield's POS and voice-fraud rules.

### RetailShield_POS_CL

Used by: `pos_void_refund.kql`, `gift_card_fraud.kql`

This table receives transaction events from your POS integration layer. Create it by sending a sample payload via the Log Analytics HTTP Data Collector API, or by using the **Tables** blade in your Log Analytics workspace.

**Minimum schema:**

| Column | Type | Description |
|---|---|---|
| `OperatorId_s` | string | POS operator identifier |
| `StoreId_s` | string | Store identifier |
| `TerminalId_s` | string | Terminal identifier |
| `TransactionType_s` | string | e.g. VOID, REFUND, SALE |
| `TenderType_s` | string | e.g. CASH, CREDIT, GIFT_CARD |
| `Amount_d` | real | Transaction amount |
| `OverrideApproved_b` | bool | Whether a manager override was applied |
| `TimeGenerated` | datetime | Event timestamp (UTC) |

To ingest data, configure your POS middleware to POST JSON to the [Log Analytics HTTP Data Collector endpoint](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api).

### RetailShield_Logs_CL

Used by: `pos_anomaly.kql`, `ai_voice_fraud.kql`

**Minimum schema:**

| Column | Type | Description |
|---|---|---|
| `EventType_s` | string | e.g. AI_Voice_Fraud, POS_Transaction |
| `DeviceName_s` | string | Source device or terminal |
| `TargetEmployee_s` | string | Employee targeted by the event |
| `ImpersonatingEntity_s` | string | Caller or entity impersonating a known role |
| `RequestMade_s` | string | Action or transfer requested |
| `AIConfidence_d` | real | AI model confidence score (0–1) |
| `CallerNumber_s` | string | Originating phone number |
| `FraudKeywordHit_s` | string | Keyword that triggered detection |
| `TimeGenerated` | datetime | Event timestamp (UTC) |

---

## 4. Configure Watchlists

RetailShield uses five watchlists. Create each one in **Sentinel → Watchlists → Add new**.

### RetailIOCWatchlist

Contains known-bad IP addresses and domains used as indicators of compromise.

| Column | Type |
|---|---|
| `IndicatorValue` | string (IP or domain) |
| `IndicatorType` | string (IP / Domain) |
| `ThreatType` | string |
| `Confidence` | int |
| `Source` | string |

### RetailApprovedSenders

List of trusted sender domains for the phishing detection rule.

| Column | Type |
|---|---|
| `SenderDomain` | string |
| `BusinessUnit` | string |

### AbuseIPDBWatchlist

List of IPs with high abuse confidence scores, used by the credential stuffing rule. Export from AbuseIPDB and import as CSV.

| Column | Type |
|---|---|
| `IPAddress` | string |
| `AbuseConfidenceScore` | int |
| `CountryCode` | string |

### RetailSupplierAccounts

List of supplier user accounts for the impossible travel rule.

| Column | Type |
|---|---|
| `UserPrincipalName` | string |
| `SupplierName` | string |
| `HomeCountry` | string |

### RetailServiceAccounts

List of service accounts to exclude from the after-hours access rule.

| Column | Type |
|---|---|
| `AccountName` | string |
| `Description` | string |

To create a watchlist:

1. Go to **Sentinel → Watchlists** and click **Add new**.
2. Enter the watchlist name (must match exactly as listed above), alias, and description.
3. Upload your CSV file. Map the **SearchKey** to the primary lookup column.
4. Click **Review + create**.

---

## 5. Deploy Detection Rules

All KQL detection rules are in `detection-rules/retail/` and `detection-rules/generic/`. Import them as Sentinel **Scheduled query** analytics rules.

### Method A — Manual import via the Sentinel UI

1. Go to **Sentinel → Analytics** and click **Create → Scheduled query rule**.
2. On the **Set rule logic** tab, paste the KQL from the relevant `.kql` file.
3. Fill in the rule name, description, severity, and MITRE ATT&CK mapping from the file header comments.
4. Set the query scheduling frequency to match the `// Frequency:` comment in the file (5 min or 15 min).
5. Set the lookback window to the `// LookbackWindow:` value.
6. On the **Automated response** tab, map the `PlaybookTrigger` field value to the corresponding Logic App (see section 7).
7. Save and enable the rule.

### Method B — ARM template deployment

You can script the import using the Azure CLI:

```bash
# Set your workspace details
RG="my-sentinel-rg"
WS="my-sentinel-workspace"
SUBID=$(az account show --query id -o tsv)

# Example: deploy a single rule via REST
RULE_NAME="RetailShield-PhishingDetection"
KQL=$(cat detection-rules/retail/phishing_detection.kql)

az rest \
  --method PUT \
  --url "https://management.azure.com/subscriptions/${SUBID}/resourceGroups/${RG}/providers/Microsoft.OperationalInsights/workspaces/${WS}/providers/Microsoft.SecurityInsights/alertRules/${RULE_NAME}?api-version=2023-02-01" \
  --body "{
    \"kind\": \"Scheduled\",
    \"properties\": {
      \"displayName\": \"RetailShield — Phishing Detection\",
      \"query\": \"${KQL}\",
      \"severity\": \"High\",
      \"enabled\": true,
      \"queryFrequency\": \"PT5M\",
      \"queryPeriod\": \"PT5M\",
      \"triggerOperator\": \"GreaterThan\",
      \"triggerThreshold\": 0
    }
  }"
```

Repeat for each rule file. The rule name, severity, frequency, and query period values are documented in the header comment block of each `.kql` file.

---

## 6. Deploy Logic App Playbooks

ARM templates for all four playbooks are in `logic-apps/`. Each template creates a Consumption-tier Logic App triggered by a Sentinel incident.

```
logic-apps/
  block-ip/workflow.json
  isolate-endpoint/workflow.json
  quarantine-email/workflow.json
  suspend-terminal/workflow.json
```

Deploy a playbook with the Azure CLI:

```bash
RG="my-sentinel-rg"
WS="my-sentinel-workspace"

az deployment group create \
  --resource-group $RG \
  --template-file logic-apps/block-ip/workflow.json \
  --parameters workspaceName=$WS
```

Repeat for each playbook. After deployment, you must grant the Logic App's **managed identity** the following roles:

| Playbook | Role required |
|---|---|
| `block_ip` | Conditional Access Administrator (Entra ID) |
| `isolate_endpoint` | Security Administrator (via Defender for Endpoint API) |
| `quarantine_email` | Security Reader + Exchange Administrator |
| `suspend_terminal` | Contributor on the Logic App / target resource group |

To assign the managed identity:

1. Open the deployed Logic App in the Azure portal.
2. Go to **Identity → System assigned** and copy the **Object ID**.
3. Go to **Microsoft Entra ID → Roles and administrators**, select the required role, and add the Object ID as an assignment.

---

## 7. Configure Automation Rules

Automation rules route Sentinel incidents to the correct playbook based on the `PlaybookTrigger` alert detail.

1. Go to **Sentinel → Automation** and click **Create → Automation rule**.
2. Set the trigger to **When incident is created**.
3. Add a condition: **Alert detail** → **Custom details key** `PlaybookTrigger` → **equals** `block_ip` (or the relevant value).
4. Add an action: **Run playbook** → select the corresponding Logic App.
5. Save the rule.

Create one automation rule per `PlaybookTrigger` value:

| PlaybookTrigger value | Logic App |
|---|---|
| `block_ip` | block-ip |
| `isolate_endpoint` | isolate-endpoint |
| `quarantine_email` | quarantine-email |
| `suspend_terminal` | suspend-terminal |
| `notify_soc` | (send Teams/email notification — configure separately) |
| `data_exfil_contain` | (custom containment flow — extend as needed) |

---

## 8. Validate the Deployment

### Run the test suite locally

The test suite validates rule file structure and metadata without a live Sentinel connection:

```bash
pip install pytest
pytest tests/ -v
```

All tests should pass. A failure indicates a missing rule file or a metadata mismatch.

### Validate KQL syntax

```bash
python scripts/validate_kql.py
```

This checks that all `.kql` files reference only known tables and contain required metadata fields.

### End-to-end smoke test

1. Open **Sentinel → Logs** and run a small query against each required table to confirm data is flowing:

   ```kql
   SigninLogs | take 5
   EmailEvents | take 5
   DeviceNetworkEvents | take 5
   RetailShield_POS_CL | take 5
   RetailShield_Logs_CL | take 5
   ```

2. Manually trigger a test incident by simulating a detection. For example, to test `mfa_fatigue.kql`, generate more than 10 MFA prompts from multiple source IPs against a test account.

3. Confirm the incident appears in **Sentinel → Incidents** with the correct severity, MITRE mapping, and playbook trigger field.

4. Confirm the automation rule fires the correct Logic App and that the playbook run shows as **Succeeded** in **Logic Apps → Run history**.

---

## Troubleshooting

### KQL validation fails with unknown table

Ensure the data connector for the table is enabled and data has started flowing. Run:

```kql
search * | distinct $table | sort by $table asc
```

to list all tables in your workspace.

### Watchlist lookup returns no results

Verify the watchlist alias matches exactly (case-sensitive) the string used in `_GetWatchlist()` within the KQL rule. Check the watchlist is not empty.

### Logic App fails with 403

The managed identity is missing the required role. See section 6 for role assignments.

### Automation rule does not fire

Confirm the **Custom details** are mapped in the analytics rule settings. Go to the rule → **Edit** → **Set rule logic** → **Alert enrichment → Custom details**, and add a mapping for `PlaybookTrigger` pointing to the `PlaybookTrigger` projected column in the KQL output.

### Rule produces no incidents in testing

Check that the query lookback window covers the time range of your test data. Lower the detection thresholds temporarily (e.g., reduce `MFAPromptThresh` from 10 to 2) and re-test. Reset thresholds after validation.
