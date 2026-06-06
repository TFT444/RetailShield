# RetailShield — Microsoft Sentinel Solution Package

This directory contains the deployment package for RetailShield as a Microsoft Sentinel Solution.

## What's included

| Component | Count | Location |
|-----------|-------|----------|
| Analytics rules | 13 | `sentinel/analytics-rules/` |
| Response playbooks | 5 | `logic-apps/` |
| Custom table schemas | 2 | `sentinel/data-connectors/` |
| Solution orchestration template | 1 | `solution/mainTemplate.json` |
| Azure portal UI definition | 1 | `solution/createUiDefinition.json` |

## Quick deployment

### Option A — Deploy everything via Azure CLI

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file solution/mainTemplate.json \
  --parameters \
      workspaceName=<your-workspace-name> \
      complianceContactEmail=security@yourorganisation.com \
      organisationName="Your Organisation Ltd"
```

### Option B — Deploy individual components

```bash
# 1. Create custom tables first
az deployment group create \
  --resource-group <rg> \
  --template-file sentinel/data-connectors/retailshield-connector.json \
  --parameters workspaceName=<workspace>

# 2. Deploy analytics rules
for f in sentinel/analytics-rules/*.json; do
  az deployment group create --resource-group <rg> --template-file "$f" \
    --parameters workspaceName=<workspace>
done

# 3. Deploy playbooks
for f in logic-apps/*/workflow.json; do
  az deployment group create --resource-group <rg> --template-file "$f" \
    --parameters workspaceName=<workspace>
done
```

### Option C — Azure portal (Custom deployment)

1. Navigate to **Deploy a custom template** in the Azure portal
2. Use **Build your own template in the editor** and paste `solution/mainTemplate.json`
3. Use the `createUiDefinition.json` for a guided wizard experience

## Deployment parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `workspaceName` | Yes | — | Log Analytics workspace name |
| `location` | No | Resource group location | Azure region |
| `complianceContactEmail` | No | *(empty)* | Internal compliance contact email for incident-reporting playbook |
| `organisationName` | No | `Retail Organisation` | Organisation name in compliance emails |
| `deployAnalyticsRules` | No | `true` | Deploy all 13 analytics rules |
| `deployPlaybooks` | No | `true` | Deploy all 5 Logic App playbooks |
| `deployDataConnector` | No | `true` | Create custom Log Analytics tables |

## Post-deployment steps

After the ARM deployment completes:

1. **Authorise API connections** — for each Logic App playbook in the Azure portal, open the Logic App → API Connections → Authorise each connection (azuresentinel, office365, mdfc-connection as applicable)

2. **Grant Sentinel Responder role** — for each Logic App's system-assigned managed identity:
   ```bash
   az role assignment create \
     --assignee <managed-identity-object-id> \
     --role "Microsoft Sentinel Responder" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>
   ```

3. **Create watchlists** — RetailShield rules depend on four watchlists. See `docs/deployment_guide.md` for schema and population instructions:
   - `RetailIOCWatchlist` — threat intelligence IOCs
   - `AbuseIPDBWatchlist` — known malicious IPs
   - `RetailServiceAccounts` — excluded automation accounts
   - `RetailSupplierAccounts` — supplier account UPNs

4. **Create automation rules** — link each analytics rule to its recommended playbook via Sentinel → Automation → Create automation rule

5. **Validate** — trigger a test incident in each severity tier and confirm the correct playbook fires

## Architecture

```
RetailShield Solution
├── Data Ingestion
│   ├── RetailShield_POS_CL      (POS terminal events via Data Collector API)
│   └── RetailShield_Logs_CL     (Voice fraud and device events)
│
├── Detection Layer (13 Scheduled Analytics Rules)
│   ├── Critical: Data Exfiltration, Ransomware Indicator
│   ├── High:     Phishing, POS Void/Refund, MFA Fatigue, AI Voice Fraud,
│   │             Credential Stuffing, Gift Card Fraud, POS Anomaly,
│   │             Privileged Role Addition, Supply Chain Anomaly
│   └── Medium:   After-Hours Access, Supplier Impossible Travel
│
└── Response Layer (5 Logic App Playbooks)
    ├── block-ip              — Block attacker IP via Defender for Endpoint
    ├── isolate-endpoint      — Device isolation via Defender for Endpoint
    ├── quarantine-email      — Email quarantine via Defender for Office 365
    ├── suspend-terminal      — Disable POS terminal
    └── incident-reporting    — UK compliance assistant (24h/72h deadlines)
```

## Data connector dependencies

These Sentinel data connectors must be configured separately:

| Connector | Tables | Used by rules |
|-----------|--------|--------------|
| Azure Active Directory | SigninLogs, AuditLogs | mfa_fatigue, credential_stuffing, after_hours_access, supplier_impossible_travel, privileged_role_addition |
| Microsoft Defender for Endpoint | DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents, DeviceEvents, DeviceLogonEvents | data_exfiltration, pos_anomaly, ransomware_indicator, after_hours_access |
| Microsoft Defender for Office 365 | EmailAttachmentInfo, EmailEvents | phishing_detection |
| Azure Diagnostics | AzureDiagnostics | supply_chain_anomaly |
