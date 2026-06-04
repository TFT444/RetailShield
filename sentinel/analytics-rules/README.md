# RetailShield — Sentinel Analytics Rule Templates

This directory contains 13 ARM template files, one per retail detection rule, ready to deploy as Microsoft Sentinel Scheduled Analytics Rules.

## Rules

| File | Display Name | Severity | Frequency | MITRE Technique |
|------|-------------|----------|-----------|-----------------|
| `after_hours_access.json` | After-Hours System Access Detection | Medium | 5 min | T1078 |
| `ai_voice_fraud.json` | AI-Assisted Voice Fraud (Vishing) Detection | High | 30 min | T1598 |
| `credential_stuffing.json` | Credential Stuffing Attack Detection | High | 5 min | T1110.004 |
| `data_exfiltration.json` | Data Exfiltration via Alternative Protocol | Critical | 5 min | T1048 |
| `gift_card_fraud.json` | Gift Card Fraud Pattern Detection | High | 5 min | T1657 |
| `mfa_fatigue.json` | MFA Fatigue / Push Bombing Attack | High | 5 min | T1621 |
| `phishing_detection.json` | Retail Phishing Email Detection | High | 5 min | T1566.001 |
| `pos_anomaly.json` | POS Terminal Anomaly Detection | High | 15 min | T1056.001 |
| `pos_void_refund.json` | POS Void/Refund Fraud Pattern | High | 5 min | T1056.001 |
| `privileged_role_addition.json` | Privileged Role Assignment Detection | High | 5 min | T1098/T1078 |
| `ransomware_indicator.json` | Ransomware Indicator Detection | Critical | 5 min | T1486 |
| `supplier_impossible_travel.json` | Supplier Impossible Travel Detection | Medium | 15 min | T1199/T1078 |
| `supply_chain_anomaly.json` | Supply Chain / Third-Party Anomaly Detection | High | 30 min | T1195 |

## Deployment

### Deploy a single rule

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file sentinel/analytics-rules/phishing_detection.json \
  --parameters workspaceName=<your-workspace-name>
```

### Deploy all rules

```bash
for f in sentinel/analytics-rules/*.json; do
  az deployment group create \
    --resource-group <your-resource-group> \
    --template-file "$f" \
    --parameters workspaceName=<your-workspace-name>
done
```

### Import via Sentinel UI

1. Open Microsoft Sentinel → **Analytics** → **Import**
2. Select one or more `.json` files from this directory
3. Review each rule's settings and enable

## Template Structure

Each template follows the `Microsoft.OperationalInsights/workspaces/providers/alertRules` ARM schema:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "parameters": { "workspaceName": { "type": "string" } },
  "resources": [{
    "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
    "apiVersion": "2022-11-01-preview",
    "kind": "Scheduled",
    "properties": {
      "displayName": "...",
      "severity": "High|Critical|Medium",
      "query": "<inline KQL>",
      "queryFrequency": "PT5M",
      "queryPeriod": "PT5M",
      "tactics": ["..."],
      "techniques": ["T...."],
      "entityMappings": [...],
      "customDetails": { "PlaybookTrigger": "...", "RiskScore": "..." }
    }
  }]
}
```

## Watchlist Dependencies

Several rules require these watchlists to be deployed first (see `docs/deployment_guide.md`):

| Watchlist | Used By |
|-----------|---------|
| `RetailIOCWatchlist` | data_exfiltration, ransomware_indicator |
| `AbuseIPDBWatchlist` | credential_stuffing |
| `RetailServiceAccounts` | after_hours_access |
| `RetailSupplierAccounts` | supplier_impossible_travel |
