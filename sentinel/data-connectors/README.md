# RetailShield — Data Connector Definition

This directory contains the ARM template that provisions the two custom Log Analytics tables used by RetailShield detection rules.

## Custom Tables

### RetailShield_POS_CL

Point-of-sale transaction events from retail terminals. Used by:

| Detection Rule | Event Types |
|---------------|-------------|
| `pos_void_refund.kql` | `pos_void_refund` |
| `gift_card_fraud.kql` | `gift_card_fraud` |
| `pos_anomaly.kql` | `pos_anomaly` (also uses `RetailShield_Logs_CL`) |

**Key columns:**

| Column | Type | Description |
|--------|------|-------------|
| `TerminalID` | string | POS terminal identifier |
| `StoreID` | string | Retail store identifier |
| `EmployeeID` | string | Cashier/operator who performed the transaction |
| `OperatorID` | string | Supervisor who authorised void/refund |
| `TransactionType` | string | Sale, Void, Refund, GiftCardIssue, GiftCardReload, GiftCardRedeem, NoSale |
| `TransactionAmount` | real | Value in GBP |
| `VoidCount` | int | Void transaction count in detection window |
| `RefundCount` | int | Refund transaction count in detection window |
| `TotalGiftCardValue` | real | Aggregate gift card transaction value |
| `RiskScore` | int | RetailShield risk score (0–100) |
| `PlaybookTrigger` | string | Recommended response playbook |

### RetailShield_Logs_CL

General RetailShield log events covering voice fraud detection and POS device anomalies. Used by:

| Detection Rule | Event Types |
|---------------|-------------|
| `ai_voice_fraud.kql` | `voice_fraud` |
| `pos_anomaly.kql` | `pos_anomaly` |

**Key columns:**

| Column | Type | Description |
|--------|------|-------------|
| `EventType` | string | voice_fraud, pos_anomaly, network_anomaly |
| `CallerID` | string | Caller identifier or phone number (voice fraud) |
| `CallCount` | int | Call volume within detection window |
| `VoiceAnomalyScore` | real | AI anomaly score 0.0–1.0 |
| `ProcessName` | string | Suspicious process name (POS anomaly) |
| `DeviceName` | string | Host device name |
| `RiskScore` | int | RetailShield risk score (0–100) |
| `PlaybookTrigger` | string | Recommended response playbook |

## Deployment

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file sentinel/data-connectors/retailshield-connector.json \
  --parameters workspaceName=<your-workspace-name>
```

This creates both custom tables in the workspace. Tables must exist before deploying analytics rules or ingesting data.

## Data Ingestion

Use the [Log Analytics Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api) or the Azure Monitor Ingestion API (DCR-based) to send records to these tables from your POS middleware or SIEM feed:

```bash
# Example ingestion via REST (simplified)
POST https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01
Content-Type: application/json
Log-Type: RetailShield_POS
x-ms-date: <RFC 7231 date>
Authorization: SharedKey <workspace-id>:<signature>

[{"TerminalID":"POS-001","StoreID":"ST-042","EmployeeID":"EMP-123",...}]
```

## Standard Tables Also Used

The following built-in Sentinel/Defender tables are referenced by RetailShield rules and require the corresponding data connectors to be enabled in your workspace:

| Table | Data Connector |
|-------|---------------|
| `SigninLogs` | Azure Active Directory |
| `AuditLogs` | Azure Active Directory |
| `DeviceNetworkEvents` | Microsoft Defender for Endpoint |
| `DeviceFileEvents` | Microsoft Defender for Endpoint |
| `DeviceProcessEvents` | Microsoft Defender for Endpoint |
| `DeviceEvents` | Microsoft Defender for Endpoint |
| `DeviceLogonEvents` | Microsoft Defender for Endpoint |
| `EmailAttachmentInfo` | Microsoft Defender for Office 365 |
| `EmailEvents` | Microsoft Defender for Office 365 |
| `AzureDiagnostics` | Azure Diagnostics |
