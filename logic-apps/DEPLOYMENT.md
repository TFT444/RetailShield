# RetailShield Logic Apps — Deployment Guide

This guide covers deploying all three RetailShield Azure Logic App playbooks into an existing Microsoft Sentinel workspace.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Azure subscription | Owner or Contributor on the target resource group |
| Microsoft Sentinel workspace | Must be in the same subscription (cross-subscription is possible but requires extra role setup) |
| Azure CLI | `az --version` ≥ 2.50 |
| AbuseIPDB API key | Free tier at [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| VirusTotal API key | Free public API at [virustotal.com](https://www.virustotal.com) |
| App registration for Defender | See [Defender for Endpoint prerequisites](#defender-for-endpoint-app-registration) below |

---

## 1. Authenticate with Azure

```bash
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

---

## 2. Deploy each playbook

All three playbooks are ARM templates deployable with `az deployment group create`. Deploy into the **same resource group** as your Sentinel workspace.

### 2a. RetailShield-TriageClassify

No API keys required — uses only the Sentinel connector.

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file logic-apps/triage-classify/workflow.json
```

Optional: override the playbook name:

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file logic-apps/triage-classify/workflow.json \
  --parameters PlaybookName="RetailShield-TriageClassify"
```

### 2b. RetailShield-ThreatIntelEnrich

Requires AbuseIPDB and VirusTotal API keys.

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file logic-apps/threat-intel-enrich/workflow.json \
  --parameters \
      AbuseIPDBApiKey="<abuseipdb-key>" \
      VirusTotalApiKey="<virustotal-key>"
```

Optional tuning parameters (showing defaults):

```bash
  --parameters \
      AbuseIPDBThreshold=75 \
      VirusTotalThreshold=3
```

### 2c. RetailShield-Containment

Requires NSG details and a Defender for Endpoint app registration.

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file logic-apps/containment/workflow.json \
  --parameters \
      TenantId="<tenant-id>" \
      NSGResourceGroup="<nsg-rg>" \
      NSGName="<nsg-name>" \
      DefenderClientId="<app-client-id>" \
      DefenderClientSecret="<app-client-secret>"
```

> **Security note:** Do not put secrets directly in shell history. Prefer using `@<parameters-file>.json` or Azure Key Vault references for production deployments.

---

## 3. Grant Managed Identity roles

Each playbook uses a **system-assigned Managed Identity**. After deployment, assign the required roles.

### 3a. Retrieve principal IDs

```bash
TRIAGE_PID=$(az logic workflow show \
  --resource-group <sentinel-rg> --name RetailShield-TriageClassify \
  --query identity.principalId -o tsv)

ENRICH_PID=$(az logic workflow show \
  --resource-group <sentinel-rg> --name RetailShield-ThreatIntelEnrich \
  --query identity.principalId -o tsv)

CONTAIN_PID=$(az logic workflow show \
  --resource-group <sentinel-rg> --name RetailShield-Containment \
  --query identity.principalId -o tsv)
```

### 3b. Microsoft Sentinel Responder (all three playbooks)

Required to read incident entities and post comments.

```bash
SENTINEL_SCOPE="/subscriptions/<sub-id>/resourceGroups/<sentinel-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"

for PID in $TRIAGE_PID $ENRICH_PID $CONTAIN_PID; do
  az role assignment create \
    --assignee $PID \
    --role "Microsoft Sentinel Responder" \
    --scope $SENTINEL_SCOPE
done
```

### 3c. Network Contributor (Containment only)

Required to write NSG security rules.

```bash
az role assignment create \
  --assignee $CONTAIN_PID \
  --role "Network Contributor" \
  --scope /subscriptions/<sub-id>/resourceGroups/<nsg-rg>
```

### 3d. Azure AD User Administrator (Containment only)

Required to disable user accounts. Grant in Entra ID (Azure AD):

1. Open **Entra ID → Roles and administrators → User Administrator**
2. Click **Add assignments**
3. Search for the Managed Identity by principal ID and add it

Alternatively, grant a custom role with only `microsoft.directory/users/disable/action` for least privilege.

---

## 4. Defender for Endpoint app registration

The Containment playbook uses OAuth2 client credentials to call the MDE REST API.

1. **Register an app** in Entra ID: Entra ID → App registrations → New registration
2. **Add API permission**: APIs my organization uses → `WindowsDefenderATP` → Application permissions → `Machine.Isolate`
3. **Grant admin consent** for the permission
4. **Create a client secret**: Certificates & secrets → New client secret
5. Note down the **Application (client) ID** and **secret value** for deployment parameters

---

## 5. Authorize API connections

After deploying with Managed Identity (`parameterValueType: Alternative`), the API connections are pre-authorized for the Managed Identity. Verify in the Azure portal:

1. Open the **azuresentinel-RetailShield-*** connection resource
2. **Edit API connection → Authorize** (if shown as unauthorized)
3. Repeat for **azuread-RetailShield-Containment**

---

## 6. Wire playbooks to Sentinel Automation Rules

Create automation rules to trigger playbooks automatically on matching incidents.

### Recommended automation rule order

| Order | Playbook | Condition | Action |
|---|---|---|---|
| 1 | RetailShield-TriageClassify | Any new incident | Run playbook |
| 2 | RetailShield-ThreatIntelEnrich | Any incident with IP entities | Run playbook |
| 3 | RetailShield-Containment | Severity = High AND rule in [RS-SSE-001, RS-SSE-002, RS-SSE-003] | Run playbook |

**Steps (Sentinel portal):**

1. **Microsoft Sentinel → Automation → Create → Automation rule**
2. Set the **Trigger**: When incident is created
3. Add **Conditions** as per the table above
4. Add **Action**: Run playbook → select the playbook
5. Save

Repeat for each rule.

---

## 7. Verify deployment

```bash
# Check all three playbooks are in Enabled state
az logic workflow list \
  --resource-group <sentinel-rg> \
  --query "[?contains(name, 'RetailShield')].{Name:name, State:state}" \
  -o table
```

Expected output:
```
Name                                State
----------------------------------  -------
RetailShield-Containment            Enabled
RetailShield-ThreatIntelEnrich      Enabled
RetailShield-TriageClassify         Enabled
```

Then fire a test incident in Sentinel and check the **Run history** for each Logic App.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Playbook fails with `403 Forbidden` on Sentinel actions | Managed Identity lacks Sentinel Responder role | Re-run step 3b |
| NSG block action fails with `AuthorizationFailed` | Managed Identity lacks Network Contributor | Re-run step 3c |
| Account disable fails | Managed Identity not assigned User Administrator in Entra ID | Complete step 3d |
| Defender isolation returns `404` | Machine not enrolled in MDE or hostname mismatch | Check `computerDnsName` in MDE portal |
| AbuseIPDB returns `429 Too Many Requests` | Free tier rate limit (1,000 checks/day) | Upgrade API tier or add a Logic App delay action |
| VirusTotal returns `401 Unauthorized` | Invalid or expired API key | Rotate the key and redeploy with new `VirusTotalApiKey` parameter |
