# RetailShield — Containment Playbook

**Playbook ID:** RetailShield-Containment  
**Trigger:** Microsoft Sentinel incident  
**Severity target:** High (identity / endpoint alerts)

## What it does

When triggered by a Sentinel incident containing IP, Account, or Host entities, this playbook:

1. **Blocks attacker IPs** — creates or overwrites a single Deny-Inbound NSG security rule (`RetailShield-Block-Inbound`, priority 4000) listing all incident IPs in `sourceAddressPrefixes`, using the Logic App's Managed Identity to call the Azure management API.
2. **Disables compromised accounts** — sets `accountEnabled: false` on each Azure AD account entity via the AAD connector (Managed Identity).
3. **Isolates endpoints** — calls the Microsoft Defender for Endpoint REST API to fully isolate each host entity, preventing lateral movement.
4. **Posts a summary comment** — adds a formatted Markdown comment to the Sentinel incident listing all containment actions taken.

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `PlaybookName` | string | Logic App resource name (default: `RetailShield-Containment`) |
| `TenantId` | string | Azure AD tenant ID — used for Defender OAuth2 token requests |
| `SubscriptionId` | string | Subscription containing the target NSG (default: deployment subscription) |
| `NSGResourceGroup` | string | Resource group of the perimeter NSG |
| `NSGName` | string | Name of the NSG to inject the block rule into |
| `DefenderClientId` | string | App registration client ID with `Machine.Isolate` on the MDE API |
| `DefenderClientSecret` | securestring | Client secret — use a Key Vault reference in production |

## Deployment

```bash
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file workflow.json \
  --parameters \
      TenantId=<tenant-id> \
      NSGResourceGroup=<nsg-rg> \
      NSGName=<nsg-name> \
      DefenderClientId=<app-client-id> \
      DefenderClientSecret=<app-client-secret>
```

## Post-deployment: grant Managed Identity roles

After deploying, retrieve the playbook's system-assigned identity and assign roles:

```bash
PRINCIPAL_ID=$(az logic workflow show \
  --resource-group <sentinel-rg> \
  --name RetailShield-Containment \
  --query identity.principalId -o tsv)

# Network Contributor on the NSG resource group — to write security rules
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Network Contributor" \
  --scope /subscriptions/<sub-id>/resourceGroups/<nsg-rg>

# Microsoft Sentinel Responder — to post incident comments
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub-id>/resourceGroups/<sentinel-rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>
```

For the Azure AD connector, also grant the Managed Identity **User Administrator** (or a custom role with `microsoft.directory/users/disable/action`) in Entra ID.

For Defender for Endpoint, the app registration (`DefenderClientId`) needs the **Machine.Isolate** application permission on the `WindowsDefenderATP` API, approved by an admin.

## Automation rule wiring

Create a Sentinel Automation Rule to trigger this playbook on High-severity incidents:

1. **Sentinel → Automation → Create → Automation rule**
2. Conditions: Incident severity `=` High
3. Actions: Run playbook → `RetailShield-Containment`

For targeted containment, scope the trigger to specific analytics rule names (RS-SSE-001 through RS-SSE-004).

## Notes

- The NSG rule `RetailShield-Block-Inbound` at priority 4000 is overwritten on each trigger, consolidating all blocked IPs from the latest incident. For persistent block lists across multiple incidents, consider a watchlist-fed NSG update script instead.
- If no IP entities are present in the incident, the NSG block step is skipped.
- `DefenderClientSecret` is a `SecureString` parameter and is not visible in run history logs. For production, replace with a Key Vault reference: `[reference(resourceId('Microsoft.KeyVault/vaults/secrets', '<vault>', '<secret>'), '2022-07-01').secretUriWithVersion]`.
