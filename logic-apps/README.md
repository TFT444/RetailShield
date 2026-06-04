# Logic Apps (SOAR Playbooks)

Azure Logic App workflow definitions for automated incident response and UK regulatory compliance assistance.

## Containment Playbooks

Triggered automatically via Sentinel Automation Rules when the `PlaybookTrigger` custom detail in an alert matches the trigger value.

| Workflow | Trigger Value | Action |
|---|---|---|
| `block-ip/` | `block_ip` | Adds the offending IP to an Entra ID Conditional Access named location to block sign-ins |
| `isolate-endpoint/` | `isolate_endpoint` | Isolates the device via the Microsoft Defender for Endpoint API |
| `quarantine-email/` | `quarantine_email` | Notifies the affected mailbox user and submits the mail message to Defender for Office 365 quarantine review |
| `suspend-terminal/` | `suspend_terminal` | Calls the POS management REST API to suspend the identified terminal (API key retrieved from Key Vault) |

## Compliance Playbooks

| Workflow | Trigger | Action |
|---|---|---|
| `incident-reporting/` | High or Critical severity incident created | Calculates UK 24h / 72h regulatory deadlines, drafts an ICO/NCSC-format incident report, and emails the designated compliance contact. **Never auto-files with any government body.** See [`incident-reporting/README.md`](incident-reporting/README.md). |

## Other Playbooks (In Development)

| Workflow | Purpose |
|---|---|
| `triage-classify/` | Auto-triage incoming Sentinel incidents and assign severity |
| `threat-intel-enrich/` | Enrich IOCs via VirusTotal, AbuseIPDB, and Microsoft Threat Intelligence |
| `containment/` | Generalised containment actions (block IP, disable AD account, isolate host) |

## Deployment

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for full step-by-step deployment instructions, including role assignments and API connection authorisation steps.

Quick deploy example:

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file logic-apps/block-ip/workflow.json \
  --parameters workspaceName=<sentinel-workspace>
```
