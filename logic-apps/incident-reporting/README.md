# UK Incident Reporting / Compliance Assistant

## ⚠️ Critical Design Note

**This playbook ASSISTS compliance by drafting and alerting. It never auto-files official government reports.**

Automated submission to regulators requires human judgement. A false or premature report filed with the ICO or NCSC can itself constitute a regulatory failure and carry independent legal consequences. This playbook generates a pre-filled draft and emails it to your designated compliance contact. A qualified person must review, verify, and submit via the official portals.

---

## UK Regulatory Requirements

### Cyber Security and Resilience Bill (2025)

The UK Government's Cyber Security and Resilience Bill imposes a **24-hour early-warning** duty on organisations operating in-scope sectors (operators of essential services, digital service providers, and supply chain organisations). The early warning must be filed with the relevant supervisory authority within 24 hours of becoming aware of a significant incident. A full report follows.

### UK GDPR / Data Protection Act 2018 — ICO Notification

Under UK GDPR Article 33 and the Data Protection Act 2018, organisations must notify the Information Commissioner's Office (ICO) within **72 hours** of becoming aware of a personal data breach, where that breach is likely to result in a risk to individuals’ rights and freedoms. Notification to affected individuals may also be required under Article 34.

### NIS Regulations 2018

Operators of Essential Services and Relevant Digital Service Providers must report incidents with a significant impact on service continuity to their Competent Authority within timelines that vary by sector (typically 72 hours).

### Why it matters — Fines

| Regulation | Maximum penalty |
|---|---|
| UK GDPR / DPA 2018 | **£17.5 million** or **4% of global annual turnover** (whichever is higher) |
| Cyber Security and Resilience Bill | Expected to align with NIS2 enforcement levels |
| NIS Regulations 2018 | Up to **£17 million** |

Missing the notification window without justification is itself an infringement that regulators treat as a separate failure, compounding the original incident.

---

## What This Playbook Does

| Step | Action |
|---|---|
| 1 | Triggers when a **High or Critical** severity Microsoft Sentinel incident is created |
| 2 | Extracts incident details: title, detection timestamp, severity, status, affected accounts / hosts / IPs, MITRE technique |
| 3 | Calculates the **24-hour early-warning deadline** (Cyber Security and Resilience Bill) and the **72-hour full-report deadline** (UK GDPR / ICO) from the incident creation timestamp |
| 4 | Composes a pre-filled draft incident report structured to meet ICO/NCSC reporting requirements |
| 5 | Emails the draft report to your organisation’s **designated compliance contact** (configurable parameter — never a government address) |
| 6 | Posts a comment to the originating Sentinel incident recording that the compliance notification was generated, with both deadline timestamps |

## What This Playbook Does NOT Do

- Does **not** send anything to the ICO, NCSC, or any government body or system
- Does **not** determine whether an incident is legally reportable — that is a DPO/legal determination
- Does **not** replace your incident response plan, legal counsel, or DPO
- Does **not** transmit data outside your Azure tenant (email is sent via your own Office 365 connection)
- Does **not** file on a schedule or retry — it fires once per qualifying incident

---

## Configuration

Deploy using the Azure CLI:

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file logic-apps/incident-reporting/workflow.json \
  --parameters workspaceName=<sentinel-workspace-name> \
               complianceContactEmail=security@yourorganisation.com \
               organisationName="Your Organisation Ltd"
```

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `workspaceName` | Yes | — | Microsoft Sentinel Log Analytics workspace name |
| `complianceContactEmail` | Yes | — | Email address of the designated compliance or security contact who receives draft reports |
| `organisationName` | No | `RetailShield Operator` | Your organisation name, included in the draft report header |
| `logicAppName` | No | `RetailShield-UKIncidentReporting` | Name for the deployed Logic App resource |
| `location` | No | Resource group location | Azure region |

---

## Required Permissions

The Logic App uses a **system-assigned managed identity**. After deployment:

1. Open the Logic App in the Azure portal
2. Go to **Identity → System assigned** and copy the **Object ID**
3. Assign **Microsoft Sentinel Responder** to the managed identity on your Sentinel workspace (required to read incident entities and post comments)

The Office 365 connection requires user-delegated consent. After deployment, open the Logic App in the portal and authorise the Office 365 API connection under **API connections**.

---

## Official Reporting Channels

The compliance email includes direct links to both portals. Your compliance contact must submit through these — no other method is accepted:

| Regulator | Portal | Use for |
|---|---|---|
| Information Commissioner’s Office (ICO) | https://ico.org.uk/for-organisations/report-a-breach/ | Personal data breaches (UK GDPR Article 33) |
| National Cyber Security Centre (NCSC) | https://www.ncsc.gov.uk/section/about-this-website/incident-management | Significant cyber incidents |

---

## Draft Report Structure

The playbook pre-fills the following sections based on incident data from Sentinel. Fields marked `[REVIEWER]` in the email require human input before any submission:

1. Nature of the incident
2. Date and time of detection
3. Systems and data potentially affected *(requires human verification)*
4. Estimated number of individuals affected *(requires DPO input — do not guess)*
5. Likely consequences *(requires human assessment)*
6. Measures taken or proposed *(auto-populated from Sentinel status; must be expanded)*
7. Current investigation status

---

## Automation Rule Setup

To trigger this playbook automatically, create a Sentinel Automation Rule:

1. Go to **Sentinel → Automation → Create → Automation rule**
2. Trigger: **When incident is created**
3. Condition: **Incident severity** → **Equals** → **High**
4. Action: **Run playbook** → select `RetailShield-UKIncidentReporting`
5. Save

If your environment uses the Defender XDR unified portal and has "Critical" as a severity level, add a second condition for Critical.
