# Open Issue Audit

Audit date: 2026-06-01  
Auditor: Tanvir Farhad

All 28 open issues were reviewed against the current codebase and the project direction: **RetailShield is a retail threat detection and incident response content pack for Microsoft Sentinel**.

Each issue has been commented with one of three assessments. No issues were closed — all close decisions are left to the maintainer.

---

## Assessment legend

| Assessment | Meaning |
|---|---|
| `completed-by-existing-code` | The issue has already been addressed by code merged to `dev` |
| `fits-retail-direction` | The issue is valid and aligns with the Sentinel content pack direction |
| `scope-creep-recommend-close` | The issue is out of scope or contradicts the content pack positioning |

---

## Results

### completed-by-existing-code (18 issues)

| Issue | Title | Notes |
|---|---|---|
| #2 | POS anomaly rule | `detection-rules/retail/pos_anomaly.kql` — RS-POS-001, merged |
| #3 | After-hours access rule | `detection-rules/retail/after_hours_access.kql` — RS-AHA-001, merged |
| #4 | Credential stuffing rule | `detection-rules/retail/credential_stuffing.kql` — RS-CRD-001, merged |
| #5 | Data exfiltration rule | `detection-rules/retail/data_exfiltration.kql` — RS-EXF-001, merged |
| #6 | Ransomware indicator rule | `detection-rules/retail/ransomware_indicator.kql` — RS-RAN-001, merged |
| #7 | AI voice fraud rule | `detection-rules/retail/ai_voice_fraud.kql` — RS-VOI-001, merged |
| #8 | Supply chain anomaly rule | `detection-rules/retail/supply_chain_anomaly.kql` — RS-SUP-001, merged |
| #30 | Containment Logic App | `logic-apps/containment/workflow.json` exists |
| #31 | Threat-intel enrichment Logic App | `logic-apps/threat-intel-enrich/workflow.json` exists |
| #32 | Triage-classify Logic App | `logic-apps/triage-classify/workflow.json` exists |
| #33 | Logic Apps deployment docs | `logic-apps/DEPLOYMENT.md` exists |
| #34 | Fix automated-response claims in README | Addressed by PR #61 (README rewrite) |
| #40 | Credential stuffing + after-hours rules | Both merged, reorganised in PR #60 |
| #41 | Data exfiltration rule | Merged, reorganised in PR #60 |
| #44 | Remove ransomware stub duplicate | Flat structure removed in PR #60 |
| #56 | Reorganise detection-rules/ | PR #60 open for review |
| #57 | Reposition README | PR #61 open for review |
| #58 | Add CONTENT_PACK.md | PR #62 open for review |

### fits-retail-direction (7 issues)

| Issue | Title | Notes |
|---|---|---|
| #9 | block_ip Logic App | Referenced by RS-MFA-001, RS-CRD-001 — needs dedicated ARM template |
| #10 | isolate_endpoint Logic App | Referenced by RS-RAN-001 — high priority |
| #11 | quarantine_email Logic App | Referenced by RS-PHI-001 — medium priority |
| #12 | suspend_terminal Logic App | Referenced by RS-POS-001 — retail-specific, good differentiator |
| #14 | Full deployment guide | End-to-end Sentinel workspace setup guide needed |
| #15 | KQL rule validation tests | Quality gate for content pack — update paths to retail/generic after PR #60 |
| #59 | This audit | Tracking issue |

### scope-creep-recommend-close (3 issues)

| Issue | Title | Reason |
|---|---|---|
| #13 | React SOC dashboard | A standalone React app is not a Sentinel content type. Use Sentinel Workbook instead. |
| #27 | Connect CVE scanner to dashboard | CVE scanner is not a Sentinel content pack component. |
| #28 | Unit tests for CVE scanner | CVE scanner is out of scope. KQL rule tests are tracked in #15. |

---

## Open PRs awaiting review

| PR | Task | Branch |
|---|---|---|
| #60 | Reorganise detection-rules/ into retail/ and generic/ | `feature/reorganise-detection-rules` |
| #61 | Reposition README as Sentinel content pack | `feature/reposition-readme` |
| #62 | Add CONTENT_PACK.md | `feature/add-content-pack-doc` |
| #63 | Issue audit (this PR) | `feature/audit-open-issues` |
