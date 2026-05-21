# Logic Apps (SOAR Playbooks)

Azure Logic App workflow definitions for automated incident response.

| Workflow | Purpose |
|---|---|
| `triage-classify/` | Auto-triage incoming Sentinel incidents and assign severity |
| `threat-intel-enrich/` | Enrich IOCs via VirusTotal, AbuseIPDB, and Microsoft TI |
| `containment/` | Block IP, disable AD account, or isolate host via Defender |
