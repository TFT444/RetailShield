# MITRE ATT&CK Coverage Matrix

Full cross-reference of RetailShield detection rules against MITRE ATT&CK Enterprise techniques.

| Status | Tactic | Technique ID | Technique Name | Rule File | Severity | Playbook Trigger |
|---|---|---|---|---|---|---|
| ✅ Done | Initial Access | T1566.001 | Spearphishing Attachment | `phishing_detection.kql` | High | `quarantine_email` |
| 🔲 Planned | Collection | T1056.001 | Keylogging (POS) | `pos_anomaly.kql` | High | `suspend_terminal` |
| 🔲 Planned | Persistence | T1078 | Valid Accounts | `after_hours_access.kql` | Medium | `notify-soc` |
| 🔲 Planned | Credential Access | T1110.004 | Credential Stuffing | `credential_stuffing.kql` | High | `block_ip` |
| 🔲 Planned | Exfiltration | T1048 | Exfiltration Over Alt. Protocol | `data_exfiltration.kql` | Critical | `isolate_endpoint` |
| ✅ Done | Impact | T1486 | Data Encrypted for Impact | `ransomware_indicator.kql` | Critical | `isolate_endpoint` |
| 🔲 Planned | Reconnaissance | T1598 | Phishing for Information | `ai_voice_fraud.kql` | High | `notify-soc` |
| 🔲 Planned | Initial Access | T1195 | Supply Chain Compromise | `supply_chain_anomaly.kql` | High | `block_ip` |
