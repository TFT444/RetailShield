# MITRE ATT&CK Coverage Matrix

Full cross-reference of RetailShield detection rules against MITRE ATT&CK Enterprise techniques.

| Status | Tactic | Technique ID | Technique Name | Rule File | Severity | Playbook Trigger |
|---|---|---|---|---|---|---|
| ✅ Done | Initial Access | T1566.001 | Spearphishing Attachment | `phishing_detection.kql` | High | `quarantine_email` |
| ✅ Done | Collection | T1056.001 | Keylogging / RAM Scraping | `pos_anomaly.kql` | High | `suspend_terminal` |
| ✅ Done | Persistence | T1078 | Valid Accounts (After-Hours) | `after_hours_access.kql` | Medium | `notify_soc` |
| ✅ Done | Credential Access | T1110.004 | Credential Stuffing | `credential_stuffing.kql` | High | `block_ip` |
| ✅ Done | Exfiltration | T1048 | Exfiltration Over Alt. Protocol | `data_exfiltration.kql` | Critical | `data_exfil_contain` |
| ✅ Done | Impact | T1486 | Data Encrypted for Impact | `ransomware_indicator.kql` | Critical | `isolate_endpoint` |
| ✅ Done | Reconnaissance | T1598 | Phishing for Information (Voice) | `ai_voice_fraud.kql` | High | `notify_soc` |
| ✅ Done | Initial Access | T1195 | Supply Chain Compromise | `supply_chain_anomaly.kql` | High | `notify_soc` |

---

## Coverage Summary

| Category | Count | Status |
|---|---|---|
| Techniques Monitored | 8 / 8 | ✅ Full Coverage |
| Rules Implemented | 8 | ✅ Complete |
| Playbooks Wired | 4 | `quarantine_email`, `block_ip`, `isolate_endpoint`, `notify_soc` |
| MITRE Tactics Covered | 6 | Initial Access, Persistence, Credential Access, Collection, Exfiltration, Impact |

---

## Retail-Specific Threat Mapping

| Retail Threat | MITRE Technique | RetailShield Rule | Priority |
|---|---|---|---|
| Phishing targeting finance/HR staff | T1566.001 | `phishing_detection.kql` | Critical |
| POS RAM scraping / keylogger | T1056.001 | `pos_anomaly.kql` | Critical |
| Service account misuse (off-hours) | T1078 | `after_hours_access.kql` | High |
| Distributed credential stuffing | T1110.004 | `credential_stuffing.kql` | High |
| DNS exfiltration from ERP/DB servers | T1048 | `data_exfiltration.kql` | Critical |
| Ransomware staging on POS network | T1486 | `ransomware_indicator.kql` | Critical |
| AI deepfake voice fraud (CFO fraud) | T1598 | `ai_voice_fraud.kql` | High |
| Compromised supplier API access | T1195 | `supply_chain_anomaly.kql` | High |

---

## PCI DSS v4.0 Alignment

| PCI DSS Requirement | Description | Covered By | Status |
|---|---|---|---|
| Req 1 | Network security controls | `after_hours_access.kql`, `supply_chain_anomaly.kql` | ✅ Covered |
| Req 2 | Secure configurations | CVE Scanner (`cve_scanner.py`) | ✅ Covered |
| Req 3 | Protect stored cardholder data | `data_exfiltration.kql`, `pos_anomaly.kql` | ✅ Covered |
| Req 4 | Cryptography in transit | CVE Scanner (Verifone TLS CVEs) | ✅ Covered |
| Req 5 | Anti-malware | `ransomware_indicator.kql` | ✅ Covered |
| Req 6 | Secure software development | CVE Scanner (patching status) | ✅ Covered |
| Req 7 | Need-to-know access control | `after_hours_access.kql` | 🔶 Partial |
| Req 8 | Identity and authentication | `credential_stuffing.kql` | ✅ Covered |
| Req 9 | Physical access controls | `pos_anomaly.kql` (terminal tampering) | 🔶 Partial |
| Req 10 | Logging and monitoring | All 8 KQL rules | ✅ Covered |
| Req 11 | Security testing | CVE Scanner (`cve_scanner.py`) | ✅ Covered |
| Req 12 | Organisational security policy | 🔲 Planned (v3.0) | 🔲 Planned |

---

## Author

**Tanvir Farhad** — ShieldTech Ltd, London  
[github.com/TFT444/RetailShield](https://github.com/TFT444/RetailShield)
