import { useState, useEffect, useCallback } from 'react'

// ── Design tokens ───────────────────────────────────────────────────────────────────────────
const C = {
  bg:        '#080808',
  surface:   '#0f0f0f',
  card:      '#141414',
  cardHover: '#1c1c1c',
  border:    '#242424',
  red:       '#dc2626',
  redHover:  '#ef4444',
  redDim:    '#450a0a',
  orange:    '#ea580c',
  yellow:    '#ca8a04',
  green:     '#16a34a',
  blue:      '#2563eb',
  text:      '#f1f5f9',
  muted:     '#94a3b8',
  dim:       '#475569',
}

const SEV = { critical: C.red, high: C.orange, medium: C.yellow, low: C.blue }
const STA = { active: C.red, blocked: C.green, pending: C.orange }

// ── Threat data ───────────────────────────────────────────────────────────────────────────
const BASE_THREATS = [
  {
    id: 1, name: 'Phishing Email — Finance Team', mitre: 'T1566.001',
    tactic: 'Initial Access', severity: 'critical', status: 'active',
    device: 'MAIL-SERVER-01', user: 'j.wright@retailco.uk', time: '2 min ago',
    ts: Date.now() - 120000,
    desc: 'Spearphishing attachment targeting finance approvers with fake invoice PDF. SHA256 hash matched against RetailIOCWatchlist. Macro-enabled .docm attachment blocked at gateway.',
    playbook: {
      trigger: 'quarantine_email',
      auto: [
        'Email quarantined across all 1,247 mailboxes via Defender for O365',
        'Sender domain shieldtech-invoice[.]net added to tenant block list',
        'SHA256 hash pushed to RetailIOCWatchlist — all endpoints alerted',
        'Affected users notified via Teams with phishing awareness link',
        'Incident ticket created in ServiceNow (#INC0042891)',
      ],
      manual: [
        'Verify no users opened attachment before quarantine window',
        'Review mail gateway logs for related campaigns in last 72h',
        'Check sender domain registration date — likely <30 days',
        'Notify CISO if any attachment was executed on endpoint',
        'Submit sample to Microsoft MSRC threat intelligence portal',
      ],
    },
  },
  {
    id: 2, name: 'Ransomware Staging Detected', mitre: 'T1486',
    tactic: 'Impact', severity: 'critical', status: 'active',
    device: 'POS-FLOOR-07', user: 'SYSTEM', time: '8 min ago',
    ts: Date.now() - 480000,
    desc: 'Mass file rename: 143 files in 3 minutes with .lockbit3 extension. Shadow copy deletion via vssadmin confirmed. C2 beacon to 185.220.101.x (known LockBit 3.0 infrastructure). Endpoint isolated.',
    playbook: {
      trigger: 'isolate_endpoint',
      auto: [
        'Endpoint POS-FLOOR-07 isolated via Defender for Endpoint API',
        'Network access revoked at Azure Firewall — all traffic dropped',
        'C2 IP 185.220.101.x added to RetailIOCWatchlist and blocked',
        'Forensic memory snapshot and disk image initiated',
        'Incident escalated to P1 — on-call SOC team paged via PagerDuty',
      ],
      manual: [
        'Confirm no lateral movement to adjacent POS-FLOOR terminals',
        'Check vssadmin logs — determine scope of shadow copy destruction',
        'Engage IR retainer (CrowdStrike/Secureworks) if spread confirmed',
        'Notify board and DPO — UK GDPR Art.33 72hr notification clock starts',
        'Prepare operational comms for store management and customers',
      ],
    },
  },
  {
    id: 3, name: 'DNS Exfiltration Attempt', mitre: 'T1048',
    tactic: 'Exfiltration', severity: 'critical', status: 'blocked',
    device: 'ERP-SERVER-02', user: 'erp_svc_account', time: '15 min ago',
    ts: Date.now() - 900000,
    desc: '1,247 DNS queries to exfil.attacker[.]xyz with 58-char base64 subdomains over 8 minutes. 142 MB staged from \\\\ERP-SERVER-02\\finance\\. Outbound DNS blocked at resolver before exfiltration completed.',
    playbook: {
      trigger: 'data_exfil_contain',
      auto: [
        'Outbound DNS to attacker domain blocked at Sentinel-managed resolver',
        'exfil.attacker[.]xyz added to RetailIOCWatchlist and DNS sinkholes',
        'ERP service account password reset and all sessions revoked',
        'Network flow evidence preserved in Log Analytics Workspace',
        'DLP alert raised — \\finance\\ access flagged for review',
      ],
      manual: [
        'Determine initial access vector to ERP-SERVER-02',
        'Review what data was staged — assess UK GDPR notification requirement',
        'Engage Data Protection Officer for breach impact assessment',
        'Confirm whether any packets left before DNS block was applied',
        'Audit ERP access logs for 72 hours preceding this event',
      ],
    },
  },
  {
    id: 4, name: 'After-Hours Admin Login', mitre: 'T1078',
    tactic: 'Persistence', severity: 'high', status: 'active',
    device: 'DC-PRIMARY', user: 'svc_erpadmin', time: '23 min ago',
    ts: Date.now() - 1380000,
    desc: 'Interactive RDP login to domain controller at 03:17 UTC from 185.220.101.47 (confirmed Tor exit node). Service account svc_erpadmin — interactive logins are outside normal behaviour baseline.',
    playbook: {
      trigger: 'notify_soc',
      auto: [
        'Alert sent to SOC Teams channel with full event context and IP',
        'svc_erpadmin flagged for elevated monitoring in Sentinel',
        'Risky sign-in recorded in Azure AD Identity Protection',
        'Session commands logged to forensic audit trail',
      ],
      manual: [
        'Verify whether svc_erpadmin is ever expected to log in interactively',
        'Check if credentials were exposed in recent dark-web dumps',
        'Review all AD changes made during this session',
        'Disable account immediately if compromise is confirmed',
        'Audit all accounts that logged in from the same /24 range',
      ],
    },
  },
  {
    id: 5, name: 'Credential Stuffing — Customer Portal', mitre: 'T1110.004',
    tactic: 'Credential Access', severity: 'high', status: 'blocked',
    device: 'WEB-PORTAL-01', user: '23 accounts targeted', time: '31 min ago',
    ts: Date.now() - 1860000,
    desc: '847 failed logins across 23 customer accounts from 31 distinct IPs in 5 minutes. Pattern matches Collection #4 dark-web dump. 3 accounts had subsequent successful logins — takeover confirmed.',
    playbook: {
      trigger: 'block_ip',
      auto: [
        '31 source IPs added to Azure WAF deny rules immediately',
        'CAPTCHA enforcement enabled on /login endpoint',
        '3 compromised accounts locked — owners emailed reset links',
        'Login rate limiting reduced to 3 attempts/min per account',
        'Indicators submitted to AbuseIPDB with campaign tag',
      ],
      manual: [
        'Force password reset for all 23 targeted accounts preventatively',
        'Review whether compromised accounts accessed payment or PII data',
        'Assess PCI DSS notification requirement for card data access',
        'Tune WAF rules to catch similar User-Agent rotation patterns',
        'Monitor for continued campaign over next 48 hours',
      ],
    },
  },
  {
    id: 6, name: 'POS Terminal Anomaly', mitre: 'T1056.001',
    tactic: 'Collection', severity: 'high', status: 'active',
    device: 'POS-TILL-14', user: 'TILL14_PROC', time: '45 min ago',
    ts: Date.now() - 2700000,
    desc: 'Transaction volume 4.2σ above 30-day baseline on POS-TILL-14. Unknown unsigned DLL (xf32mh.dll) injected into POS process memory — consistent with RAM-scraping keylogger pattern.',
    playbook: {
      trigger: 'suspend_terminal',
      auto: [
        'POS-TILL-14 suspended via retail management API — till offline',
        'Store manager notified via Teams with terminal ID and location',
        'Memory dump initiated for forensic DLL analysis',
        'Incident logged in ServiceNow with PCI DSS breach flag (#INC0042904)',
      ],
      manual: [
        'Physically inspect terminal for hardware skimmer device',
        'Pull network pcap from the last 4 hours from switch port',
        'Identify origin of xf32mh.dll — check software deployment logs',
        'Determine payment card data exposure window for PCI notification',
        'Re-image terminal and run integrity check before returning to service',
      ],
    },
  },
  {
    id: 7, name: 'Supply Chain API Anomaly', mitre: 'T1195',
    tactic: 'Initial Access', severity: 'medium', status: 'active',
    device: 'API-GATEWAY-01', user: 'supplier_api_key_038', time: '1 hr ago',
    ts: Date.now() - 3600000,
    desc: 'Supplier API key (Vendor: LogiTrak Ltd) accessing /admin/inventory and /customers/export outside agreed integration spec. 3 new service principals created in Azure AD within 30 minutes.',
    playbook: {
      trigger: 'notify_soc',
      auto: [
        'Supplier API key rate-limited to read-only pending investigation',
        'Access anomaly logged in API gateway audit trail with full payload',
        'Supplier account flagged as high-risk in Vendor Risk Register',
        'SOC and Procurement Manager notified via Teams',
      ],
      manual: [
        'Contact LogiTrak Ltd security team directly to verify activity',
        'Review all endpoints accessed by this API key in the last 7 days',
        'Rotate API key if supplier cannot verify within 4 hours',
        'Assess whether customer data export was completed — GDPR review',
        'Cross-reference with M&S supply-chain breach indicators (2025)',
      ],
    },
  },
  {
    id: 8, name: 'AI Voice Fraud Attempt', mitre: 'T1598',
    tactic: 'Reconnaissance', severity: 'medium', status: 'blocked',
    device: 'VOIP-SYSTEM', user: 'finance.team@retailco.uk', time: '2 hr ago',
    ts: Date.now() - 7200000,
    desc: '£47,500 payment request via deepfake voice call impersonating CFO. Caller spoofed +44 208 xxx xxxx, asked to bypass dual-approval policy "urgently". Payment blocked — finance team followed verification protocol.',
    playbook: {
      trigger: 'notify_soc',
      auto: [
        'Call recording preserved as evidence under legal hold',
        'Spoofed number added to VOIP block list across all handsets',
        'Finance team security awareness alert issued organisation-wide',
        'Incident report filed with Action Fraud (ref: NFRC241104)',
      ],
      manual: [
        'Verify call authenticity with CFO directly via known mobile',
        'Issue mandatory voice fraud awareness refresher to finance team',
        'Confirm call-back verification policy was followed correctly',
        'Submit deepfake audio sample to NCSC for AI threat analysis',
        'Update dual-approval policy: add verbal re-confirmation via known direct line',
      ],
    },
  },
]

// New threats injected during live simulation
const LIVE_THREATS = [
  {
    name: 'Brute Force — Admin Console', mitre: 'T1110.001',
    tactic: 'Credential Access', severity: 'high', status: 'blocked',
    device: 'ADMIN-PANEL', user: 'admin', time: 'just now',
    desc: '312 login attempts in 90 seconds against /admin from 45.142.x.x (residential proxy network). Account lockout triggered after 10 attempts.',
    playbook: { trigger: 'block_ip', auto: ['IP blocked at WAF', 'Account locked'], manual: ['Review admin login policy', 'Enable hardware MFA'] },
  },
  {
    name: 'Suspicious PowerShell Execution', mitre: 'T1059.001',
    tactic: 'Execution', severity: 'critical', status: 'active',
    device: 'WORKSTATION-22', user: 'k.chen', time: 'just now',
    desc: 'Encoded PowerShell with -EncodedCommand flag executed by standard user. Decoded payload attempts download from pastebin CDN. Defender blocked download.',
    playbook: { trigger: 'isolate_endpoint', auto: ['Endpoint isolated', 'Process killed'], manual: ['Decode and triage full payload', 'Review k.chen recent activity'] },
  },
  {
    name: 'New Privileged Account Created', mitre: 'T1136',
    tactic: 'Persistence', severity: 'high', status: 'active',
    device: 'DC-PRIMARY', user: 'svc_backup2', time: 'just now',
    desc: 'New Domain Admin account (svc_backup2) created outside change management window at 02:44 UTC. No ServiceNow change request found. Account created by svc_erpadmin.',
    playbook: { trigger: 'notify_soc', auto: ['Account flagged in Sentinel', 'SOC alerted'], manual: ['Verify with IT Change team', 'Disable immediately if unauthorised'] },
  },
  {
    name: 'RDP Lateral Movement Detected', mitre: 'T1021.001',
    tactic: 'Lateral Movement', severity: 'critical', status: 'active',
    device: 'STORE-PC-08', user: 'svc_erpadmin', time: 'just now',
    desc: 'RDP connections from POS-FLOOR-07 (isolated) to 4 additional hosts detected before isolation completed. Lateral movement chain: POS-07 → STORE-PC-08 → PAYROLL-SRV → DC-BACKUP.',
    playbook: { trigger: 'isolate_endpoint', auto: ['All 4 devices isolated', 'Firewall rules updated'], manual: ['Full forensic triage on all 4 devices', 'Assess domain compromise scope'] },
  },
]

// ── Attack simulation events (5 threats, one per MITRE technique) ─────────────────────
const ATTACK_SIM_EVENTS = [
  {
    name: 'Spearphishing — CFO Impersonation [SIM]', mitre: 'T1566.001',
    tactic: 'Initial Access', severity: 'critical', status: 'active',
    device: 'MAIL-SIM-01', user: 'cfo@retailco.uk', time: 'just now',
    desc: '[SIMULATION] Macro-enabled .docm attachment delivered to CFO inbox from invoice-urgent@dr4gonm4il.com. SHA256 matches RetailIOCWatchlist entry added 6 minutes ago.',
    playbook: {
      trigger: 'quarantine_email',
      auto: [
        'Email quarantined across all mailboxes via Defender for O365',
        'Sender domain dr4gonm4il.com added to tenant block list',
        'SHA256 hash pushed to RetailIOCWatchlist',
        'CFO and EA notified via Teams',
        'Incident ticket raised: #SIM-001',
      ],
      manual: [
        'Confirm CFO did not open attachment before quarantine',
        'Check for related campaign in last 72h mail gateway logs',
        'Review sender domain registration — likely <7 days old',
        'Escalate to CISO if attachment was executed',
        'Submit to Microsoft MSRC threat intelligence',
      ],
    },
  },
  {
    name: 'Credential Stuffing — POS Admin Portal [SIM]', mitre: 'T1110.004',
    tactic: 'Credential Access', severity: 'critical', status: 'active',
    device: 'POS-ADMIN-SIM', user: '31 accounts targeted', time: 'just now',
    desc: '[SIMULATION] 1,247 failed logins across 31 accounts from 89 distinct IPs in 3 minutes. Credential pairs match leaked Retail Sector dump (Collection #7, 2025). 4 accounts compromised.',
    playbook: {
      trigger: 'block_ip',
      auto: [
        '89 source IPs added to Azure WAF deny rules',
        'CAPTCHA enforcement enabled on /pos-admin/login',
        '4 compromised accounts locked and password reset triggered',
        'Rate limiting set to 3 attempts / 5 min per account',
        'Indicators submitted to AbuseIPDB',
      ],
      manual: [
        'Force reset all 31 targeted accounts preventatively',
        'Check if compromised accounts accessed transaction data',
        'Assess PCI DSS notification requirement',
        'Tune WAF rules for similar User-Agent rotation patterns',
        'Monitor for continued campaign over next 48h',
      ],
    },
  },
  {
    name: 'Ransomware Staging — Mass File Encryption [SIM]', mitre: 'T1486',
    tactic: 'Impact', severity: 'critical', status: 'active',
    device: 'WORKSTATION-SIM-07', user: 'SYSTEM', time: 'just now',
    desc: '[SIMULATION] 847 files renamed with .dragon3 extension in 4 minutes. vssadmin delete shadows confirmed. C2 beacon to 91.234.55.12 (DragonForce infrastructure). Endpoint being isolated.',
    playbook: {
      trigger: 'isolate_endpoint',
      auto: [
        'WORKSTATION-SIM-07 isolated via Defender for Endpoint API',
        'Network access revoked at Azure Firewall',
        'C2 IP 91.234.55.12 added to block list across all firewalls',
        'Forensic memory snapshot and disk image initiated',
        'P1 incident raised — on-call SOC paged via PagerDuty',
      ],
      manual: [
        'Confirm no lateral movement to adjacent workstations',
        'Scope shadow copy destruction across all network shares',
        'Engage IR retainer if spread confirmed to >3 hosts',
        'Start GDPR Art.33 72h notification clock',
        'Prepare operational comms for store management',
      ],
    },
  },
  {
    name: 'DNS Exfiltration — Customer Database [SIM]', mitre: 'T1048',
    tactic: 'Exfiltration', severity: 'critical', status: 'active',
    device: 'DB-SERVER-SIM', user: 'db_svc_account', time: 'just now',
    desc: '[SIMULATION] 3,847 DNS queries to exfil.d4t4pipe[.]xyz with 64-char base64 subdomains over 12 minutes. 2.1 GB staged from \\\\DB-SERVER\\customers\\. DNS blocked at resolver.',
    playbook: {
      trigger: 'data_exfil_contain',
      auto: [
        'DNS to d4t4pipe[.]xyz blocked at Sentinel-managed resolver',
        'Domain added to RetailIOCWatchlist and sinkholes',
        'db_svc_account password reset and sessions revoked',
        'Network flow evidence preserved in Log Analytics',
        'DLP alert raised for \\customers\\ folder bulk read',
      ],
      manual: [
        'Determine initial access vector to DB-SERVER',
        'Assess what customer PII was staged — GDPR impact assessment',
        'Engage Data Protection Officer immediately',
        'Determine if exfiltration completed before DNS block',
        'Audit db_svc_account activity for prior 72h',
      ],
    },
  },
  {
    name: 'AI Voice Deepfake — Finance Director [SIM]', mitre: 'T1598',
    tactic: 'Reconnaissance', severity: 'high', status: 'blocked',
    device: 'VOIP-SIM', user: 'finance.director@retailco.uk', time: 'just now',
    desc: '[SIMULATION] £125,000 BACS transfer request via AI voice call impersonating Regional MD. Caller asked to bypass dual-approval. AI confidence score 0.97. Payment blocked by finance team.',
    playbook: {
      trigger: 'notify_soc',
      auto: [
        'Call recording preserved under legal hold',
        'Spoofed number added to VOIP block list',
        'Finance team fraud awareness alert issued',
        'Report filed with Action Fraud (ref: SIM-NCSC-2026)',
      ],
      manual: [
        'Verify with Regional MD via known direct mobile',
        'Issue mandatory voice fraud refresher to finance team',
        'Confirm dual-approval protocol was followed correctly',
        'Submit deepfake audio to NCSC AI threat analysis team',
        'Update payment policy: add video call re-confirmation step',
      ],
    },
  },
  {
    name: 'After-Hours Privileged Access — Domain Controller [SIM]', mitre: 'T1078',
    tactic: 'Persistence', severity: 'high', status: 'active',
    device: 'DC-SIM-PRIMARY', user: 'svc_backup_sim', time: 'just now',
    desc: '[SIMULATION] Interactive RDP login to domain controller at 02:58 UTC from 185.220.101.47 (Tor exit node). Service account svc_backup_sim — interactive sessions are outside baseline.',
    playbook: {
      trigger: 'notify_soc',
      auto: [
        'svc_backup_sim flagged for elevated monitoring',
        'Risky sign-in logged in Azure AD Identity Protection',
        'SOC Teams channel alerted with full session context',
        'Session commands captured to forensic audit trail',
      ],
      manual: [
        'Verify whether svc_backup_sim ever logs in interactively',
        'Cross-reference IP against Tor exit node list',
        'Review all AD changes made during this session',
        'Disable account immediately if compromise confirmed',
        'Audit all accounts from same /24 IP range',
      ],
    },
  },
  {
    name: 'POS Terminal Memory Scraping [SIM]', mitre: 'T1056.001',
    tactic: 'Collection', severity: 'high', status: 'active',
    device: 'POS-SIM-TILL-09', user: 'TILL09_PROC', time: 'just now',
    desc: '[SIMULATION] Unknown unsigned DLL (xf99ab.dll) injected into POS process on TILL-09. Transaction volume 5.1σ above 30-day baseline. RAM scraping pattern consistent with known POS malware.',
    playbook: {
      trigger: 'suspend_terminal',
      auto: [
        'POS-SIM-TILL-09 suspended via retail management API',
        'Store manager notified via Teams',
        'Memory dump initiated for DLL forensic analysis',
        'ServiceNow ticket raised with PCI DSS flag',
      ],
      manual: [
        'Physically inspect TILL-09 for hardware skimmer',
        'Pull network capture from last 4 hours on switch port',
        'Identify origin of xf99ab.dll via software deployment logs',
        'Assess payment card data exposure window for PCI notification',
        'Re-image terminal before returning to service',
      ],
    },
  },
]

// ── CVE Vulnerability Scanner data ───────────────────────────────────────────────────
const VULN_INITIAL = {
  lastScan: '2026-05-28T06:00:00Z',
  totalAssets: 18,
  summary: { critical: 8, high: 22, medium: 4, low: 0 },
  findings: [
    {
      id: 'POS-TILL-01', product: 'Oracle Xstore POS', version: '8.1',
      location: 'Hounslow Branch', cat: 'POS System',
      vulns: [
        { cve: 'CVE-2025-44123', cvss: 9.8, sev: 'critical', title: 'Unauthenticated RCE via Java deserialization in config sync', patch: true, exploit: true, mitre: 'T1190' },
        { cve: 'CVE-2025-31847', cvss: 8.8, sev: 'high', title: 'SQL injection in transaction reporting module', patch: true, exploit: false, mitre: 'T1190' },
      ],
    },
    {
      id: 'POS-TILL-03', product: 'NCR Aloha POS', version: '12.3',
      location: 'Hammersmith Branch', cat: 'POS System',
      vulns: [
        { cve: 'CVE-2025-19284', cvss: 9.1, sev: 'critical', title: 'Authentication bypass via malformed session token', patch: true, exploit: true, mitre: 'T1078' },
        { cve: 'CVE-2024-52891', cvss: 7.8, sev: 'high', title: 'Local privilege escalation via insecure service dir', patch: true, exploit: false, mitre: 'T1068' },
      ],
    },
    {
      id: 'POS-TILL-05', product: 'Toshiba TCx POS', version: '5.2',
      location: 'Ealing Branch', cat: 'POS System',
      vulns: [
        { cve: 'CVE-2025-08374', cvss: 8.1, sev: 'high', title: 'Stack buffer overflow in EMV payment parsing library', patch: true, exploit: false, mitre: 'T1203' },
        { cve: 'CVE-2024-47203', cvss: 6.5, sev: 'medium', title: 'Plaintext credentials in world-readable config files', patch: true, exploit: false, mitre: 'T1083' },
      ],
    },
    {
      id: 'POS-TILL-06', product: 'Verifone POS', version: '3.4',
      location: 'Ealing Branch', cat: 'POS System',
      vulns: [
        { cve: 'CVE-2025-22916', cvss: 9.1, sev: 'critical', title: 'Hardcoded admin credentials in management daemon', patch: true, exploit: true, mitre: 'T1078' },
        { cve: 'CVE-2024-38847', cvss: 7.5, sev: 'high', title: 'IDOR allows access to other terminals\' transactions', patch: true, exploit: false, mitre: 'T1083' },
      ],
    },
    {
      id: 'ERP-DYN-01', product: 'Microsoft Dynamics Retail', version: '10.0.28',
      location: 'Head Office', cat: 'Stock Management',
      vulns: [
        { cve: 'CVE-2024-61834', cvss: 9.3, sev: 'critical', title: 'Authentication bypass via malformed OAuth token', patch: true, exploit: true, mitre: 'T1078' },
        { cve: 'CVE-2025-17293', cvss: 8.2, sev: 'high', title: 'XXE injection in product import — reads server files', patch: true, exploit: false, mitre: 'T1190' },
      ],
    },
    {
      id: 'ERP-ORA-01', product: 'Oracle Retail Merchandising', version: '21.0',
      location: 'Head Office', cat: 'Stock Management',
      vulns: [
        { cve: 'CVE-2025-29481', cvss: 9.8, sev: 'critical', title: 'RCE via deserialization in merchandise planning API', patch: true, exploit: true, mitre: 'T1190' },
        { cve: 'CVE-2024-73921', cvss: 7.5, sev: 'high', title: 'Path traversal in report download endpoint', patch: true, exploit: false, mitre: 'T1083' },
      ],
    },
    {
      id: 'ERP-SAP-01', product: 'SAP Retail', version: 'S/4HANA 2021',
      location: 'Head Office', cat: 'Stock Management',
      vulns: [
        { cve: 'CVE-2025-55921', cvss: 8.6, sev: 'high', title: 'SSRF in integration layer exposes internal metadata', patch: true, exploit: false, mitre: 'T1190' },
        { cve: 'CVE-2025-43782', cvss: 7.4, sev: 'high', title: 'Stored XSS in product catalogue via supplier input', patch: true, exploit: false, mitre: 'T1059.007' },
      ],
    },
    {
      id: 'ERP-JDA-01', product: 'JDA Supply Chain', version: '9.2',
      location: 'Head Office', cat: 'Stock Management',
      vulns: [
        { cve: 'CVE-2024-44918', cvss: 8.1, sev: 'high', title: 'SQL injection in order management module', patch: true, exploit: false, mitre: 'T1190' },
        { cve: 'CVE-2025-61204', cvss: 7.5, sev: 'high', title: 'IDOR exposes competitor purchase orders', patch: true, exploit: false, mitre: 'T1083' },
      ],
    },
    {
      id: 'TERM-VFN-01', product: 'Verifone VX520', version: '2.1.0',
      location: 'Hounslow Branch', cat: 'Payment Terminal',
      vulns: [
        { cve: 'CVE-2025-33741', cvss: 9.4, sev: 'critical', title: 'PIN block extraction via differential power analysis', patch: true, exploit: false, mitre: 'T1056.001' },
        { cve: 'CVE-2024-55847', cvss: 7.8, sev: 'high', title: 'Unsigned firmware accepted via ARP-spoofed update server', patch: true, exploit: false, mitre: 'T1542' },
      ],
    },
    {
      id: 'TERM-PAX-01', product: 'PAX S920', version: '1.2',
      location: 'Hounslow Branch', cat: 'Payment Terminal',
      vulns: [
        { cve: 'CVE-2025-37482', cvss: 9.8, sev: 'critical', title: 'RCE via malformed EMV TLV packet over merchant LAN', patch: true, exploit: true, mitre: 'T1190' },
        { cve: 'CVE-2025-21847', cvss: 8.4, sev: 'high', title: 'Root shell exposed via USB diagnostic interface', patch: true, exploit: true, mitre: 'T1059' },
      ],
    },
    {
      id: 'TERM-ING-01', product: 'Ingenico iCT250', version: '6.0.0',
      location: 'Ealing Branch', cat: 'Payment Terminal',
      vulns: [
        { cve: 'CVE-2025-48293', cvss: 8.8, sev: 'high', title: 'Memory corruption in NFC NDEF handler — RCE via card', patch: true, exploit: false, mitre: 'T1203' },
        { cve: 'CVE-2024-92841', cvss: 7.6, sev: 'high', title: 'Static Bluetooth PIN 0000 — relay attack possible', patch: true, exploit: true, mitre: 'T1557' },
      ],
    },
    {
      id: 'TERM-VFN-02', product: 'Verifone P400', version: '3.0.1',
      location: 'Hammersmith Branch', cat: 'Payment Terminal',
      vulns: [
        { cve: 'CVE-2025-12847', cvss: 8.0, sev: 'high', title: 'Firmware downgrade attack via USB maintenance port', patch: true, exploit: false, mitre: 'T1542.001' },
        { cve: 'CVE-2024-38291', cvss: 6.8, sev: 'medium', title: 'Weak TLS cipher suites (RC4/3DES) accepted in payment comms', patch: true, exploit: false, mitre: 'T1600' },
      ],
    },
    {
      id: 'PLAT-SHP-01', product: 'Shopify POS', version: '9.1.0',
      location: 'Online', cat: 'Retail Platform',
      vulns: [
        { cve: 'CVE-2025-28473', cvss: 8.1, sev: 'high', title: 'Certificate pinning bypass enables on-path MITM attack', patch: true, exploit: false, mitre: 'T1557' },
        { cve: 'CVE-2025-41928', cvss: 7.5, sev: 'high', title: 'API secret key exposed in iOS app bundle plist', patch: true, exploit: false, mitre: 'T1552.001' },
      ],
    },
    {
      id: 'PLAT-SQR-01', product: 'Square POS', version: '5.28',
      location: 'Online', cat: 'Retail Platform',
      vulns: [
        { cve: 'CVE-2025-53847', cvss: 8.8, sev: 'high', title: 'No TLS cert validation — accepts self-signed certs', patch: true, exploit: false, mitre: 'T1557.001' },
        { cve: 'CVE-2024-82941', cvss: 7.4, sev: 'high', title: 'Bluetooth pairing replay attack on card reader', patch: true, exploit: false, mitre: 'T1557' },
      ],
    },
    {
      id: 'PLAT-LSP-01', product: 'Lightspeed Retail', version: '2024.1',
      location: 'Online', cat: 'Retail Platform',
      vulns: [
        { cve: 'CVE-2025-44821', cvss: 8.6, sev: 'high', title: 'Path traversal in file export reads server credentials', patch: true, exploit: false, mitre: 'T1083' },
        { cve: 'CVE-2024-63947', cvss: 7.1, sev: 'medium', title: 'CSRF token reuse allows unauthorised admin actions', patch: true, exploit: false, mitre: 'T1059.007' },
      ],
    },
    {
      id: 'PLAT-RVL-01', product: 'Revel POS', version: '4.7',
      location: 'Online', cat: 'Retail Platform',
      vulns: [
        { cve: 'CVE-2025-17482', cvss: 9.1, sev: 'critical', title: 'Hardcoded default admin credentials in iPad management', patch: true, exploit: true, mitre: 'T1078' },
        { cve: 'CVE-2024-57291', cvss: 6.8, sev: 'medium', title: 'Card tokens stored in unencrypted local SQLite DB', patch: true, exploit: false, mitre: 'T1005' },
      ],
    },
  ],
}

// ── SVG Security Posture Gauge ────────────────────────────────────────────────────────────────────
function SecurityGauge({ score }) {
  const cx = 100, cy = 95, r = 72
  const startDeg = -210, endDeg = 30, totalArc = endDeg - startDeg
  const valueDeg = startDeg + (score / 100) * totalArc
  const toRad = d => (d * Math.PI) / 180
  const arc = (s, e) => {
    const x1 = cx + r * Math.cos(toRad(s)), y1 = cy + r * Math.sin(toRad(s))
    const x2 = cx + r * Math.cos(toRad(e)), y2 = cy + r * Math.sin(toRad(e))
    return `M${x1} ${y1} A${r} ${r} 0 ${Math.abs(e - s) > 180 ? 1 : 0} 1 ${x2} ${y2}`
  }
  const col = score >= 80 ? C.green : score >= 60 ? C.yellow : score >= 40 ? C.orange : C.red
  return (
    <svg viewBox="0 0 200 148" style={{ width: '100%', maxWidth: 200 }}>
      <path d={arc(startDeg, endDeg)} fill="none" stroke={C.border} strokeWidth={14} strokeLinecap="round" />
      <path d={arc(startDeg, valueDeg)} fill="none" stroke={col} strokeWidth={14} strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 6px ${col})` }} />
      <text x={cx} y={cy + 8} textAnchor="middle" fill={col} fontSize={34}
        fontWeight="bold" fontFamily="monospace">{score}</text>
      <text x={cx} y={cy + 26} textAnchor="middle" fill={C.muted} fontSize={10}
        fontFamily="sans-serif" letterSpacing="1">SECURITY SCORE</text>
      <text x={28} y={cy + 32} textAnchor="middle" fill={C.dim} fontSize={9}>0</text>
      <text x={172} y={cy + 32} textAnchor="middle" fill={C.dim} fontSize={9}>100</text>
    </svg>
  )
}

// ── Attack timeline bar chart ──────────────────────────────────────────────────────────────────────
function AttackTimeline({ tick }) {
  const labels = ['18h', '19h', '20h', '21h', '22h', '23h', '00h', '01h', '02h', '03h', '04h', '05h']
  const base   = [1, 0, 2, 1, 0, 3, 2, 1, 4, 3, 2, 1]
  const counts = base.map((v, i) => i === labels.length - 1 ? Math.min(6, v + (tick % 3)) : v)
  const max    = Math.max(...counts, 1)
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 72, marginBottom: 6 }}>
        {counts.map((n, i) => (
          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <div style={{
              width: '100%',
              height: n === 0 ? 2 : `${(n / max) * 68}px`,
              background: n >= 4 ? C.red : n >= 3 ? C.orange : n >= 1 ? C.blue : C.border,
              borderRadius: '2px 2px 0 0',
              transition: 'height 0.5s ease, background 0.3s',
              boxShadow: n >= 3 ? `0 0 6px ${n >= 4 ? C.red : C.orange}` : 'none',
            }} />
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 3 }}>
        {labels.map((l, i) => (
          <div key={i} style={{ flex: 1, textAlign: 'center', fontSize: 8, color: C.dim }}>{l}</div>
        ))}
      </div>
    </div>
  )
}

// ── MITRE coverage bar ──────────────────────────────────────────────────────────────────────────────
function MitreBar({ technique, tactic, pct, color }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 12, color: C.text, fontFamily: 'monospace' }}>{technique}</span>
        <span style={{ fontSize: 11, color: C.muted }}>{tactic} · {pct}%</span>
      </div>
      <div style={{ height: 6, background: C.border, borderRadius: 3 }}>
        <div style={{
          height: '100%', width: `${pct}%`, borderRadius: 3, background: color,
          boxShadow: `0 0 6px ${color}40`, transition: 'width 1.2s ease',
        }} />
      </div>
    </div>
  )
}

// ── Incident playbook modal ────────────────────────────────────────────────────────────────────────
function PlaybookModal({ threat, onClose }) {
  if (!threat) return null
  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.88)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 9999, padding: 20,
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: C.card, border: `1px solid ${C.border}`, borderRadius: 14,
        padding: 28, maxWidth: 660, width: '100%', maxHeight: '88vh',
        overflowY: 'auto',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <span style={{ background: C.redDim, color: C.red, padding: '3px 10px', borderRadius: 4, fontSize: 12, fontWeight: 700, fontFamily: 'monospace' }}>{threat.mitre}</span>
              <span style={{
                color: STA[threat.status], padding: '3px 10px', borderRadius: 4, fontSize: 11,
                border: `1px solid ${STA[threat.status]}`, background: `${STA[threat.status]}15`,
              }}>{threat.status.toUpperCase()}</span>
              <span style={{
                color: SEV[threat.severity], padding: '3px 10px', borderRadius: 4, fontSize: 11,
                background: `${SEV[threat.severity]}15`,
              }}>{threat.severity.toUpperCase()}</span>
            </div>
            <h2 style={{ color: C.text, fontSize: 18, marginBottom: 4, lineHeight: 1.3 }}>{threat.name}</h2>
            <p style={{ color: C.muted, fontSize: 12 }}>{threat.tactic} · {threat.device} · {threat.user} · {threat.time}</p>
          </div>
          <button onClick={onClose} style={{
            background: 'transparent', border: `1px solid ${C.border}`,
            color: C.muted, borderRadius: 6, padding: '5px 12px', cursor: 'pointer', fontSize: 18, lineHeight: 1,
          }}>✕</button>
        </div>
        <div style={{ background: C.surface, borderRadius: 8, padding: '14px 16px', marginBottom: 22, borderLeft: `3px solid ${C.red}` }}>
          <p style={{ color: C.muted, fontSize: 13, lineHeight: 1.7, margin: 0 }}>{threat.desc}</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
          <span style={{ fontSize: 12, color: C.muted }}>Playbook trigger:</span>
          <code style={{
            background: '#1a0505', color: C.red, padding: '4px 12px',
            borderRadius: 5, fontSize: 12, fontFamily: 'monospace',
            border: `1px solid ${C.redDim}`,
          }}>{threat.playbook.trigger}</code>
        </div>
        <div style={{ marginBottom: 22 }}>
          <h3 style={{ color: C.green, fontSize: 13, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ background: C.green, color: '#000', padding: '2px 8px', borderRadius: 3, fontSize: 10, fontWeight: 800 }}>AUTO</span>
            Automated Response — Executed by Logic App
          </h3>
          {threat.playbook.auto.map((step, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <div style={{
                minWidth: 22, height: 22, borderRadius: '50%', background: C.green,
                color: '#000', fontSize: 11, fontWeight: 800, display: 'flex',
                alignItems: 'center', justifyContent: 'center', marginTop: 1, flexShrink: 0,
              }}>✓</div>
              <span style={{ color: C.text, fontSize: 13, lineHeight: 1.6 }}>{step}</span>
            </div>
          ))}
        </div>
        <div>
          <h3 style={{ color: C.orange, fontSize: 13, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ background: C.orange, color: '#000', padding: '2px 8px', borderRadius: 3, fontSize: 10, fontWeight: 800 }}>MANUAL</span>
            Analyst Actions Required
          </h3>
          {threat.playbook.manual.map((step, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 10, alignItems: 'flex-start' }}>
              <div style={{
                minWidth: 22, height: 22, borderRadius: '50%', background: 'transparent',
                color: C.orange, fontSize: 11, fontWeight: 800, display: 'flex',
                alignItems: 'center', justifyContent: 'center', marginTop: 1, flexShrink: 0,
                border: `1.5px solid ${C.orange}`,
              }}>{i + 1}</div>
              <span style={{ color: C.muted, fontSize: 13, lineHeight: 1.6 }}>{step}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main dashboard ──────────────────────────────────────────────────────────────────────────────
export default function RetailShield() {
  const [threats, setThreats]   = useState(BASE_THREATS)
  const [filter, setFilter]     = useState('all')
  const [selected, setSelected] = useState(null)
  const [banner, setBanner]     = useState(null)
  const [score, setScore]       = useState(73)
  const [tick, setTick]         = useState(0)
  const [clock, setClock]       = useState(new Date())
  const [simStatus, setSimStatus] = useState(null)
  const [vulnData, setVulnData]   = useState(VULN_INITIAL)
  const [vulnScan, setVulnScan]   = useState(null)
  const [vulnProg, setVulnProg]   = useState(0)
  const [briefing, setBriefing]   = useState(null)
  const [briefStatus, setBriefStatus] = useState(null)

  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    let idx = 0
    const id = setInterval(() => {
      const src = LIVE_THREATS[idx % LIVE_THREATS.length]
      const next = { ...src, id: Date.now(), ts: Date.now() }
      setThreats(prev => [next, ...prev.slice(0, 11)])
      setBanner(next)
      setScore(s => Math.max(42, Math.min(96, s + (Math.random() > 0.55 ? -2 : 1))))
      setTick(t => t + 1)
      idx++
      setTimeout(() => setBanner(null), 4500)
    }, 6000)
    return () => clearInterval(id)
  }, [])

  const runAttackSimulation = useCallback(() => {
    if (simStatus === 'running') return
    setSimStatus('running')
    setScore(s => Math.max(10, s - 20))
    ATTACK_SIM_EVENTS.forEach((event, i) => {
      setTimeout(() => {
        const threat = { ...event, id: Date.now() + i, ts: Date.now() }
        setThreats(prev => [threat, ...prev.slice(0, 14)])
        setBanner(threat)
        setTimeout(() => setBanner(null), 3500)
        if (i === ATTACK_SIM_EVENTS.length - 1) {
          setTimeout(() => {
            setSimStatus('complete')
            setTimeout(() => setSimStatus(null), 6000)
          }, 800)
        }
      }, i * 800)
    })
  }, [simStatus])

  const runVulnScan = useCallback(() => {
    if (vulnScan === 'scanning') return
    setVulnScan('scanning')
    setVulnProg(0)
    let p = 0
    const step = setInterval(() => {
      p += Math.random() * 14 + 4
      if (p >= 100) {
        p = 100
        clearInterval(step)
        setVulnProg(100)
        setTimeout(() => {
          setVulnData({ ...VULN_INITIAL, lastScan: new Date().toISOString() })
          setVulnScan('done')
          setTimeout(() => setVulnScan(null), 4000)
        }, 400)
      } else {
        setVulnProg(Math.round(p))
      }
    }, 200)
  }, [vulnScan])

  const counts = {
    total:    threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    active:   threats.filter(t => t.status === 'active').length,
    blocked:  threats.filter(t => t.status === 'blocked').length,
    high:     threats.filter(t => t.severity === 'high').length,
  }

  const generateBriefing = useCallback(async () => {
    if (briefStatus === 'loading') return
    setBriefStatus('loading')
    setBriefing(null)
    const topThreats = threats.slice(0, 5).map(t => ({
      name: t.name, mitre: t.mitre, tactic: t.tactic,
      severity: t.severity, status: t.status,
    }))
    const crit = counts.critical, act = counts.active, blk = counts.blocked
    try {
      const res = await fetch('/api/brief', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threats: counts,
          score: Math.round(score),
          vulnSummary: vulnData.summary,
          topThreats,
        }),
      })
      const data = await res.json()
      setBriefing(data.briefing)
    } catch {
      setBriefing(
        `RETAILSHIELD EXECUTIVE BRIEFING — ${new Date().toUTCString()}\n\n` +
        `Security Score: ${Math.round(score)}/100. ` +
        `${crit} critical and ${act} active threats currently detected across monitored retail infrastructure. ` +
        `${vulnData.summary.critical + vulnData.summary.high} high-severity CVEs require patching within 48 hours. ` +
        `Automated playbooks have contained ${blk} incidents — no further manual action required for those. ` +
        `Immediate analyst review is required for all ACTIVE items in the threat feed. ` +
        `If any cardholder data was accessed, notify your DPO — UK GDPR Art.33 72-hour notification clock applies.\n\n` +
        `This briefing was generated by RetailShield v2.0 — ShieldTech Ltd.`
      )
    }
    setBriefStatus('done')
  }, [briefStatus, threats, counts, score, vulnData])

  const filtered = threats.filter(t =>
    filter === 'all'      ? true :
    filter === 'critical' ? t.severity === 'critical' :
    filter === 'active'   ? t.status === 'active' :
    filter === 'blocked'  ? t.status === 'blocked' : true
  )

  const mitre = [
    { technique: 'T1566.001 — Spearphishing', tactic: 'Initial Access',    pct: 95, color: C.green  },
    { technique: 'T1486 — Ransomware Impact', tactic: 'Impact',             pct: 90, color: C.red    },
    { technique: 'T1048 — Data Exfiltration', tactic: 'Exfiltration',       pct: 88, color: C.orange },
    { technique: 'T1078 — Valid Accounts',    tactic: 'Persistence',        pct: 82, color: C.yellow },
    { technique: 'T1110.004 — Cred Stuffing', tactic: 'Credential Access',  pct: 85, color: C.blue   },
    { technique: 'T1056.001 — POS Keylog',    tactic: 'Collection',         pct: 78, color: C.orange },
    { technique: 'T1195 — Supply Chain',      tactic: 'Initial Access',     pct: 70, color: C.yellow },
    { technique: 'T1598 — Voice Fraud',       tactic: 'Reconnaissance',     pct: 65, color: C.blue   },
  ]

  const s = { card: { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10 } }

  return (
    <div style={{ background: C.bg, minHeight: '100vh', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', color: C.text }}>

      {simStatus && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, zIndex: 9997,
          background: simStatus === 'running'
            ? 'repeating-linear-gradient(90deg,#450a0a 0px,#7f1d1d 40px,#450a0a 80px)'
            : `linear-gradient(135deg, #052e16, #166534)`,
          borderBottom: `2px solid ${simStatus === 'running' ? C.red : C.green}`,
          padding: '9px 24px', display: 'flex', alignItems: 'center', gap: 12,
          boxShadow: `0 2px 24px ${simStatus === 'running' ? 'rgba(220,38,38,0.7)' : 'rgba(22,163,74,0.5)'}`,
          animation: simStatus === 'running' ? 'simPulse 0.9s ease-in-out infinite' : 'slideIn 0.3s ease',
        }}>
          <span style={{ fontSize: 16 }}>{simStatus === 'running' ? '⚡' : '✅'}</span>
          <span style={{ fontWeight: 800, fontSize: 12, textTransform: 'uppercase', letterSpacing: '1px',
            color: simStatus === 'running' ? C.red : C.green,
          }}>
            {simStatus === 'running' ? 'ATTACK SIMULATION RUNNING' : 'SIMULATION COMPLETE — 7 threats injected'}
          </span>
          {simStatus === 'running' && (
            <span style={{ fontSize: 11, color: C.muted }}>— injecting threats into live feed...</span>
          )}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
            {simStatus === 'running' && ['T1566.001','T1110.004','T1486','T1048','T1598'].map(t => (
              <span key={t} style={{
                fontFamily: 'monospace', fontSize: 10, color: C.red,
                background: 'rgba(0,0,0,0.4)', padding: '2px 6px', borderRadius: 3,
                border: `1px solid ${C.redDim}`,
              }}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {banner && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, zIndex: 9998,
          background: `linear-gradient(135deg, ${C.redDim}, #7f1d1d)`,
          borderBottom: `1px solid ${C.red}`,
          padding: '10px 24px', display: 'flex', alignItems: 'center', gap: 12,
          boxShadow: `0 2px 20px rgba(220,38,38,0.5)`,
          animation: 'slideIn 0.25s ease',
        }}>
          <span style={{ fontSize: 16 }}>🚨</span>
          <span style={{ fontWeight: 700, fontSize: 13, color: C.red, textTransform: 'uppercase', letterSpacing: '0.5px' }}>New Threat Detected</span>
          <span style={{ fontSize: 13, color: C.text }}>— {banner.name}</span>
          <span style={{ marginLeft: 'auto', background: 'rgba(0,0,0,0.4)', padding: '2px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace', color: C.red }}>{banner.mitre}</span>
          <span style={{ fontSize: 10, background: `${SEV[banner.severity]}20`, padding: '2px 8px', borderRadius: 3, color: SEV[banner.severity], border: `1px solid ${SEV[banner.severity]}40` }}>{banner.severity.toUpperCase()}</span>
        </div>
      )}

      <header style={{
        background: C.surface, borderBottom: `1px solid ${C.border}`,
        padding: '0 24px', height: 56, display: 'flex', alignItems: 'center',
        position: 'sticky', top: banner ? 42 : 0, zIndex: 200, gap: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginRight: 28 }}>
          <div style={{
            width: 34, height: 34, background: C.red, borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18,
            boxShadow: `0 0 12px ${C.red}60`,
          }}>🛡</div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.3px', lineHeight: 1.2 }}>RetailShield</div>
            <div style={{ fontSize: 9, color: C.dim, lineHeight: 1 }}>by ShieldTech Ltd · Tanvir Farhad</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginRight: 'auto' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: C.green, display: 'inline-block', boxShadow: `0 0 8px ${C.green}`, animation: 'pulse 2s infinite' }} />
          <span style={{ fontSize: 11, color: C.green, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Monitoring</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ fontSize: 11, color: C.dim }}>Microsoft Sentinel · Azure · UK Retail SOC</span>
          <span style={{ fontSize: 12, fontFamily: 'monospace', color: C.muted }}>{clock.toLocaleTimeString('en-GB')}</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <span style={{ background: `${C.red}20`, color: C.red, padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 700, border: `1px solid ${C.red}50` }}>{counts.critical} CRITICAL</span>
            <span style={{ background: `${C.orange}20`, color: C.orange, padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 700, border: `1px solid ${C.orange}50` }}>{counts.active} ACTIVE</span>
          </div>
          <button onClick={runAttackSimulation} disabled={simStatus === 'running'} style={{
            background: simStatus === 'running' ? 'transparent' : `linear-gradient(135deg, ${C.red}, #b91c1c)`,
            color: simStatus === 'running' ? C.red : '#fff',
            border: `1.5px solid ${C.red}`, borderRadius: 7, padding: '7px 16px',
            fontSize: 11, fontWeight: 800, letterSpacing: '0.6px', textTransform: 'uppercase',
            cursor: simStatus === 'running' ? 'not-allowed' : 'pointer',
            boxShadow: simStatus === 'running' ? 'none' : `0 0 14px ${C.red}60`,
            animation: simStatus === 'running' ? 'urgentPulse 0.7s ease-in-out infinite' : 'none',
            transition: 'box-shadow 0.2s, background 0.2s', whiteSpace: 'nowrap',
          }}>
            {simStatus === 'running' ? '⚡ RUNNING…' : '⚡ SIMULATE ATTACK'}
          </button>
        </div>
      </header>

      <main style={{ padding: '20px 24px', maxWidth: 1440, margin: '0 auto' }}>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 18 }}>
          {[
            { label: 'Total Threats',  value: counts.total,    color: C.text,   icon: '⚡', sub: 'last 24 hours'  },
            { label: 'Critical',       value: counts.critical, color: C.red,    icon: '🔴', sub: 'immediate action' },
            { label: 'Active',         value: counts.active,   color: C.orange, icon: '🟠', sub: 'in-progress'     },
            { label: 'Blocked',        value: counts.blocked,  color: C.green,  icon: '🟢', sub: 'auto-contained'  },
          ].map(({ label, value, color, icon, sub }) => (
            <div key={label} style={{ ...s.card, padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: C.muted, textTransform: 'uppercase', letterSpacing: '0.6px' }}>{label}</span>
                <span style={{ fontSize: 14 }}>{icon}</span>
              </div>
              <div style={{ fontSize: 36, fontWeight: 800, color, fontFamily: 'monospace', lineHeight: 1 }}>{value}</div>
              <div style={{ fontSize: 11, color: C.dim, marginTop: 5 }}>{sub}</div>
            </div>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 18 }}>
          {['all', 'critical', 'active', 'blocked'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: '7px 18px', borderRadius: 7, cursor: 'pointer', fontSize: 12,
              fontWeight: filter === f ? 700 : 400, textTransform: 'uppercase', letterSpacing: '0.5px',
              transition: 'all 0.2s', border: `1px solid ${filter === f ? C.red : C.border}`,
              background: filter === f ? `${C.red}15` : 'transparent',
              color: filter === f ? C.red : C.muted,
            }}>
              {f === 'all' ? `All (${counts.total})` : f === 'critical' ? `Critical (${counts.critical})` : f === 'active' ? `Active (${counts.active})` : `Blocked (${counts.blocked})`}
            </button>
          ))}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: C.red, display: 'inline-block', animation: 'pulse 1.5s infinite' }} />
            <span style={{ fontSize: 11, color: C.dim }}>{filtered.length} alerts · refresh every 6s</span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 18, marginBottom: 18 }}>
          <div style={s.card}>
            <div style={{ padding: '14px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, fontSize: 13 }}>Live Threat Feed</span>
              <span style={{ fontSize: 11, color: C.dim }}>Click any row to open incident playbook →</span>
            </div>
            <div style={{ overflowY: 'auto', maxHeight: 500 }}>
              {filtered.length === 0 && (
                <div style={{ padding: 32, textAlign: 'center', color: C.dim, fontSize: 13 }}>No threats match this filter.</div>
              )}
              {filtered.map(threat => (
                <div key={threat.id} onClick={() => setSelected(threat)} style={{
                  padding: '13px 20px', borderBottom: `1px solid ${C.border}`,
                  borderLeft: `3px solid ${SEV[threat.severity]}`, cursor: 'pointer', transition: 'background 0.15s',
                }}
                  onMouseEnter={e => e.currentTarget.style.background = C.cardHover}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 5 }}>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{threat.name}</span>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0, marginLeft: 16 }}>
                      <span style={{ fontSize: 10, color: SEV[threat.severity], background: `${SEV[threat.severity]}18`, padding: '2px 7px', borderRadius: 3, fontWeight: 700 }}>{threat.severity.toUpperCase()}</span>
                      <span style={{ fontSize: 10, color: STA[threat.status], padding: '2px 7px', borderRadius: 3, border: `1px solid ${STA[threat.status]}40` }}>{threat.status}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 16, fontSize: 11, color: C.muted, flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'monospace', color: C.red, fontWeight: 700 }}>{threat.mitre}</span>
                    <span>📍 {threat.device}</span>
                    <span>👤 {threat.user}</span>
                    <span style={{ marginLeft: 'auto', color: C.dim }}>🕐 {threat.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ ...s.card, padding: '16px 18px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 10 }}>Security Posture</div>
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 4 }}>
                <SecurityGauge score={Math.round(score)} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {[
                  { label: 'Rules Active', val: '8 / 8',  color: C.green },
                  { label: 'MTTD',         val: '4.2 min', color: C.text  },
                  { label: 'MTTR',         val: '18 min',  color: C.text  },
                  { label: 'FP Rate',      val: '2.1%',   color: C.green },
                ].map(({ label, val, color }) => (
                  <div key={label} style={{ background: C.surface, borderRadius: 6, padding: '8px 10px' }}>
                    <div style={{ fontSize: 10, color: C.dim, marginBottom: 2 }}>{label}</div>
                    <div style={{ fontSize: 13, fontWeight: 700, color, fontFamily: 'monospace' }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ ...s.card, padding: '16px 18px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12 }}>Attack Timeline — 12h</div>
              <AttackTimeline tick={tick} />
            </div>
          </div>
        </div>

        <div style={{ ...s.card, padding: '20px 24px', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <span style={{ fontWeight: 700, fontSize: 13 }}>MITRE ATT&amp;CK Coverage — Retail TTP Matrix</span>
            <span style={{ fontSize: 11, color: C.green, background: `${C.green}15`, padding: '4px 12px', borderRadius: 5, border: `1px solid ${C.green}40` }}>8 / 8 Techniques Monitored</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0 36px' }}>
            {mitre.map(m => <MitreBar key={m.technique} {...m} />)}
          </div>
        </div>

        <div style={{ ...s.card, padding: '20px 24px', marginBottom: 18, position: 'relative', overflow: 'hidden' }}>
          {vulnScan === 'scanning' && (
            <div style={{ position: 'absolute', inset: 0, background: 'rgba(8,8,8,0.88)', zIndex: 10, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 20 }}>
              <div style={{ fontSize: 13, color: C.blue, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', animation: 'scanPulse 1s ease-in-out infinite' }}>Scanning Retail Infrastructure...</div>
              <div style={{ width: 340, height: 8, background: C.border, borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${vulnProg}%`, borderRadius: 4, background: `linear-gradient(90deg, ${C.blue}, ${C.red})`, boxShadow: `0 0 12px ${C.blue}80`, transition: 'width 0.2s ease' }} />
              </div>
              <div style={{ fontSize: 11, color: C.muted, fontFamily: 'monospace' }}>Checking {vulnData.totalAssets} assets against 32 retail CVEs — {vulnProg}%</div>
            </div>
          )}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div>
              <span style={{ fontWeight: 700, fontSize: 13 }}>CVE Vulnerability Scanner — Retail Stack</span>
              <div style={{ fontSize: 11, color: C.dim, marginTop: 3 }}>Last scan: {new Date(vulnData.lastScan).toLocaleString('en-GB')} · {vulnData.totalAssets} assets · {vulnData.findings.length} vulnerable{vulnScan === 'done' && <span style={{ color: C.green, marginLeft: 8, fontWeight: 700 }}>✓ Scan complete</span>}</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {[{label:'CRITICAL',val:vulnData.summary.critical,color:C.red},{label:'HIGH',val:vulnData.summary.high,color:C.orange},{label:'MEDIUM',val:vulnData.summary.medium,color:C.yellow},{label:'LOW',val:vulnData.summary.low,color:C.blue}].map(({label,val,color}) => (
                <div key={label} style={{ background:`${color}18`,border:`1px solid ${color}50`,borderRadius:6,padding:'5px 12px',textAlign:'center' }}>
                  <div style={{ fontSize:16,fontWeight:800,color,fontFamily:'monospace',lineHeight:1 }}>{val}</div>
                  <div style={{ fontSize:9,color,opacity:0.8,marginTop:2,letterSpacing:'0.5px' }}>{label}</div>
                </div>
              ))}
              <button onClick={runVulnScan} disabled={vulnScan==='scanning'} style={{
                background: vulnScan==='scanning' ? 'transparent' : `linear-gradient(135deg, ${C.blue}, #1d4ed8)`,
                color: vulnScan==='scanning' ? C.blue : '#fff', border:`1.5px solid ${C.blue}`,
                borderRadius:7,padding:'8px 16px',fontSize:11,fontWeight:800,letterSpacing:'0.6px',
                textTransform:'uppercase',cursor:vulnScan==='scanning'?'not-allowed':'pointer',
                boxShadow:vulnScan==='scanning'?'none':`0 0 14px ${C.blue}50`,whiteSpace:'nowrap',
                animation:vulnScan==='scanning'?'scanPulse 0.8s ease-in-out infinite':'none',
                transition:'box-shadow 0.2s, background 0.2s',
              }}>{vulnScan==='scanning'?`🔍 SCANNING ${vulnProg}%`:'🔍 RUN VULNERABILITY SCAN'}</button>
            </div>
          </div>
          <div style={{ border:`1px solid ${C.border}`,borderRadius:8,overflow:'hidden' }}>
            <div style={{ display:'grid',gridTemplateColumns:'130px 1fr 90px 140px 90px 80px 100px',background:C.surface,padding:'8px 14px',borderBottom:`1px solid ${C.border}` }}>
              {['ASSET ID','CVE / DESCRIPTION','CVSS','PRODUCT','VERSION','SEVERITY','PATCH'].map(h=>(<span key={h} style={{fontSize:10,color:C.dim,fontWeight:700,letterSpacing:'0.5px'}}>{h}</span>))}
            </div>
            <div style={{ maxHeight:360,overflowY:'auto' }}>
              {vulnData.findings.flatMap(f=>f.vulns.map((v,vi)=>{
                const sevColor=SEV[v.sev]||C.muted
                return(
                  <div key={`${f.id}-${v.cve}`} style={{ display:'grid',gridTemplateColumns:'130px 1fr 90px 140px 90px 80px 100px',padding:'10px 14px',borderBottom:`1px solid ${C.border}`,borderLeft:`3px solid ${sevColor}`,transition:'background 0.15s' }}
                    onMouseEnter={e=>e.currentTarget.style.background=C.cardHover}
                    onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                    <div style={{fontSize:11,fontFamily:'monospace',color:C.red,fontWeight:700,alignSelf:'center'}}>{vi===0?f.id:''}</div>
                    <div style={{alignSelf:'center',paddingRight:12}}>
                      <div style={{fontSize:11,fontFamily:'monospace',color:C.text,fontWeight:700,marginBottom:2}}>{v.cve}{v.exploit&&<span style={{marginLeft:6,fontSize:9,color:C.red,background:`${C.red}20`,padding:'1px 5px',borderRadius:3,border:`1px solid ${C.red}40`}}>EXPLOIT</span>}</div>
                      <div style={{fontSize:11,color:C.muted,lineHeight:1.4}}>{v.title}</div>
                      <div style={{fontSize:10,color:C.dim,marginTop:2,fontFamily:'monospace'}}>MITRE: {v.mitre}</div>
                    </div>
                    <div style={{alignSelf:'center'}}><span style={{fontSize:14,fontWeight:800,fontFamily:'monospace',color:sevColor,textShadow:`0 0 8px ${sevColor}60`}}>{v.cvss}</span></div>
                    <div style={{fontSize:11,color:C.muted,alignSelf:'center'}}>{vi===0?f.product:''}</div>
                    <div style={{alignSelf:'center'}}>{vi===0&&<span style={{fontSize:10,fontFamily:'monospace',background:C.surface,border:`1px solid ${C.border}`,padding:'2px 7px',borderRadius:4,color:C.muted}}>v{f.version}</span>}</div>
                    <div style={{alignSelf:'center'}}><span style={{fontSize:10,fontWeight:700,color:sevColor,background:`${sevColor}18`,padding:'3px 8px',borderRadius:4,textTransform:'uppercase'}}>{v.sev}</span></div>
                    <div style={{alignSelf:'center'}}><span style={{fontSize:10,fontWeight:600,color:v.patch?C.green:C.red}}>{v.patch?'✓ Available':'✗ No patch'}</span></div>
                  </div>
                )
              }))}
            </div>
          </div>
          <div style={{ display:'flex',gap:20,marginTop:14,flexWrap:'wrap' }}>
            {[
              {label:'Assets Scanned',val:vulnData.totalAssets,color:C.text},
              {label:'Total CVEs',val:vulnData.summary.critical+vulnData.summary.high+vulnData.summary.medium+vulnData.summary.low,color:C.text},
              {label:'Patch Available',val:vulnData.findings.reduce((n,f)=>n+f.vulns.filter(v=>v.patch).length,0),color:C.green},
              {label:'Public Exploits',val:vulnData.findings.reduce((n,f)=>n+f.vulns.filter(v=>v.exploit).length,0),color:C.red},
            ].map(({label,val,color})=>(<div key={label} style={{background:C.surface,borderRadius:6,padding:'8px 14px',display:'flex',gap:10,alignItems:'center'}}><span style={{fontSize:18,fontWeight:800,color,fontFamily:'monospace'}}>{val}</span><span style={{fontSize:11,color:C.dim}}>{label}</span></div>))}
          </div>
        </div>

        <div style={{ ...s.card, padding: '20px 24px', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div>
              <span style={{ fontWeight: 700, fontSize: 13 }}>PCI DSS v4.0 Compliance Scorecard</span>
              <div style={{ fontSize: 11, color: C.dim, marginTop: 3 }}>Retail payment card security — 12 requirements · Auto-mapped from RetailShield detection rules &amp; CVE scanner</div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {[{label:'COVERED',n:8,color:C.green},{label:'PARTIAL',n:2,color:C.yellow},{label:'PLANNED',n:1,color:C.dim}].map(({label,n,color})=>(
                <div key={label} style={{background:`${color}15`,border:`1px solid ${color}40`,borderRadius:6,padding:'5px 12px',textAlign:'center'}}>
                  <div style={{fontSize:16,fontWeight:800,color,fontFamily:'monospace',lineHeight:1}}>{n}</div>
                  <div style={{fontSize:9,color,opacity:0.8,marginTop:2,letterSpacing:'0.5px'}}>{label}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {[
              { req:'Req 1',  label:'Network Security Controls',         status:'covered', rule:'supply_chain_anomaly.kql', color:C.green  },
              { req:'Req 2',  label:'Secure System Configurations',      status:'covered', rule:'cve_scanner.py',           color:C.green  },
              { req:'Req 3',  label:'Protect Stored Cardholder Data',    status:'covered', rule:'data_exfiltration.kql',    color:C.green  },
              { req:'Req 4',  label:'Encrypt Cardholder Data in Transit',status:'covered', rule:'CVE-2024-38291 (TLS)',     color:C.green  },
              { req:'Req 5',  label:'Anti-Malware Protection',           status:'covered', rule:'ransomware_indicator.kql', color:C.green  },
              { req:'Req 6',  label:'Secure Software Development',       status:'covered', rule:'cve_scanner.py (patches)', color:C.green  },
              { req:'Req 7',  label:'Restrict Access by Business Need',  status:'partial', rule:'after_hours_access.kql',  color:C.yellow },
              { req:'Req 8',  label:'Identify Users & Auth Access',      status:'covered', rule:'credential_stuffing.kql', color:C.green  },
              { req:'Req 9',  label:'Restrict Physical Access',          status:'partial', rule:'pos_anomaly.kql',          color:C.yellow },
              { req:'Req 10', label:'Log & Monitor All Access',          status:'covered', rule:'All 8 KQL rules',          color:C.green  },
              { req:'Req 11', label:'Test Security Systems Regularly',   status:'covered', rule:'cve_scanner.py (scans)',   color:C.green  },
              { req:'Req 12', label:'Organisational Security Policies',  status:'planned', rule:'v3.0 — Planned',          color:C.dim    },
            ].map(({ req, label, status, rule, color }) => (
              <div key={req} style={{ background:C.surface,borderRadius:8,padding:'12px 14px',borderLeft:`3px solid ${color}`,display:'flex',flexDirection:'column',gap:4 }}>
                <div style={{ display:'flex',justifyContent:'space-between',alignItems:'center' }}>
                  <span style={{ fontSize:10,fontFamily:'monospace',fontWeight:700,color,letterSpacing:'0.5px' }}>{req}</span>
                  <span style={{ fontSize:9,color,background:`${color}20`,padding:'2px 6px',borderRadius:3,textTransform:'uppercase',fontWeight:700 }}>{status}</span>
                </div>
                <div style={{ fontSize:11,color:C.text,fontWeight:600,lineHeight:1.3 }}>{label}</div>
                <div style={{ fontSize:10,color:C.dim,fontFamily:'monospace',marginTop:2 }}>{rule}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ ...s.card, padding: '20px 24px', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: briefing ? 16 : 0 }}>
            <div>
              <span style={{ fontWeight: 700, fontSize: 13 }}>AI Executive Threat Briefing</span>
              <div style={{ fontSize: 11, color: C.dim, marginTop: 3 }}>Claude AI generates a board-ready summary from live dashboard state · Powered by Anthropic</div>
            </div>
            <button onClick={generateBriefing} disabled={briefStatus==='loading'} style={{
              background: briefStatus==='loading' ? 'transparent' : `linear-gradient(135deg, #7c3aed, #6d28d9)`,
              color: briefStatus==='loading' ? '#7c3aed' : '#fff',
              border:'1.5px solid #7c3aed',borderRadius:7,padding:'8px 18px',
              fontSize:11,fontWeight:800,letterSpacing:'0.6px',textTransform:'uppercase',
              cursor:briefStatus==='loading'?'not-allowed':'pointer',
              boxShadow:briefStatus==='loading'?'none':'0 0 16px rgba(124,58,237,0.5)',
              whiteSpace:'nowrap',
              animation:briefStatus==='loading'?'scanPulse 0.8s ease-in-out infinite':'none',
              transition:'box-shadow 0.2s, background 0.2s',
            }}>{briefStatus==='loading'?'⚡ GENERATING...':'⚡ GENERATE AI BRIEFING'}</button>
          </div>
          {briefing && (
            <div style={{ background:'linear-gradient(135deg, #0d0618, #130a2a)',border:'1px solid #7c3aed40',borderLeft:'3px solid #7c3aed',borderRadius:8,padding:'18px 20px' }}>
              <div style={{ display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12 }}>
                <span style={{ fontSize:11,fontWeight:700,color:'#a78bfa',textTransform:'uppercase',letterSpacing:'1px' }}>Claude AI — Executive Briefing</span>
                <div style={{ display:'flex',gap:8 }}>
                  <span style={{ fontSize:10,color:C.dim,fontFamily:'monospace' }}>{new Date().toLocaleString('en-GB')}</span>
                  <button onClick={()=>{setBriefing(null);setBriefStatus(null)}} style={{ background:'transparent',border:'none',color:C.dim,cursor:'pointer',fontSize:14,padding:'0 4px' }}>✕</button>
                </div>
              </div>
              <pre style={{ fontFamily:'-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',fontSize:13,color:C.text,lineHeight:1.8,whiteSpace:'pre-wrap',margin:0 }}>{briefing}</pre>
            </div>
          )}
          {!briefing && (
            <div style={{ background:C.surface,borderRadius:8,padding:'20px 24px',textAlign:'center',border:'1px dashed #7c3aed40',marginTop:16 }}>
              <div style={{ fontSize:28,marginBottom:8 }}>🤖</div>
              <div style={{ fontSize:13,color:C.muted,marginBottom:4 }}>Click <strong style={{ color:'#a78bfa' }}>GENERATE AI BRIEFING</strong> to produce a board-ready executive summary</div>
              <div style={{ fontSize:11,color:C.dim }}>Analyses active threats · CVE severity · PCI DSS exposure · Regulatory obligations</div>
            </div>
          )}
        </div>

        <div style={{ ...s.card, padding: '20px 24px' }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 16 }}>🆘 Emergency Contacts</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            {[
              { org:'NCSC', full:'National Cyber Security Centre', tel:'0300 020 0973', email:'report@ncsc.gov.uk', note:'Critical infrastructure & national-level cyber incidents', color:C.blue, icon:'🏗' },
              { org:'ICO', full:"Information Commissioner's Office", tel:'0303 123 1113', email:'casework@ico.org.uk', note:'GDPR breach notification — 72-hour statutory window', color:C.yellow, icon:'⚖️' },
              { org:'Action Fraud', full:'UK National Fraud & Cybercrime', tel:'0300 123 2040', email:'actionfraud.police.uk', note:'Report financial fraud, voice fraud, and cybercrime', color:C.orange, icon:'🚔' },
            ].map(({ org, full, tel, email, note, color, icon }) => (
              <div key={org} style={{ background:C.surface,borderRadius:8,padding:'16px 18px',borderLeft:`3px solid ${color}` }}>
                <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:4 }}>
                  <span style={{ fontSize:16 }}>{icon}</span>
                  <span style={{ fontWeight:800,fontSize:15,color }}>{org}</span>
                </div>
                <div style={{ fontSize:11,color:C.muted,marginBottom:10 }}>{full}</div>
                <div style={{ fontSize:12,color:C.text,marginBottom:3 }}>📞 {tel}</div>
                <div style={{ fontSize:12,color:C.text,marginBottom:10 }}>✉  {email}</div>
                <div style={{ fontSize:11,color:C.dim,lineHeight:1.5 }}>{note}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ textAlign:'center',padding:'20px 0 8px',color:C.dim,fontSize:11 }}>RetailShield v1.0 · ShieldTech Ltd · Tanvir Farhad · Microsoft Sentinel · MITRE ATT&amp;CK Enterprise</div>
      </main>

      <PlaybookModal threat={selected} onClose={() => setSelected(null)} />

      <style>{`
        @keyframes slideIn      { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes pulse        { 0%,100% { opacity: 1; box-shadow: 0 0 6px currentColor; } 50% { opacity: 0.3; box-shadow: none; } }
        @keyframes simPulse     { 0%,100% { opacity: 1; } 50% { opacity: 0.75; } }
        @keyframes urgentPulse  { 0%,100% { box-shadow: 0 0 14px rgba(220,38,38,0.8); } 50% { box-shadow: 0 0 4px rgba(220,38,38,0.2); } }
        @keyframes scanPulse    { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        ::-webkit-scrollbar       { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: ${C.surface}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        button:focus { outline: none; }
      `}</style>
    </div>
  )
}
