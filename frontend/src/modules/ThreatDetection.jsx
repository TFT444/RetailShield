import { useState, useEffect, useCallback, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import {
  Activity, AlertTriangle, Shield, Zap, Clock, Check,
  X, Download, Copy, RefreshCw, FileText, Search,
} from 'lucide-react';
import TopBar       from '../components/TopBar.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge  from '../components/StatusBadge.jsx';
import StatCard     from '../components/StatCard.jsx';
import { ATTACK_SIM_EVENTS, MITRE_COVERAGE } from '../lib/data.js';
import { useBreakpoint } from '../lib/hooks.js';

const TIMELINE_BASE = [
  {t:'06:00',v:1},{t:'06:30',v:0},{t:'07:00',v:2},{t:'07:30',v:1},
  {t:'08:00',v:3},{t:'08:30',v:5},{t:'09:00',v:7},{t:'09:30',v:4},
  {t:'10:00',v:2},{t:'10:30',v:3},{t:'11:00',v:6},{t:'11:30',v:8},
];

function detectAttackType(inc) {
  switch (inc.technique) {
    case 'T1486':     return 'ransomware';
    case 'T1048':     return 'exfiltration';
    case 'T1110.004': return 'credentialStuffing';
    case 'T1566.001': return 'phishing';
    case 'T1657':     return 'giftCardFraud';
    case 'T1656':     return 'aiVoiceFraud';
    case 'T1565':     return 'posManipulation';
    case 'T1199':     return 'supplyChain';
    case 'T1621':     return 'mfaFatigue';
    case 'T1550.002': return 'lateralMovement';
    case 'T1190':     return 'sqlInjection';
    case 'T1098.003': return 'privilegedRole';
    case 'T1078':     return 'afterHoursAccess';
    default:          return 'generic';
  }
}

function generateReport(inc, now) {
  if (!inc) return '';
  const det  = inc.detectedAt ? new Date(inc.detectedAt) : now;
  const ico  = new Date(det.getTime() + 72 * 3600000);
  const ncsc = new Date(det.getTime() + 24 * 3600000);
  const fmt  = d => d.toLocaleString('en-GB', { timeZone:'Europe/London', day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' });
  const type = detectAttackType(inc);
  const lines = [];
  const add  = s => lines.push(s);

  add('RETAILSHIELD — INCIDENT REPORT');
  add(`Generated: ${fmt(now)}  |  Classification: CONFIDENTIAL`);
  add('─'.repeat(60));

  // ── §1  EXECUTIVE SUMMARY ────────────────────────────────
  add('\n§1  EXECUTIVE SUMMARY');
  add(`Incident ID  : ${inc.id}`);
  add(`Title        : ${inc.title}`);
  add(`Severity     : ${inc.severity}`);
  add(`MITRE Tactic : ${inc.tactic} (${inc.technique})`);
  add(`Status       : ${inc.status}`);
  add(`Detected     : ${inc.detectedAt ? fmt(new Date(inc.detectedAt)) : 'During simulation'}`);
  add(`MTTD         : ${inc.mttd} minutes`);
  add(`\n${inc.description}`);

  if (type === 'ransomware') {
    add(`\nEncryption spread: ${inc.filesModified?.toLocaleString() || 'Unknown'} files encrypted within 2 minutes of execution. Family: ${inc.ransomwareFamily || 'Unknown'}. Extension: ${inc.suspiciousExtension || 'Unknown'}.`);
    add(`Business continuity is at immediate risk. Backup integrity assessment is underway.`);
  } else if (type === 'exfiltration') {
    const gb = inc.dataTransferredGB;
    add(`\nVolume exfiltrated: ${gb ? `${gb.toLocaleString()} GB (${(gb / 1024).toFixed(1)} TB)` : 'Unknown'} transferred to ${inc.geoLocation || 'unknown'} infrastructure (${inc.destinationIP || 'Unknown'}:${inc.destinationPort || 'Unknown'}).`);
    add(`UK GDPR Article 33 notification is likely required within 72 hours.`);
  } else if (type === 'credentialStuffing') {
    add(`\nAttack volume: ${inc.failedAttempts?.toLocaleString() || 'Unknown'} failed login attempts from ${inc.geoLocation || inc.country || 'unknown'} (${inc.sourceIP || 'Unknown'}).`);
    add(`Credential pairs sourced from known breach datasets. Customer account integrity is under SIEM assessment.`);
  } else if (type === 'phishing') {
    add(`\nPhishing score: ${inc.phishingScore || 'Unknown'}/100. Attachment: .${inc.attachmentType?.toUpperCase() || 'Unknown'}. Sender: ${inc.sourceEmail || 'Unknown'}.`);
    add(`Target: ${inc.entity || 'Unknown'}. Email quarantined automatically before user interaction.`);
  } else if (type === 'giftCardFraud') {
    add(`\nFinancial exposure: £${inc.estimatedLossGBP?.toLocaleString() || '0'} across ${inc.cardsAffected?.toLocaleString() || '0'} gift cards drained via automated API attack.`);
    add(`Affected cards frozen pending reissuance. Fraud team notified.`);
  } else if (type === 'aiVoiceFraud') {
    add(`\nFraud method: ${inc.fraudMethod || 'AI voice cloning'}. Target: ${inc.targetRole || 'Unknown'} at ${inc.entity || 'Unknown'}.`);
    add(`Staff member identified the fraud before completing any financial transfer. No financial loss confirmed.`);
  } else if (type === 'posManipulation') {
    add(`\nVoid/refund abuse: ${inc.voidCount || 'Unknown'} transactions totalling £${inc.refundTotalGBP?.toLocaleString() || '0'} by operator ${inc.operatorName || 'Unknown'} — 92% without a preceding customer sale.`);
  } else if (type === 'supplyChain') {
    add(`\nCompromised supplier account: ${inc.supplierAccount || 'Unknown'} authenticated from unrecognised IP ${inc.sourceIP || 'Unknown'}. Attempted bank detail modification and purchase order exfiltration.`);
  } else if (type === 'mfaFatigue') {
    add(`\nMFA push volume: ${inc.pushCount || 'Unknown'} push notifications against ${inc.entity || 'targeted accounts'} within 20 minutes. No successful bypass recorded.`);
  } else if (type === 'lateralMovement') {
    add(`\nPass-the-hash lateral movement: ${inc.sourceHost || 'compromised host'} → ${inc.targetHost || 'management server'}. NTLM hash reuse — no plaintext credentials required.`);
  } else if (type === 'sqlInjection') {
    add(`\nInjection pattern: ${inc.injectionPattern || 'UNION-based'} on ${inc.entity || 'API endpoint'}. WAF blocked all payloads — no confirmed data extraction.`);
  } else if (type === 'privilegedRole') {
    add(`\nAccount ${inc.accountModified || 'Unknown'} granted ${inc.roleAdded || 'privileged role'} outside change control. Role automatically reverted within ${inc.mttd || 'Unknown'} minutes.`);
  }

  // ── §2  TECHNICAL DETAILS ────────────────────────────────
  add('\n§2  TECHNICAL DETAILS');
  add(`Attack technique : ${inc.technique} — ${inc.tactic}`);

  if (type === 'ransomware') {
    if (inc.deviceName)          add(`Infected host        : ${inc.deviceName}`);
    if (inc.filesModified)       add(`Files encrypted      : ${inc.filesModified.toLocaleString()}`);
    if (inc.suspiciousExtension) add(`Encrypted extension  : ${inc.suspiciousExtension}`);
    if (inc.ransomwareFamily)    add(`Ransomware family    : ${inc.ransomwareFamily}`);
    add(`Encryption scope     : Domain controller — maximum blast radius`);
    add(`Shadow copy deletion : Likely (standard ${inc.ransomwareFamily || 'ransomware'} TTP)`);
    add(`C2 communication     : Outbound beacon activity detected pre-encryption`);
    add(`Initial vector       : Under investigation — likely phishing or RDP brute force`);
  } else if (type === 'exfiltration') {
    if (inc.entity)            add(`Source system    : ${inc.entity}`);
    if (inc.destinationIP)     add(`Destination IP   : ${inc.destinationIP} (${inc.geoLocation || 'Unknown'})`);
    if (inc.destinationPort)   add(`Destination port : ${inc.destinationPort}`);
    if (inc.dataTransferredGB) add(`Data transferred : ${inc.dataTransferredGB.toLocaleString()} GB`);
    add(`IP reputation    : Known malicious — listed on threat intelligence feeds`);
    add(`Protocol         : Custom C2 / raw TCP on port ${inc.destinationPort || '4444'}`);
    add(`Data at risk     : ${inc.dataCategories?.join(', ') || 'Customer PII, Payment Records'}`);
    add(`Extraction method: Automated script — sustained bandwidth usage pattern detected`);
  } else if (type === 'credentialStuffing') {
    if (inc.sourceIP)       add(`Source IP         : ${inc.sourceIP} (${inc.geoLocation || inc.country || 'Unknown'})`);
    if (inc.failedAttempts) add(`Failed attempts   : ${inc.failedAttempts.toLocaleString()}`);
    if (inc.entity)         add(`Target system     : ${inc.entity}`);
    add(`Credential source : Known breached pairs from dark web marketplaces`);
    add(`Attack pattern    : Distributed — multiple user agents and spoofed headers`);
    add(`Geographic anomaly: Origin inconsistent with UK customer base`);
    add(`Successful logins : Under investigation — SIEM correlation in progress`);
  } else if (type === 'phishing') {
    if (inc.sourceEmail)    add(`Sender email    : ${inc.sourceEmail}`);
    if (inc.entity)         add(`Target mailbox  : ${inc.entity}`);
    if (inc.attachmentType) add(`Attachment type : .${inc.attachmentType} (macro-enabled Office document)`);
    if (inc.phishingScore)  add(`Phishing score  : ${inc.phishingScore}/100 (alert threshold: 70)`);
    add(`Email lure      : ${inc.title.includes('CFO') ? 'Board communications impersonation' : 'Supplier invoice impersonation'}`);
    add(`DMARC result    : FAIL — sender domain not authorised by SPF/DKIM`);
    add(`Sandbox verdict : MALICIOUS — macro executes PowerShell download cradle`);
    add(`Payload         : Cobalt Strike beacon (C2 callback on execution)`);
  } else if (type === 'giftCardFraud') {
    if (inc.sourceIP)         add(`Source IP        : ${inc.sourceIP}`);
    if (inc.cardsAffected)    add(`Cards targeted   : ${inc.cardsAffected.toLocaleString()}`);
    if (inc.estimatedLossGBP) add(`Estimated loss   : £${inc.estimatedLossGBP.toLocaleString()}`);
    if (inc.entity)           add(`Target endpoint  : ${inc.entity}`);
    add(`Attack velocity  : 200+ balance checks per minute (normal baseline: <5/min)`);
    add(`Card source      : Prior data breach or dark web card number dump`);
    add(`Redemption method: Automated script cycling card numbers via API`);
    add(`POS correlation  : No in-store POS involvement — pure API-layer attack`);
  } else if (type === 'aiVoiceFraud') {
    if (inc.entity)      add(`Targeted store   : ${inc.entity}`);
    if (inc.targetRole)  add(`Target role      : ${inc.targetRole}`);
    if (inc.fraudMethod) add(`Fraud method     : ${inc.fraudMethod}`);
    add(`Impersonated     : Regional store manager (known and trusted by staff)`);
    add(`Voice indicators : Unusual cadence, audio artefacts, no ambient background noise`);
    add(`Social eng. chain: 1) Voice call → 2) Urgency framing → 3) Financial request`);
    add(`Call metadata    : Preserved for forensic analysis and law enforcement referral`);
    add(`Detection method : Staff-initiated report via fraud hotline`);
  } else if (type === 'posManipulation') {
    if (inc.operatorName)   add(`Operator             : ${inc.operatorName}`);
    if (inc.entity)         add(`Affected store       : ${inc.entity}`);
    if (inc.voidCount)      add(`Void/refund count    : ${inc.voidCount}`);
    if (inc.refundTotalGBP) add(`Total value          : £${inc.refundTotalGBP.toLocaleString()}`);
    add(`Refund-without-sale  : 92% (industry alert threshold: >25%)`);
    add(`Transaction pattern  : All voids by same operator on same POS terminal`);
    add(`CCTV correlation     : Footage flagged for retention — loss prevention review required`);
  } else if (type === 'supplyChain') {
    if (inc.supplierAccount) add(`Supplier account : ${inc.supplierAccount}`);
    if (inc.sourceIP)        add(`Login IP         : ${inc.sourceIP}`);
    if (inc.entity)          add(`Target portal    : ${inc.entity}`);
    add(`Suspicious actions : Bank detail modification + PO history download in one session`);
    add(`Device fingerprint : Unknown — no prior access record from this device`);
    add(`Auth method        : Valid credentials — account likely compromised via phishing`);
    add(`Financial risk     : Accounts Payable holds suspended pending supplier verification`);
  } else if (type === 'mfaFatigue') {
    if (inc.sourceIP)  add(`Source IP         : ${inc.sourceIP}`);
    if (inc.pushCount) add(`Push notifications: ${inc.pushCount}`);
    if (inc.entity)    add(`Targeted accounts : ${inc.entity}`);
    add(`Attack duration   : 20 minutes (sustained push bombing campaign)`);
    add(`MFA method        : Authenticator app push — inherently susceptible to fatigue`);
    add(`Successful bypass : None confirmed — all push approvals blocked`);
    add(`Password exposure : Attacker held valid passwords — prior credential breach likely`);
  } else if (type === 'lateralMovement') {
    if (inc.sourceHost) add(`Source host      : ${inc.sourceHost}`);
    if (inc.targetHost) add(`Target host      : ${inc.targetHost}`);
    add(`Technique        : Pass-the-Hash (NTLM hash reuse — no plaintext required)`);
    add(`Hash source      : Previously dumped LSASS credential store`);
    add(`Privilege level  : Domain Admin NTLM hash used for authentication`);
    add(`Detection signal : NTLM authentication anomaly — unexpected source/target pair`);
  } else if (type === 'sqlInjection') {
    if (inc.sourceIP)         add(`Source IP        : ${inc.sourceIP}`);
    if (inc.entity)           add(`Target endpoint  : ${inc.entity}`);
    if (inc.injectionPattern) add(`Injection pattern: ${inc.injectionPattern}`);
    add(`Injection type   : UNION-based — attempting schema enumeration and data extraction`);
    add(`WAF response     : All payloads blocked — 0 successful extractions`);
    add(`Vulnerability    : CWE-89 SQL Injection`);
    add(`Data at risk     : Customer PII and payment data in targeted database`);
  } else if (type === 'privilegedRole') {
    if (inc.accountModified) add(`Account modified : ${inc.accountModified}`);
    if (inc.roleAdded)       add(`Role granted     : ${inc.roleAdded}`);
    if (inc.entity)          add(`Directory        : ${inc.entity}`);
    add(`Change window    : Outside approved change control period`);
    add(`Source session   : Originating from previously compromised host`);
    add(`Detection rule   : PAM — Privileged Role Addition outside change window`);
    add(`Revert latency   : Role removed within 1 minute of alert`);
  } else if (type === 'afterHoursAccess') {
    if (inc.operatorName)   add(`Accessing user   : ${inc.operatorName}`);
    if (inc.systemAccessed) add(`System accessed  : ${inc.systemAccessed}`);
    if (inc.entity)         add(`Entity           : ${inc.entity}`);
    if (inc.suspicionScore) add(`Suspicion score  : ${inc.suspicionScore}/100`);
    add(`Access time      : Outside configured operational hours (06:00–22:00)`);
    add(`Credential status: Valid — possible insider threat or credential reuse`);
  } else {
    if (inc.sourceIP)       add(`Source IP      : ${inc.sourceIP} (${inc.country || 'Unknown'})`);
    if (inc.sourceEmail)    add(`Source email   : ${inc.sourceEmail}`);
    if (inc.deviceName)     add(`Affected device: ${inc.deviceName}`);
    if (inc.failedAttempts) add(`Failed attempts: ${inc.failedAttempts.toLocaleString()}`);
    if (inc.filesModified)  add(`Files modified : ${inc.filesModified.toLocaleString()}`);
  }

  // ── §3  IMPACT ASSESSMENT ────────────────────────────────
  add('\n§3  IMPACT ASSESSMENT');
  add(`Impact level: ${inc.impactLevel || 'Under assessment'}`);

  if (inc.affectedEntities?.length) {
    add('\nAffected entities:');
    inc.affectedEntities.forEach(e => add(`  • ${e}`));
  }
  if (inc.dataCategories?.length) {
    add('\nData categories involved:');
    inc.dataCategories.forEach(d => add(`  • ${d}`));
  }

  if (type === 'ransomware') {
    add('\nBusiness continuity impact:');
    add(`  • Warehouse domain controller offline — warehouse operations suspended`);
    add(`  • ${inc.filesModified?.toLocaleString() || 'Unknown'} files encrypted — recovery time objective under assessment`);
    add(`  • Shadow copy deletion suspected — clean offline backups are the primary recovery path`);
    add(`  • Supply chain disruption risk if warehouse remains offline beyond 4 hours`);
    add('\nRecovery options:');
    add(`  • Restore from last verified clean backup (integrity check required before restoration)`);
    add(`  • Engage specialist ransomware IR firm if backups are unavailable or corrupted`);
    add(`  • Do not pay ransom without legal counsel and law enforcement consultation`);
  } else if (type === 'exfiltration') {
    add('\nGDPR breach assessment:');
    add(`  • ${inc.dataTransferredGB?.toLocaleString() || '2,150'} GB transferred — high likelihood of personal data exposure`);
    add(`  • Data categories: ${inc.dataCategories?.join(', ') || 'Customer PII, Payment Records'}`);
    add(`  • UK GDPR Article 33 notification required within 72 hours of detection`);
    add(`  • Destination IP flagged on threat intelligence feeds — nation-state nexus possible`);
    add('\nCustomer impact:');
    add(`  • Customer PII at risk — names, addresses, payment card data potentially included`);
    add(`  • Customer notification under GDPR Article 34 is being assessed`);
    add(`  • PCI DSS incident assessment required if payment card data is confirmed in scope`);
  } else if (type === 'credentialStuffing') {
    add('\nCustomer account exposure:');
    add(`  • ${inc.failedAttempts?.toLocaleString() || 'Unknown'} login attempts — success rate under investigation`);
    add(`  • Successful logins would grant access to order history, saved addresses, payment methods`);
    add(`  • SIEM correlation running to identify any compromised sessions`);
    add('\nPortal integrity:');
    add(`  • Rate limiting and CAPTCHA now active — attack vector contained`);
    add(`  • No confirmed data exposure — monitoring continues across all portal endpoints`);
  } else if (type === 'phishing') {
    add('\nCredential harvesting risk:');
    add(`  • Target ${inc.entity || 'Finance team'} has elevated system access — high-value target`);
    add(`  • If macro had executed: Cobalt Strike beacon would establish persistent C2 access`);
    add(`  • Email quarantined before interaction — credential exposure unlikely`);
    add('\nAffected staff accounts:');
    add(`  • Primary target: ${inc.entity || 'Unknown'}`);
    add(`  • Secondary risk: Others in same department may receive follow-on targeted emails`);
    add(`  • Quarantine confirmed successful — attack contained at delivery stage`);
  } else if (type === 'giftCardFraud') {
    const loss = inc.estimatedLossGBP || 42350;
    const cards = inc.cardsAffected || 847;
    add('\nFinancial loss analysis:');
    add(`  • Total estimated loss : £${loss.toLocaleString()}`);
    add(`  • Cards drained        : ${cards.toLocaleString()}`);
    add(`  • Average per card     : £${(loss / cards).toFixed(2)}`);
    add(`  • Cards now frozen     : ${cards.toLocaleString()} (reissuance required)`);
    add('\nFraud pattern analysis:');
    add(`  • Automated velocity attack — 200+ balance checks/min (normal: <5/min)`);
    add(`  • Card numbers sourced from prior breach or dark web marketplace`);
    add(`  • No in-store POS involvement — pure API-layer redemption`);
    add(`  • Criminal referral to Action Fraud in progress`);
  } else if (type === 'aiVoiceFraud') {
    add('\nSocial engineering assessment:');
    add(`  • No financial loss — staff member raised suspicion before completing transfer`);
    add(`  • Attack sophistication: high — AI voice clone requires audio samples of the target`);
    add(`  • Impersonation target is known and trusted by store staff — high success potential`);
    add('\nStaff awareness:');
    add(`  • Positive outcome — staff followed correct reporting procedure`);
    add(`  • Risk remains: other store staff may not identify AI voice artefacts`);
    add(`  • All-store training update required immediately`);
  } else if (type === 'posManipulation') {
    add('\nFinancial reconciliation:');
    add(`  • Suspected insider theft: £${inc.refundTotalGBP?.toLocaleString() || '2,870'} via ${inc.voidCount || 38} void/refund transactions`);
    add(`  • Refund-without-sale ratio: 92% (industry alert threshold: 25%)`);
    add(`  • Operator POS access suspended — store operations continue via other terminals`);
    add('\nInternal controls gap:');
    add(`  • High-value voids processed without manager PIN approval`);
    add(`  • Loss prevention review and policy update required`);
  } else if (type === 'supplyChain') {
    add('\nFinancial exposure:');
    add(`  • Bank detail change attempt blocked — no fraudulent payments made`);
    add(`  • If successful: payments rerouted to attacker-controlled account (BEC pattern)`);
    add(`  • All pending payments to ${inc.supplierAccount || 'affected supplier'} held by Accounts Payable`);
    add('\nThird-party risk:');
    add(`  • Supplier portal access model under immediate security review`);
    add(`  • All supplier accounts to require MFA following this incident`);
  } else if (type === 'mfaFatigue') {
    add('\nAuthentication integrity:');
    add(`  • No successful MFA bypass — all 4 accounts remain secure`);
    add(`  • Attacker held valid passwords — prior credential breach confirmed`);
    add(`  • Push MFA is inherently susceptible to fatigue — migration to number-matching required`);
    add('\nFinance team risk:');
    add(`  • Finance accounts have access to payment systems, ERP, and banking portals — high value target`);
    add(`  • Passwords for all 4 targeted accounts must be rotated immediately`);
  } else if (type === 'lateralMovement') {
    add('\nNetwork compromise scope:');
    add(`  • Attacker moved from ${inc.sourceHost || 'warehouse DC'} to ${inc.targetHost || 'management server'}`);
    add(`  • Management server access could expose monitoring tools, credentials, and infrastructure configs`);
    add(`  • NTLM hash reuse — Credential Guard would have prevented this technique`);
    add('\nBlast radius:');
    add(`  • Active Directory integrity at risk — further lateral movement cannot be ruled out`);
    add(`  • All domain admin credentials invalidated as a precaution`);
  } else if (type === 'sqlInjection') {
    add('\nDatabase exposure:');
    add(`  • WAF blocked all 847 payloads — no confirmed data extraction`);
    add(`  • Underlying endpoint vulnerability (CWE-89) remains until code is remediated`);
    add(`  • Customer PII and payment data would be exposed if WAF had not intervened`);
    add('\nCustomer data risk:');
    add(`  • No confirmed breach at this time — code review and pentest required`);
  } else if (type === 'privilegedRole') {
    add('\nPrivilege escalation scope:');
    add(`  • ${inc.accountModified || 'Service account'} held ${inc.roleAdded || 'Global Administrator'} for approximately ${inc.mttd || 'Unknown'} minutes`);
    add(`  • Global Administrator grants full Azure AD tenant control — maximum privilege level`);
    add(`  • Role reverted automatically — no confirmed data access during the privilege window`);
    add('\nPersistence mechanism:');
    add(`  • Classic technique: elevate service account to survive credential resets`);
    add(`  • Source session on compromised host — full attack chain investigation required`);
  }

  // ── §4  RESPONSE ACTIONS ─────────────────────────────────
  add('\n§4  RESPONSE ACTIONS');
  add('\nEvent timeline:');
  (inc.timeline || []).forEach(e => add(`  ${e.time.padEnd(8)} ${e.event}`));
  add('\nAutomated defences activated:');
  (inc.autoDefence || []).forEach(d => add(`  [+] ${d}`));

  if (type === 'ransomware') {
    add('\nManual response steps in progress:');
    add(`  [→] Incident response team engaged — forensic image of ${inc.entity || 'affected host'} being captured`);
    add(`  [→] Backup integrity verification underway — identifying last clean restore point`);
    add(`  [→] NCSC notification being prepared (24-hour deadline: ${fmt(ncsc)})`);
    add(`  [→] ICO notification being prepared (72-hour deadline: ${fmt(ico)})`);
  } else if (type === 'exfiltration') {
    add('\nManual response steps in progress:');
    add(`  [→] Forensic analysis of ${inc.entity || 'affected server'} underway`);
    add(`  [→] Legal team engaged for breach scope and customer notification assessment`);
    add(`  [→] ICO notification being prepared (72-hour deadline: ${fmt(ico)})`);
    add(`  [→] All outbound connections from ${inc.entity || 'affected system'} reviewed for past 7 days`);
  } else if (type === 'phishing') {
    add('\nEmail gateway response:');
    add(`  [→] Sender domain ${inc.sourceEmail?.split('@')[1] || 'attacker domain'} added to global blocklist`);
    add(`  [→] Retrospective search for similar emails across all mailboxes in progress`);
    add(`  [→] Sandbox analysis report shared with threat intelligence team`);
  } else if (type === 'giftCardFraud') {
    add('\nFraud response actions:');
    add(`  [→] ${inc.cardsAffected?.toLocaleString() || '847'} affected cards frozen — reissuance process initiated`);
    add(`  [→] CAPTCHA deployed to balance-check and redemption API endpoints`);
    add(`  [→] Action Fraud referral being prepared`);
  } else if (type === 'supplyChain') {
    add('\nSupplier management response:');
    add(`  [→] Out-of-band verification call to ${inc.supplierAccount || 'affected supplier'} via known contact`);
    add(`  [→] Accounts Payable holds in place — no payments to be released without verification`);
    add(`  [→] Security review of all supplier portal accounts initiated`);
  } else if (type === 'mfaFatigue') {
    add('\nAccount remediation steps:');
    add(`  [→] Passwords reset for all 4 targeted Finance accounts`);
    add(`  [→] Number-matching MFA enabled for all Finance team members`);
    add(`  [→] Company-wide advisory issued — do not approve unexpected MFA push requests`);
  } else if (type === 'aiVoiceFraud') {
    add('\nFraud containment steps:');
    add(`  [→] Fraud alert broadcast to all stores via regional manager communications`);
    add(`  [→] Verbal-authorisation policy suspended — all financial requests require written confirmation`);
    add(`  [→] Call recording and metadata preserved for law enforcement referral`);
  }

  // ── §5  UK REGULATORY COMPLIANCE ─────────────────────────
  add('\n§5  UK REGULATORY COMPLIANCE');

  if (!inc.needsICO && !inc.needsNCSC) {
    if (type === 'credentialStuffing') {
      add('No personal data confirmed as accessed — mandatory notification is not currently required.');
      add('ICO obligation will be triggered if SIEM analysis identifies successful account compromises.');
      add('Continue monitoring for anomalous sessions from the attack window.');
    } else if (type === 'giftCardFraud') {
      add('Gift card fraud does not automatically trigger UK GDPR Article 33 notification.');
      add('If customer PII was used to source card numbers, review ICO obligations with legal counsel.');
      add('A PCI DSS incident assessment should be conducted given payment card system involvement.');
    } else if (type === 'aiVoiceFraud') {
      add('No data breach occurred — no mandatory regulatory notification required at this time.');
      add('If a financial transfer had been completed, FCA reporting obligations may apply.');
      add('Retain call metadata and preserve evidence for potential law enforcement referral.');
    } else if (type === 'posManipulation') {
      add('No mandatory regulatory notification required for internal POS fraud at this stage.');
      add('If employee personal data is processed as part of the investigation, DPA 2018 obligations apply.');
      add('HR and legal must be involved in any disciplinary action to ensure compliance.');
    } else if (type === 'mfaFatigue') {
      add('No successful authentication bypass — no mandatory regulatory notification required.');
      add('If accounts are later confirmed compromised, ICO notification would be required within 72 hours.');
      add('Maintain detailed logs of the attack for potential law enforcement referral.');
    } else if (type === 'sqlInjection') {
      add('No confirmed data extraction — no mandatory regulatory notification required at this time.');
      add('If forensic analysis identifies successful exfiltration, ICO notification is required within 72 hours.');
      add('PCI DSS scope: if payment card data resides in the targeted database, notify your acquiring bank.');
    } else if (type === 'afterHoursAccess') {
      add('No mandatory regulatory notification required based on current assessment.');
      add('If investigation confirms unauthorised data access, reassess ICO and NCSC obligations immediately.');
    } else if (type === 'lateralMovement') {
      add('NCSC notification may be required depending on confirmed scope — assessment in progress.');
      add('If management server data was accessed, ICO notification may also apply.');
    } else if (type === 'privilegedRole') {
      add('No confirmed data access during the privilege window — notification assessment in progress.');
      add('If investigation reveals data access, both ICO (72h) and NCSC (24h) obligations may apply.');
    } else {
      add('No mandatory regulatory notification required based on current assessment.');
    }
  }

  if (inc.needsICO) {
    add('\nICO NOTIFICATION — UK GDPR Article 33 (72-hour obligation)');
    add(`Deadline : ${fmt(ico)}`);
    add(`Portal   : https://ico.org.uk/for-organisations/report-a-breach/`);
    add('');
    if (type === 'ransomware') {
      add(`DRAFT: We are reporting a ransomware incident (${inc.ransomwareFamily || 'family under investigation'}) affecting ${inc.entity || 'our systems'}, detected on ${fmt(det)}.`);
      add(`${inc.filesModified?.toLocaleString() || 'An unknown number of'} files were encrypted, including ${inc.dataCategories?.join(', ') || 'employee and operational data'}. The affected system has been isolated and backup restoration is underway.`);
      add(`Risk to data subjects: potential loss of availability and confidentiality of personal data. We are assessing whether personal data was exfiltrated prior to encryption.`);
    } else if (type === 'exfiltration') {
      add(`DRAFT: We are reporting a personal data breach involving the exfiltration of approximately ${inc.dataTransferredGB ? `${inc.dataTransferredGB.toLocaleString()} GB` : '2.1 TB'} of data to infrastructure in ${inc.geoLocation || 'an overseas jurisdiction'}, detected on ${fmt(det)}.`);
      add(`Data categories involved: ${inc.dataCategories?.join(', ') || 'Customer PII and payment records'}. The exfiltration connection has been terminated and the destination IP blocked.`);
      add(`Risk to data subjects: HIGH — customer personal and financial data is likely compromised. Customer notification under GDPR Article 34 is being assessed.`);
    } else {
      add(`DRAFT: We are notifying the ICO of a personal data breach affecting ${inc.dataCategories?.join(', ') || 'personal data'} in connection with ${inc.id}.`);
      add(`The breach was detected on ${fmt(det)}. Containment measures are in place. We will provide a full report within 72 hours.`);
    }
  }

  if (inc.needsNCSC) {
    add('\nNCSC REPORT — Cyber Security and Resilience Bill 2025 (24-hour obligation)');
    add(`Deadline : ${fmt(ncsc)}`);
    add(`Portal   : https://report.ncsc.gov.uk/`);
    add('');
    if (type === 'ransomware') {
      add(`DRAFT: Reporting ransomware incident ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Family: ${inc.ransomwareFamily || 'Under investigation'}.`);
      add(`Files encrypted: ${inc.filesModified?.toLocaleString() || 'Unknown'}. Affected system: ${inc.entity || 'Unknown'}. System isolated. Restoration in progress. Matching known ${inc.ransomwareFamily || 'ransomware'} supply-chain TTPs.`);
    } else if (type === 'phishing') {
      add(`DRAFT: Reporting targeted spearphishing incident ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Target: ${inc.entity || 'Unknown'}. Phishing score: ${inc.phishingScore || 'Unknown'}/100.`);
      add(`Email quarantined before interaction — no confirmed compromise. Notification raised as precaution given targeting of senior personnel.`);
    } else if (type === 'lateralMovement') {
      add(`DRAFT: Reporting lateral movement incident ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Movement: ${inc.sourceHost || 'unknown'} → ${inc.targetHost || 'unknown'}.`);
      add(`Impact: ${inc.impactLevel || 'Under assessment'}. Network segment isolated. Credential reset completed across affected domain.`);
    } else if (type === 'supplyChain') {
      add(`DRAFT: Reporting supply chain / third-party account compromise ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Compromised supplier account: ${inc.supplierAccount || 'Unknown'}.`);
      add(`Account suspended. Financial controls activated. No confirmed data loss or fraudulent payment.`);
    } else if (type === 'privilegedRole') {
      add(`DRAFT: Reporting privileged role addition / persistence mechanism ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Account: ${inc.accountModified || 'Unknown'}, role granted: ${inc.roleAdded || 'Unknown'}.`);
      add(`Role automatically reverted. Account disabled. Full attack chain investigation underway.`);
    } else {
      add(`DRAFT: Reporting incident ${inc.id} — "${inc.title}", detected ${fmt(det)}.`);
      add(`MITRE technique: ${inc.technique} (${inc.tactic}). Impact: ${inc.impactLevel || 'Under assessment'}.`);
    }
  }

  // ── §6  RECOMMENDATIONS ──────────────────────────────────
  add('\n§6  RECOMMENDATIONS');
  (inc.recommendations || []).forEach((r, i) => add(`  ${i + 1}. ${r}`));

  if (type === 'ransomware') {
    add('\nAdditional mitigations:');
    add(`  • Deploy EDR with ransomware behavioural detection on all servers`);
    add(`  • Implement network micro-segmentation to limit encryption blast radius`);
    add(`  • Test backup restoration quarterly — maintain verified offline copies`);
    add(`  • Enrol in NCSC Early Warning Service for ransomware gang intelligence feeds`);
  } else if (type === 'exfiltration') {
    add('\nData governance:');
    add(`  • Classify and label all data assets — apply DLP policies based on classification`);
    add(`  • Implement UEBA on ERP access to detect anomalous query and download patterns`);
    add(`  • Restrict outbound firewall rules — block uncommon destination ports by default`);
  } else if (type === 'credentialStuffing') {
    add('\nLong-term customer account security:');
    add(`  • Integrate with NCSC Credential Exposure Notification Service`);
    add(`  • Implement adaptive authentication — flag and step-up logins from anomalous geographies`);
  } else if (type === 'phishing') {
    add('\nEmail security hardening:');
    add(`  • Enable Microsoft Defender for Office 365 Safe Attachments on all mailboxes`);
    add(`  • Enforce DMARC (p=reject) on all outbound-sending domains`);
    add(`  • Conduct quarterly phishing simulation exercises — track click rates by department`);
  } else if (type === 'giftCardFraud') {
    add('\nPlatform hardening:');
    add(`  • Implement per-card velocity limits (max 1 balance-check per 60 seconds per card)`);
    add(`  • Add device fingerprinting to gift card API — flag and challenge new devices`);
    add(`  • Require account login for balance checks on cards above a defined face value`);
  } else if (type === 'aiVoiceFraud') {
    add('\nOrganisational controls:');
    add(`  • Establish a rotating daily codeword protocol for all financial authorisations by phone`);
    add(`  • Never authorise cash transfers via phone alone — require two-person written confirmation`);
    add(`  • Report to Action Fraud (0300 123 2040) and preserve call recording evidence`);
  } else if (type === 'posManipulation') {
    add('\nProcess controls:');
    add(`  • Implement real-time anomaly alerting for void/refund velocity per operator`);
    add(`  • Require biometric or manager PIN for all refunds above a configurable threshold`);
    add(`  • Conduct unannounced till audits at high-risk stores on a monthly schedule`);
  } else if (type === 'supplyChain') {
    add('\nThird-party security:');
    add(`  • Apply NCSC Supplier Security Assessment framework to all portal-connected suppliers`);
    add(`  • Mandate MFA for all supplier portal access — 30-day implementation target`);
    add(`  • Require out-of-band verification for any bank detail change requests`);
  } else if (type === 'mfaFatigue') {
    add('\nAuthentication hardening:');
    add(`  • Migrate all users from push MFA to FIDO2 hardware keys or passkeys within 90 days`);
    add(`  • Enable Conditional Access — block MFA attempts originating from anonymous proxy IPs`);
    add(`  • Issue company-wide guidance: never approve unexpected or unsolicited MFA push requests`);
  } else if (type === 'lateralMovement') {
    add('\nNetwork defence:');
    add(`  • Deploy Microsoft Credential Guard on all domain-joined endpoints within 30 days`);
    add(`  • Implement tiered admin model — separate accounts for workstation, server, and domain tiers`);
    add(`  • Enable NTLM audit logging to detect future hash-relay and pass-the-hash attempts`);
  } else if (type === 'sqlInjection') {
    add('\nDevelopment security:');
    add(`  • Mandate SAST scanning in CI/CD pipeline — block deployments with CWE-89 findings`);
    add(`  • Engage a CREST-accredited firm for a full API penetration test`);
    add(`  • Implement database activity monitoring — alert on anomalous SELECT/UNION query patterns`);
  } else if (type === 'privilegedRole') {
    add('\nIdentity governance:');
    add(`  • Enable Azure PIM just-in-time access for all admin roles — no standing privileges`);
    add(`  • Configure continuous access evaluation — revoke sessions on anomalous risk signals`);
    add(`  • Conduct a full privileged account audit — remove all standing admin rights`);
  }

  add('\n' + '─'.repeat(60));
  add('Report generated by RetailShield · ShieldTech Ltd · Tanvir Farhad');
  add('DOI: https://doi.org/10.5281/zenodo.20608262');
  return lines.join('\n');
}

export default function ThreatDetection({ onBack, nav, incidents, setIncidents }) {
  const [view, setView]           = useState('dashboard');
  const [simulating, setSimulating] = useState(false);
  const [selected, setSelected]   = useState(null);
  const [reportInc, setReportInc] = useState(null);
  const [reportText, setReportText] = useState('');
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied]       = useState(false);
  const [clock, setClock]         = useState(new Date());
  const [search, setSearch]       = useState('');
  const [sevFilter, setSevFilter] = useState('All');
  const { isMobile } = useBreakpoint();

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const lastScenario = useRef(-1);

  const runSim = useCallback(() => {
    if (simulating) return;
    setSimulating(true);
    let idx = Math.floor(Math.random() * ATTACK_SIM_EVENTS.length);
    if (ATTACK_SIM_EVENTS.length > 1 && idx === lastScenario.current) {
      idx = (idx + 1) % ATTACK_SIM_EVENTS.length;
    }
    lastScenario.current = idx;
    const scenario = ATTACK_SIM_EVENTS[idx];
    setTimeout(() => {
      setIncidents(prev => {
        const maxNum = prev.reduce((m, i) => Math.max(m, parseInt(i.id.slice(4), 10) || 0), 2849);
        return [{ ...scenario, id: `INC-${maxNum + 1}`, detectedAt: new Date().toISOString() }, ...prev];
      });
      setSimulating(false);
    }, 800);
  }, [simulating, setIncidents]);

  const handleGenerate = () => {
    if (!reportInc) return;
    setGenerating(true); setReportText('');
    setTimeout(() => { setReportText(generateReport(reportInc, clock)); setGenerating(false); }, 1100);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };

  const handleDownload = () => {
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([reportText], { type:'text/plain' })),
      download: `RetailShield-${reportInc?.id || 'report'}-${Date.now()}.txt`,
    });
    a.click();
  };

  const active   = incidents.filter(i => i.status === 'Active').length;
  const critical = incidents.filter(i => i.severity === 'Critical').length;

  const filtered = incidents.filter(i => {
    const q = search.toLowerCase();
    return (!search || i.title.toLowerCase().includes(q) || i.id.toLowerCase().includes(q))
      && (sevFilter === 'All' || i.severity === sevFilter);
  });

  const TABS = [
    { id:'dashboard', label:'Dashboard' },
    { id:'incidents', label:`Incidents (${incidents.length})` },
    { id:'report',    label:'AI Report' },
  ];

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex', flexDirection:'column' }}>
      <TopBar moduleName="Threat Detection" onBack={onBack} nav={nav} currentRoute="threat" />

      {/* Sub-nav */}
      <div style={{ background:'var(--surface)', borderBottom:'1px solid var(--border)', display:'flex', alignItems:'stretch', overflowX:'auto' }}>
        <div style={{ display:'flex', flexShrink:0 }}>
          {TABS.map(tab => (
            <button key={tab.id} onClick={() => { setView(tab.id); setSelected(null); }}
              style={{
                padding:`10px ${isMobile ? '12px' : '16px'}`, background:'none', border:'none',
                borderBottom: view === tab.id ? '2px solid var(--primary)' : '2px solid transparent',
                color: view === tab.id ? 'var(--text)' : 'var(--text-muted)',
                fontSize: isMobile ? '12px' : '13px', fontWeight: view === tab.id ? 600 : 400,
                cursor:'pointer', transition:'color var(--t)', whiteSpace:'nowrap',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:'8px', padding:'6px 12px', flexShrink:0 }}>
          {!isMobile && (
            <div style={{ display:'flex', alignItems:'center', gap:'5px' }}>
              <span className="live-dot" />
              <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{clock.toLocaleTimeString('en-GB')}</span>
            </div>
          )}
          <button onClick={runSim} disabled={simulating}
            style={{
              display:'flex', alignItems:'center', gap:'5px',
              padding:'6px 12px', borderRadius:'var(--r-btn)',
              background: simulating ? 'rgba(220,38,38,0.5)' : 'var(--accent)',
              border:'none', color:'white', fontSize:'12px', fontWeight:600,
              cursor: simulating ? 'not-allowed' : 'pointer', transition:'background var(--t)',
              minHeight:'32px', whiteSpace:'nowrap',
            }}
          >
            <Zap size={13} />
            {isMobile ? (simulating ? '…' : 'Attack') : (simulating ? 'Simulating…' : 'Simulate Attack')}
          </button>
        </div>
      </div>

      {/* Content area */}
      <div className="rs-page" style={{ flex:1, overflowY:'auto' }}>
        <div className="rs-page-inner" style={{ margin:'0 auto', display:'flex', flexDirection:'column', gap:'16px' }}>

          {/* ── DASHBOARD ── */}
          {view === 'dashboard' && (
            <div className="anim-fade" style={{ display:'flex', flexDirection:'column', gap:'16px' }}>
              <div className="rs-stats">
                <StatCard label="Active Incidents" value={active}    sub="requiring attention"  accent={active > 0 ? 'var(--accent)' : undefined}    icon={AlertTriangle} />
                <StatCard label="Critical Threats"  value={critical}  sub="this session"         accent={critical > 0 ? '#F97316' : undefined}          icon={Shield} />
                <StatCard label="Avg MTTD" value="22.5 min" sub="mean time to detect" icon={Clock}
                  breakdown={[
                    { label:'Phishing Detection',   value:'13 min' },
                    { label:'Credential Stuffing',  value:'21 min' },
                    { label:'Ransomware Indicator', value:'26 min' },
                    { label:'Data Exfiltration',    value:'30 min' },
                  ]}
                  breakdownSource="Based on live Sentinel evaluation — 8 June 2026"
                />
                <StatCard label="Rules Active"      value="19"        sub="MITRE ATT&CK mapped"  icon={Activity} />
              </div>

              <div className="rs-two-col">
                {/* Live feed */}
                <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden', display:'flex', flexDirection:'column' }}>
                  <div style={{ padding:'14px 16px', borderBottom:'1px solid var(--border)', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:'7px' }}>
                      <span className="live-dot" />
                      <span style={{ fontSize:'13px', fontWeight:600, color:'var(--text)' }}>Live Threat Feed</span>
                    </div>
                    <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{incidents.length} events</span>
                  </div>
                  <div style={{ maxHeight:'320px', overflowY:'auto' }}>
                    {incidents.length === 0
                      ? <EmptyState msg="No incidents detected" />
                      : incidents.slice(0, 10).map(inc => (
                        <button key={inc.id} onClick={() => { setSelected(inc); setView('incidents'); }}
                          style={{ width:'100%', padding:'10px 16px', background:'none', border:'none', borderBottom:'1px solid var(--border)', cursor:'pointer', textAlign:'left', transition:'background var(--t)' }}
                          onMouseEnter={e => e.currentTarget.style.background='var(--card-hover)'}
                          onMouseLeave={e => e.currentTarget.style.background='none'}
                        >
                          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:'8px', marginBottom:'4px' }}>
                            <span style={{ fontSize:'13px', fontWeight:500, color:'var(--text)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{inc.title}</span>
                            <SeverityBadge severity={inc.severity} />
                          </div>
                          <div style={{ display:'flex', gap:'10px' }}>
                            <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{inc.id}</span>
                            <StatusBadge status={inc.status} />
                          </div>
                        </button>
                      ))}
                    {incidents.length > 10 && (
                      <button onClick={() => setView('incidents')} style={{ width:'100%', padding:'10px', background:'none', border:'none', borderTop:'1px solid var(--border)', color:'var(--primary)', fontSize:'12px', cursor:'pointer', fontWeight:500 }}>
                        View all {incidents.length} incidents
                      </button>
                    )}
                  </div>
                </div>

                {/* MITRE coverage */}
                <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
                  <div style={{ padding:'14px 16px', borderBottom:'1px solid var(--border)' }}>
                    <span style={{ fontSize:'13px', fontWeight:600, color:'var(--text)' }}>MITRE ATT&CK Coverage</span>
                  </div>
                  <div className="rs-mitre">
                    {MITRE_COVERAGE.map(m => {
                      const pct = m.covered / m.total;
                      const col = pct >= 0.6 ? 'var(--success)' : pct >= 0.3 ? 'var(--warning)' : 'var(--accent)';
                      return (
                        <div key={m.tactic} style={{ background:'var(--surface)', borderRadius:'6px', padding:'9px 11px' }}>
                          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:'5px', gap:'4px' }}>
                            <span style={{ fontSize:'11px', color:'var(--text-muted)', fontWeight:500, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{m.tactic}</span>
                            <span style={{ fontSize:'11px', color:col, fontFamily:'var(--font-mono)', fontWeight:600, flexShrink:0 }}>{m.covered}/{m.total}</span>
                          </div>
                          <div style={{ height:'3px', background:'var(--border)', borderRadius:'2px', overflow:'hidden' }}>
                            <div style={{ height:'100%', width:`${pct*100}%`, background:col, borderRadius:'2px' }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Timeline chart */}
              <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', padding:'16px' }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:'12px' }}>
                  <span style={{ fontSize:'13px', fontWeight:600, color:'var(--text)' }}>Alert Timeline — Today</span>
                  <span style={{ fontSize:'11px', color:'var(--text-dim)' }}>30-min intervals</span>
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={TIMELINE_BASE} margin={{ top:4, right:4, left:-24, bottom:0 }}>
                    <XAxis dataKey="t" tick={{ fontSize:10, fill:'#5A6478' }} axisLine={false} tickLine={false} interval={isMobile ? 2 : 1} />
                    <YAxis tick={{ fontSize:10, fill:'#5A6478' }} axisLine={false} tickLine={false} width={32} />
                    <Tooltip contentStyle={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'6px', fontSize:'12px' }} labelStyle={{ color:'var(--text-muted)' }} itemStyle={{ color:'var(--primary)' }} />
                    <Bar dataKey="v" radius={[3,3,0,0]}>
                      {TIMELINE_BASE.map((d,i) => <Cell key={i} fill={d.v>=6?'#DC2626':d.v>=4?'#D97706':'#2563EB'} opacity={0.8} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* ── INCIDENTS ── */}
          {view === 'incidents' && (
            <div className="anim-fade" style={{ display:'flex', flexDirection: isMobile || !selected ? 'column' : 'row', gap:'16px' }}>

              {/* Table panel */}
              <div style={{ flex:1, background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden', minWidth:0 }}>
                {/* Filters */}
                <div style={{ padding:'12px 16px', borderBottom:'1px solid var(--border)', display:'flex', gap:'8px', flexWrap:'wrap' }}>
                  <div style={{ position:'relative', flex:1, minWidth:'140px' }}>
                    <Search size={13} color="var(--text-dim)" style={{ position:'absolute', left:'9px', top:'50%', transform:'translateY(-50%)' }} />
                    <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search…"
                      style={{ width:'100%', padding:'7px 9px 7px 28px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--r-btn)', color:'var(--text)', fontSize:'14px', outline:'none' }} />
                  </div>
                  <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
                    {['All','Critical','High','Medium','Low'].map(s => (
                      <button key={s} onClick={() => setSevFilter(s)} style={{ padding:'5px 10px', borderRadius:'var(--r-btn)', border:'1px solid var(--border)', background: sevFilter===s?'var(--primary)':'var(--surface)', color: sevFilter===s?'white':'var(--text-muted)', fontSize:'11px', fontWeight:500, cursor:'pointer', transition:'all var(--t)', minHeight:'32px' }}>{s}</button>
                    ))}
                  </div>
                </div>

                {/* Table — scrollable on mobile */}
                <div className="rs-table-wrap">
                  <div data-table style={{ minWidth:'560px' }}>
                    <div style={{ display:'grid', gridTemplateColumns:'80px 1fr 90px 110px 60px', padding:'9px 16px', background:'var(--surface)', borderBottom:'1px solid var(--border)' }}>
                      {['ID','Title','Severity','Status','MTTD'].map(h => <span key={h} style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em' }}>{h}</span>)}
                    </div>
                    {filtered.length === 0
                      ? <EmptyState msg="No incidents match current filters" />
                      : filtered.map(inc => (
                        <button key={inc.id} onClick={() => setSelected(selected?.id===inc.id ? null : inc)}
                          style={{
                            width:'100%', display:'grid', gridTemplateColumns:'80px 1fr 90px 110px 60px',
                            padding:'11px 16px', background: selected?.id===inc.id?'var(--card-hover)':'none',
                            border:'none', borderBottom:'1px solid var(--border)', cursor:'pointer',
                            textAlign:'left', transition:'background var(--t)', alignItems:'center',
                          }}
                          onMouseEnter={e => { if(selected?.id!==inc.id) e.currentTarget.style.background='rgba(255,255,255,0.02)'; }}
                          onMouseLeave={e => { if(selected?.id!==inc.id) e.currentTarget.style.background='none'; }}
                        >
                          <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{inc.id}</span>
                          <span style={{ fontSize:'13px', color:'var(--text)', fontWeight:500, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', paddingRight:'12px' }}>{inc.title}</span>
                          <SeverityBadge severity={inc.severity} />
                          <StatusBadge   status={inc.status} />
                          <span style={{ fontSize:'12px', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{inc.mttd}m</span>
                        </button>
                      ))}
                  </div>
                </div>
              </div>

              {/* Detail panel */}
              {selected && (
                <div style={{ width: isMobile ? '100%' : '380px', background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden', animation:'fadeIn 200ms ease', display:'flex', flexDirection:'column', flexShrink:0 }}>
                  <div style={{ padding:'14px 16px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:'8px' }}>
                    <div style={{ minWidth:0 }}>
                      <div style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)', marginBottom:'3px' }}>{selected.id}</div>
                      <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text)', lineHeight:1.3 }}>{selected.title}</div>
                    </div>
                    <button onClick={() => setSelected(null)} aria-label="Close" style={{ background:'none', border:'none', color:'var(--text-dim)', cursor:'pointer', padding:'4px', flexShrink:0, minWidth:'32px', minHeight:'32px', display:'flex', alignItems:'center', justifyContent:'center' }}>
                      <X size={15} />
                    </button>
                  </div>
                  <div style={{ flex:1, overflowY:'auto', padding:'14px 16px', display:'flex', flexDirection:'column', gap:'14px' }}>
                    <div style={{ display:'flex', gap:'6px', flexWrap:'wrap' }}>
                      <SeverityBadge severity={selected.severity} size="lg" />
                      <StatusBadge status={selected.status} />
                      <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)', alignSelf:'center' }}>{selected.technique}</span>
                    </div>
                    <p style={{ fontSize:'13px', color:'var(--text-muted)', lineHeight:1.6 }}>{selected.description}</p>

                    <Sect title="Timeline">
                      {(selected.timeline||[]).map((e,i) => (
                        <div key={i} style={{ display:'flex', gap:'10px', paddingBottom:'6px' }}>
                          <span style={{ fontSize:'11px', color:'var(--primary)', fontFamily:'var(--font-mono)', flexShrink:0 }}>{e.time}</span>
                          <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{e.event}</span>
                        </div>
                      ))}
                    </Sect>

                    <Sect title="Automated Defence">
                      {(selected.autoDefence||[]).map((d,i) => (
                        <div key={i} style={{ display:'flex', gap:'7px', marginBottom:'4px' }}>
                          <Check size={12} color="var(--success)" style={{ flexShrink:0, marginTop:'2px' }} />
                          <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{d}</span>
                        </div>
                      ))}
                    </Sect>

                    <Sect title="Recommendations">
                      {(selected.recommendations||[]).map((r,i) => (
                        <div key={i} style={{ display:'flex', gap:'7px', marginBottom:'4px' }}>
                          <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)', flexShrink:0 }}>{i+1}.</span>
                          <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{r}</span>
                        </div>
                      ))}
                    </Sect>

                    {(selected.needsICO || selected.needsNCSC) && (
                      <div style={{ background:'var(--accent-dim)', border:'1px solid rgba(220,38,38,0.25)', borderRadius:'6px', padding:'10px 12px' }}>
                        <div style={{ fontSize:'12px', fontWeight:600, color:'#F87171', marginBottom:'6px' }}>Regulatory Notification Required</div>
                        <div style={{ display:'flex', gap:'6px', flexWrap:'wrap' }}>
                          {selected.needsICO  && <span style={{ fontSize:'11px', background:'rgba(220,38,38,0.1)', color:'#F87171', padding:'2px 8px', borderRadius:'4px', border:'1px solid rgba(220,38,38,0.2)' }}>ICO — 72h</span>}
                          {selected.needsNCSC && <span style={{ fontSize:'11px', background:'rgba(220,38,38,0.1)', color:'#F87171', padding:'2px 8px', borderRadius:'4px', border:'1px solid rgba(220,38,38,0.2)' }}>NCSC — 24h</span>}
                        </div>
                      </div>
                    )}

                    <button onClick={() => { setReportInc(selected); setView('report'); setReportText(''); }}
                      style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:'6px', padding:'10px', borderRadius:'var(--r-btn)', background:'var(--primary)', border:'none', color:'white', fontSize:'13px', fontWeight:600, cursor:'pointer', transition:'background var(--t)', minHeight:'44px' }}
                      onMouseEnter={e => e.currentTarget.style.background='var(--primary-dk)'}
                      onMouseLeave={e => e.currentTarget.style.background='var(--primary)'}
                    >
                      <FileText size={14} /> Generate AI Report
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── AI REPORT ── */}
          {view === 'report' && (
            <div className="anim-fade" style={{ maxWidth:'860px' }}>
              <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
                <div style={{ padding:'18px 20px', borderBottom:'1px solid var(--border)' }}>
                  <div style={{ fontSize:'14px', fontWeight:600, color:'var(--text)', marginBottom:'3px' }}>AI Incident Report Generator</div>
                  <div style={{ fontSize:'12px', color:'var(--text-dim)' }}>6-section structured report with ICO/NCSC draft notifications where required.</div>
                </div>
                <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)', display:'flex', gap:'10px', flexWrap:'wrap', alignItems:'flex-end' }}>
                  <div style={{ flex:1, minWidth:'180px' }}>
                    <label style={{ fontSize:'12px', fontWeight:500, color:'var(--text-muted)', display:'block', marginBottom:'5px' }}>Select incident</label>
                    <select value={reportInc?.id||''} onChange={e => { setReportInc(incidents.find(i=>i.id===e.target.value)||null); setReportText(''); }}
                      style={{ width:'100%', padding:'8px 10px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--r-btn)', color:'var(--text)', fontSize:'14px', cursor:'pointer', outline:'none' }}>
                      <option value="">— choose an incident —</option>
                      {incidents.map(i => <option key={i.id} value={i.id}>{i.id} — {i.title}</option>)}
                    </select>
                  </div>
                  <button onClick={handleGenerate} disabled={!reportInc||generating}
                    style={{
                      display:'flex', alignItems:'center', gap:'6px', padding:'9px 16px', borderRadius:'var(--r-btn)',
                      background: !reportInc||generating?'rgba(37,99,235,0.5)':'var(--primary)',
                      border:'none', color:'white', fontSize:'13px', fontWeight:600,
                      cursor: !reportInc||generating?'not-allowed':'pointer', transition:'background var(--t)',
                      minHeight:'40px', whiteSpace:'nowrap',
                    }}
                    onMouseEnter={e => { if(reportInc&&!generating) e.currentTarget.style.background='var(--primary-dk)'; }}
                    onMouseLeave={e => { if(reportInc&&!generating) e.currentTarget.style.background='var(--primary)'; }}
                  >
                    {generating?<><Spinner/>Generating…</>:<><RefreshCw size={13}/>Generate Report</>}
                  </button>
                </div>
                {reportText && (
                  <>
                    <div style={{ padding:'6px 20px', background:'var(--surface)', borderBottom:'1px solid var(--border)', display:'flex', gap:'8px', justifyContent:'flex-end' }}>
                      <SmallBtn onClick={handleCopy}>{copied?<><Check size={12} color="var(--success)"/>Copied</>:<><Copy size={12}/>Copy</>}</SmallBtn>
                      <SmallBtn onClick={handleDownload}><Download size={12}/>Download</SmallBtn>
                    </div>
                    <pre style={{ padding:'20px', fontSize:'12px', lineHeight:1.7, color:'var(--text-muted)', fontFamily:'var(--font-mono)', whiteSpace:'pre-wrap', wordBreak:'break-word', maxHeight:'560px', overflowY:'auto', margin:0, background:'var(--surface)', animation:'fadeIn 300ms ease' }}>
                      {reportText}
                    </pre>
                  </>
                )}
                {!reportText&&!generating&&<EmptyState msg="Select an incident and click Generate Report" />}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

function Sect({ title, children }) {
  return (
    <div>
      <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'7px' }}>{title}</div>
      {children}
    </div>
  );
}
function EmptyState({ msg }) {
  return <div style={{ padding:'40px', textAlign:'center', color:'var(--text-dim)', fontSize:'13px' }}>{msg}</div>;
}
function Spinner() {
  return <span style={{ width:'12px', height:'12px', border:'2px solid rgba(255,255,255,0.3)', borderTopColor:'white', borderRadius:'50%', animation:'spin 0.7s linear infinite', display:'inline-block', marginRight:'6px' }} />;
}
function SmallBtn({ onClick, children }) {
  return (
    <button onClick={onClick} style={{ display:'flex', alignItems:'center', gap:'4px', padding:'5px 10px', background:'none', border:'1px solid var(--border)', borderRadius:'6px', color:'var(--text-muted)', fontSize:'12px', cursor:'pointer', transition:'all var(--t)', minHeight:'32px' }}
      onMouseEnter={e => e.currentTarget.style.color='var(--text)'}
      onMouseLeave={e => e.currentTarget.style.color='var(--text-muted)'}
    >{children}</button>
  );
}
