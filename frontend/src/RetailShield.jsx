import { useState, useEffect } from 'react'

// ── Design tokens ─────────────────────────────────────────────────────────────
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

// ── Threat data ───────────────────────────────────────────────────────────────
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

// ── SVG Security Posture Gauge ────────────────────────────────────────────────
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

// ── Attack timeline bar chart ─────────────────────────────────────────────────
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

// ── MITRE coverage bar ────────────────────────────────────────────────────────
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

// ── Incident playbook modal ───────────────────────────────────────────────────
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
        {/* Title bar */}
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

        {/* Description */}
        <div style={{ background: C.surface, borderRadius: 8, padding: '14px 16px', marginBottom: 22, borderLeft: `3px solid ${C.red}` }}>
          <p style={{ color: C.muted, fontSize: 13, lineHeight: 1.7, margin: 0 }}>{threat.desc}</p>
        </div>

        {/* Trigger */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 22 }}>
          <span style={{ fontSize: 12, color: C.muted }}>Playbook trigger:</span>
          <code style={{
            background: '#1a0505', color: C.red, padding: '4px 12px',
            borderRadius: 5, fontSize: 12, fontFamily: 'monospace',
            border: `1px solid ${C.redDim}`,
          }}>{threat.playbook.trigger}</code>
        </div>

        {/* AUTO steps */}
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

        {/* MANUAL steps */}
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

// ── Main dashboard ────────────────────────────────────────────────────────────
export default function RetailShield() {
  const [threats, setThreats]   = useState(BASE_THREATS)
  const [filter, setFilter]     = useState('all')
  const [selected, setSelected] = useState(null)
  const [banner, setBanner]     = useState(null)
  const [score, setScore]       = useState(73)
  const [tick, setTick]         = useState(0)
  const [clock, setClock]       = useState(new Date())

  // Live clock
  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  // Live feed — inject new threat every 6 seconds
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

  const counts = {
    total:    threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    active:   threats.filter(t => t.status === 'active').length,
    blocked:  threats.filter(t => t.status === 'blocked').length,
  }

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

  const s = { // shared styles
    card: { background: C.card, border: `1px solid ${C.border}`, borderRadius: 10 },
  }

  return (
    <div style={{ background: C.bg, minHeight: '100vh', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', color: C.text }}>

      {/* ── Live alert banner ── */}
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
          <span style={{ fontWeight: 700, fontSize: 13, color: C.red, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            New Threat Detected
          </span>
          <span style={{ fontSize: 13, color: C.text }}>— {banner.name}</span>
          <span style={{ marginLeft: 'auto', background: 'rgba(0,0,0,0.4)', padding: '2px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace', color: C.red }}>
            {banner.mitre}
          </span>
          <span style={{ fontSize: 10, color: C.muted, background: `${SEV[banner.severity]}20`, padding: '2px 8px', borderRadius: 3, color: SEV[banner.severity], border: `1px solid ${SEV[banner.severity]}40` }}>
            {banner.severity.toUpperCase()}
          </span>
        </div>
      )}

      {/* ── Header ── */}
      <header style={{
        background: C.surface, borderBottom: `1px solid ${C.border}`,
        padding: '0 24px', height: 56, display: 'flex', alignItems: 'center',
        position: 'sticky', top: banner ? 42 : 0, zIndex: 200, gap: 0,
      }}>
        {/* Logo */}
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

        {/* Live indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginRight: 'auto' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: C.green, display: 'inline-block', boxShadow: `0 0 8px ${C.green}`, animation: 'pulse 2s infinite' }} />
          <span style={{ fontSize: 11, color: C.green, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Monitoring</span>
        </div>

        {/* Right side */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <span style={{ fontSize: 11, color: C.dim }}>Microsoft Sentinel · Azure · UK Retail SOC</span>
          <span style={{ fontSize: 12, fontFamily: 'monospace', color: C.muted }}>
            {clock.toLocaleTimeString('en-GB')}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <span style={{ background: `${C.red}20`, color: C.red, padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 700, border: `1px solid ${C.red}50` }}>
              {counts.critical} CRITICAL
            </span>
            <span style={{ background: `${C.orange}20`, color: C.orange, padding: '4px 12px', borderRadius: 5, fontSize: 11, fontWeight: 700, border: `1px solid ${C.orange}50` }}>
              {counts.active} ACTIVE
            </span>
          </div>
        </div>
      </header>

      {/* ── Main content ── */}
      <main style={{ padding: '20px 24px', maxWidth: 1440, margin: '0 auto' }}>

        {/* KPI row */}
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

        {/* Filter bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 18 }}>
          {['all', 'critical', 'active', 'blocked'].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: '7px 18px', borderRadius: 7, cursor: 'pointer', fontSize: 12,
              fontWeight: filter === f ? 700 : 400, textTransform: 'uppercase',
              letterSpacing: '0.5px', transition: 'all 0.2s',
              border: `1px solid ${filter === f ? C.red : C.border}`,
              background: filter === f ? `${C.red}15` : 'transparent',
              color: filter === f ? C.red : C.muted,
            }}>
              {f === 'all' ? `All (${counts.total})` :
               f === 'critical' ? `Critical (${counts.critical})` :
               f === 'active' ? `Active (${counts.active})` :
               `Blocked (${counts.blocked})`}
            </button>
          ))}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: C.red, display: 'inline-block', animation: 'pulse 1.5s infinite' }} />
            <span style={{ fontSize: 11, color: C.dim }}>{filtered.length} alerts · refresh every 6s</span>
          </div>
        </div>

        {/* Two-column layout: feed + sidebar */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 18, marginBottom: 18 }}>

          {/* Threat feed */}
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
                <div
                  key={threat.id}
                  onClick={() => setSelected(threat)}
                  style={{
                    padding: '13px 20px',
                    borderBottom: `1px solid ${C.border}`,
                    borderLeft: `3px solid ${SEV[threat.severity]}`,
                    cursor: 'pointer',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = C.cardHover}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 5 }}>
                    <span style={{ fontWeight: 600, fontSize: 13 }}>{threat.name}</span>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0, marginLeft: 16 }}>
                      <span style={{ fontSize: 10, color: SEV[threat.severity], background: `${SEV[threat.severity]}18`, padding: '2px 7px', borderRadius: 3, fontWeight: 700 }}>
                        {threat.severity.toUpperCase()}
                      </span>
                      <span style={{ fontSize: 10, color: STA[threat.status], padding: '2px 7px', borderRadius: 3, border: `1px solid ${STA[threat.status]}40` }}>
                        {threat.status}
                      </span>
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

          {/* Right sidebar */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

            {/* Security posture gauge */}
            <div style={{ ...s.card, padding: '16px 18px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 10 }}>Security Posture</div>
              <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 4 }}>
                <SecurityGauge score={Math.round(score)} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {[
                  { label: 'Rules Active',   val: '8 / 8',  color: C.green },
                  { label: 'MTTD',           val: '4.2 min', color: C.text  },
                  { label: 'MTTR',           val: '18 min',  color: C.text  },
                  { label: 'FP Rate',        val: '2.1%',   color: C.green },
                ].map(({ label, val, color }) => (
                  <div key={label} style={{ background: C.surface, borderRadius: 6, padding: '8px 10px' }}>
                    <div style={{ fontSize: 10, color: C.dim, marginBottom: 2 }}>{label}</div>
                    <div style={{ fontSize: 13, fontWeight: 700, color, fontFamily: 'monospace' }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Attack timeline */}
            <div style={{ ...s.card, padding: '16px 18px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12 }}>Attack Timeline — 12h</div>
              <AttackTimeline tick={tick} />
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK coverage */}
        <div style={{ ...s.card, padding: '20px 24px', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <span style={{ fontWeight: 700, fontSize: 13 }}>MITRE ATT&amp;CK Coverage — Retail TTP Matrix</span>
            <span style={{
              fontSize: 11, color: C.green, background: `${C.green}15`,
              padding: '4px 12px', borderRadius: 5, border: `1px solid ${C.green}40`,
            }}>8 / 8 Techniques Monitored</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0 36px' }}>
            {mitre.map(m => <MitreBar key={m.technique} {...m} />)}
          </div>
        </div>

        {/* Emergency contacts */}
        <div style={{ ...s.card, padding: '20px 24px' }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 16 }}>🆘 Emergency Contacts</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
            {[
              {
                org: 'NCSC',
                full: 'National Cyber Security Centre',
                tel: '0300 020 0973',
                email: 'report@ncsc.gov.uk',
                note: 'Critical infrastructure & national-level cyber incidents',
                color: C.blue,
                icon: '🏛',
              },
              {
                org: 'ICO',
                full: "Information Commissioner's Office",
                tel: '0303 123 1113',
                email: 'casework@ico.org.uk',
                note: 'GDPR breach notification — 72-hour statutory window',
                color: C.yellow,
                icon: '⚖️',
              },
              {
                org: 'Action Fraud',
                full: 'UK National Fraud & Cybercrime',
                tel: '0300 123 2040',
                email: 'actionfraud.police.uk',
                note: 'Report financial fraud, voice fraud, and cybercrime',
                color: C.orange,
                icon: '🚔',
              },
            ].map(({ org, full, tel, email, note, color, icon }) => (
              <div key={org} style={{
                background: C.surface, borderRadius: 8, padding: '16px 18px',
                borderLeft: `3px solid ${color}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 16 }}>{icon}</span>
                  <span style={{ fontWeight: 800, fontSize: 15, color }}>{org}</span>
                </div>
                <div style={{ fontSize: 11, color: C.muted, marginBottom: 10 }}>{full}</div>
                <div style={{ fontSize: 12, color: C.text, marginBottom: 3 }}>📞 {tel}</div>
                <div style={{ fontSize: 12, color: C.text, marginBottom: 10 }}>✉  {email}</div>
                <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.5 }}>{note}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div style={{ textAlign: 'center', padding: '20px 0 8px', color: C.dim, fontSize: 11 }}>
          RetailShield v1.0 · ShieldTech Ltd · Tanvir Farhad · Microsoft Sentinel · MITRE ATT&amp;CK Enterprise
        </div>
      </main>

      {/* Playbook modal */}
      <PlaybookModal threat={selected} onClose={() => setSelected(null)} />

      {/* Global styles */}
      <style>{`
        @keyframes slideIn  { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes pulse    { 0%,100% { opacity: 1; box-shadow: 0 0 6px currentColor; } 50% { opacity: 0.3; box-shadow: none; } }
        ::-webkit-scrollbar       { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: ${C.surface}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        button:focus { outline: none; }
      `}</style>
    </div>
  )
}
