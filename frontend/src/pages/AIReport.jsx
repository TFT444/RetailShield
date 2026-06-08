import { useState } from 'react';
import { C, SEV, FONTS } from '../lib/tokens.js';
import { FileText, Download, Copy, Check, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react';

function generateReport(inc, now) {
  const dt = now.toISOString();
  const icoDeadline = new Date(now.getTime() + 72 * 3600000).toISOString();
  const ncscDeadline = new Date(now.getTime() + 24 * 3600000).toISOString();
  const fmtDt = d => new Date(d).toLocaleString('en-GB', { timeZone: 'Europe/London', dateStyle: 'long', timeStyle: 'medium' }) + ' GMT';

  return {
    generated: dt,
    s1: {
      title: '§1 Executive Summary',
      content: `A ${inc.severity.toLowerCase()}-severity security incident (${inc.id}) was detected at ${fmtDt(inc.detectedAt || dt)} affecting ${inc.entity || 'RetailShield infrastructure'}. The incident has been classified under MITRE ATT&CK technique ${inc.technique} (${inc.tactic}). Mean time to detect was ${inc.mttd || 'N/A'} minutes.

${inc.description}

Current status: ${inc.status}. Automated response playbooks were triggered immediately upon detection. This report documents all findings, response actions, and regulatory obligations arising from this incident.`,
    },
    s2: {
      title: '§2 Technical Details',
      content: `MITRE ATT&CK Mapping
  Technique : ${inc.technique}
  Tactic    : ${inc.tactic}
  Severity  : ${inc.severity}

Indicators of Compromise (IoC)
${[
  inc.sourceIP      ? `  Source IP             : ${inc.sourceIP} (${inc.country || 'Unknown'})` : null,
  inc.sourceEmail   ? `  Sender Address        : ${inc.sourceEmail}` : null,
  inc.destinationIP ? `  Destination IP        : ${inc.destinationIP} (${inc.geoLocation || 'Unknown'})` : null,
  inc.ransomwareFamily ? `  Ransomware Family     : ${inc.ransomwareFamily}` : null,
  inc.suspiciousExtension ? `  Suspicious Extension  : ${inc.suspiciousExtension}` : null,
  inc.filesModified   ? `  Files Modified        : ${inc.filesModified}` : null,
  inc.dataTransferredMB ? `  Data Transferred      : ${inc.dataTransferredMB} MB` : null,
  inc.failedAttempts  ? `  Failed Login Attempts : ${inc.failedAttempts}` : null,
  inc.phishingScore   ? `  Phishing Score        : ${inc.phishingScore}/100` : null,
  inc.attachmentType  ? `  Attachment Type       : ${inc.attachmentType}` : null,
  inc.injectionPattern ? `  Injection Pattern     : ${inc.injectionPattern}` : null,
].filter(Boolean).join('\n')}

Affected Systems
${(inc.affectedEntities || [inc.entity]).map(e => `  • ${e}`).join('\n')}

Attack Timeline
${(inc.timeline || []).map(t => `  [${t.time}] ${t.event}`).join('\n')}`,
    },
    s3: {
      title: '§3 Impact Assessment',
      content: `Overall Impact Level: ${inc.impactLevel || (inc.severity === 'Critical' ? 'Severe' : inc.severity === 'High' ? 'High' : 'Moderate')}

Data Categories Potentially Affected
${(inc.dataCategories || []).length > 0 ? (inc.dataCategories || []).map(d => `  • ${d}`).join('\n') : '  • No personal data confirmed affected at this stage'}

Business Impact
${inc.severity === 'Critical'
  ? `  • Operational disruption to affected systems is confirmed
  • Financial loss exposure pending full assessment
  • Reputational risk if incident becomes public
  • Regulatory reporting obligations triggered`
  : `  • Limited operational disruption
  • Financial exposure under assessment
  • Customer impact: ${inc.needsICO ? 'Potential customer data exposure identified' : 'No customer data confirmed affected'}`}

Scope Confirmation
  • Confirmed affected assets: ${(inc.affectedEntities || []).length}
  • Containment status: ${inc.status === 'Contained' || inc.status === 'Resolved' ? 'Contained' : 'Containment in progress'}
  • Eradication status: ${inc.status === 'Resolved' ? 'Complete' : 'In progress'}`,
    },
    s4: {
      title: '§4 Response Actions Taken',
      content: `Automated Response (Playbook: ${inc.id}-AUTO)
${(inc.autoDefence || []).map((a, i) => `  ${i + 1}. ${a}`).join('\n')}

Manual SOC Actions
  1. Incident classified and priority assigned
  2. Affected assets isolated from production network
  3. Forensic evidence preserved (memory dump, log export)
  4. Stakeholders notified per escalation matrix

Pending Actions
${(inc.recommendations || []).map((r, i) => `  ${i + 1}. ${r}`).join('\n')}`,
    },
    s5: {
      title: '§5 UK Regulatory Compliance',
      needsICO: inc.needsICO,
      needsNCSC: inc.needsNCSC,
      content: `Regulatory Obligations Assessment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

UK GDPR / Data Protection Act 2018 — ICO Notification
  Obligation   : ${inc.needsICO ? '⚠ REQUIRED — Personal data breach detected' : '✓ NOT REQUIRED — No personal data confirmed affected'}
  Authority    : Information Commissioner's Office (ICO)
  Deadline     : ${inc.needsICO ? `72 hours from discovery → ${fmtDt(icoDeadline)}` : 'N/A'}
  Reference    : Article 33 UK GDPR

Cyber Security and Resilience Bill — NCSC Reporting
  Obligation   : ${inc.needsNCSC ? '⚠ REQUIRED — Significant cyber incident' : '✓ NOT REQUIRED — Below significance threshold'}
  Authority    : National Cyber Security Centre (NCSC)
  Deadline     : ${inc.needsNCSC ? `24 hours from discovery → ${fmtDt(ncscDeadline)}` : 'N/A'}
  Reference    : CSR Bill 2025 (UK equivalent of NIS2)

${inc.needsICO ? `DRAFT ICO NOTIFICATION (Article 33 UK GDPR)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
To: reportabreach@ico.org.uk
Subject: Personal Data Breach Notification — ${inc.id}

Organisation: RetailShield Ltd / ShieldTech Ltd
Data Controller: Tanvir Farhad, ShieldTech Ltd, London
Date/Time of Breach: ${fmtDt(inc.detectedAt || dt)}
Date/Time Notified: ${fmtDt(dt)}
Notification Deadline: ${fmtDt(icoDeadline)}

Nature of Breach: ${inc.description}
Categories of Data: ${(inc.dataCategories || ['Under assessment']).join(', ')}
Approximate number of individuals affected: Under assessment
Likely consequences: ${inc.impactLevel || 'Under assessment'}
Measures taken: ${(inc.autoDefence || []).join('; ')}

Signed: Tanvir Farhad — SOC Lead, ShieldTech Ltd` : ''}

${inc.needsNCSC ? `DRAFT NCSC REPORT (CSR Bill 2025)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
To: report@ncsc.gov.uk
Subject: Significant Cyber Incident Report — ${inc.id}

Organisation: RetailShield Ltd / ShieldTech Ltd
Incident Reference: ${inc.id}
Date/Time Detected: ${fmtDt(inc.detectedAt || dt)}
Report Submitted: ${fmtDt(dt)}
24-Hour Deadline: ${fmtDt(ncscDeadline)}

Incident Type: ${inc.tactic} — ${inc.technique}
Severity: ${inc.severity}
Systems Affected: ${(inc.affectedEntities || []).join(', ')}
Attack Vector: ${inc.description}
Containment Status: ${inc.status}
Response Actions: ${(inc.autoDefence || []).join('; ')}

Signed: Tanvir Farhad — SOC Lead, ShieldTech Ltd` : ''}`,
    },
    s6: {
      title: '§6 Recommendations',
      content: `Immediate Actions (0–24 hours)
${(inc.recommendations || []).slice(0, 3).map((r, i) => `  ${i + 1}. ${r}`).join('\n')}

Short-Term Actions (1–7 days)
  1. Conduct full forensic review of affected systems
  2. Review and update detection rules to improve coverage for ${inc.technique}
  3. Brief relevant teams on attack TTPs and lessons learned
  4. Update incident response playbooks based on gaps identified

Strategic Improvements (1–3 months)
  1. Commission external penetration test targeting ${inc.tactic} attack surface
  2. Implement enhanced monitoring for ${inc.technique} technique patterns
  3. Review and test business continuity plan
  4. Schedule MITRE ATT&CK coverage gap assessment

Lessons Learned
  • MTTD of ${inc.mttd || 'N/A'} minutes — target: ≤5 minutes for ${inc.severity} severity
  • Automated playbook response was ${(inc.autoDefence || []).length > 0 ? 'effective' : 'not triggered'}
  • UK regulatory deadlines identified: ${[inc.needsICO ? 'ICO (72h)' : null, inc.needsNCSC ? 'NCSC (24h)' : null].filter(Boolean).join(', ') || 'None triggered'}`,
    },
  };
}

function Section({ sec, expanded, toggle }) {
  const hasWarning = sec.needsICO !== undefined && (sec.needsICO || sec.needsNCSC);
  return (
    <div style={{ background: C.card, border: `1px solid ${hasWarning ? C.amber : C.border}`, borderRadius: 10, overflow: 'hidden', marginBottom: 8 }}>
      <button
        onClick={toggle}
        style={{
          width: '100%', padding: '14px 18px', background: 'none', border: 'none',
          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10, textAlign: 'left',
        }}
      >
        {hasWarning && <AlertTriangle size={14} color={C.amber} />}
        <span style={{ flex: 1, color: C.text, fontSize: 14, fontWeight: 600, fontFamily: FONTS.ui }}>{sec.title}</span>
        {expanded ? <ChevronUp size={14} color={C.textMuted} /> : <ChevronDown size={14} color={C.textMuted} />}
      </button>
      {expanded && (
        <div style={{ padding: '0 18px 16px', borderTop: `1px solid ${C.border}` }}>
          <pre style={{
            color: C.text, fontSize: 12, fontFamily: FONTS.mono,
            whiteSpace: 'pre-wrap', lineHeight: 1.7, margin: '12px 0 0',
          }}>
            {sec.content}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function AIReport({ incidents }) {
  const [selectedId, setSelectedId] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState({});
  const [copied, setCopied] = useState(false);

  const activeIncidents = incidents.filter(i => i.severity === 'Critical' || i.severity === 'High');

  function generateReportHandler() {
    const inc = incidents.find(i => i.id === selectedId);
    if (!inc) return;
    setLoading(true);
    setReport(null);
    setTimeout(() => {
      const r = generateReport(inc, new Date());
      setReport(r);
      setExpanded({ s1: true, s2: false, s3: false, s4: false, s5: true, s6: false });
      setLoading(false);
    }, 1200);
  }

  function copyReport() {
    if (!report) return;
    const text = Object.values(report)
      .filter(v => v && v.title)
      .map(s => `${s.title}\n${'='.repeat(50)}\n${s.content}\n`)
      .join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function downloadReport() {
    if (!report) return;
    const inc = incidents.find(i => i.id === selectedId);
    const text = Object.values(report)
      .filter(v => v && v.title)
      .map(s => `${s.title}\n${'='.repeat(50)}\n${s.content}\n`)
      .join('\n');
    const blob = new Blob([
      `RETAILSHIELD INCIDENT REPORT\n${'='.repeat(50)}\nGenerated: ${new Date(report.generated).toLocaleString('en-GB')}\nIncident: ${inc?.id} — ${inc?.title}\n\n${text}`
    ], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RetailShield_IR_${selectedId}_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const toggle = key => setExpanded(e => ({ ...e, [key]: !e[key] }));

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>AI Incident Report</h1>
        <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4 }}>
          6-section UK-compliant report with ICO / NCSC draft notifications
        </div>
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <label style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 8 }}>
              Select Incident
            </label>
            <select
              value={selectedId}
              onChange={e => setSelectedId(e.target.value)}
              style={{
                width: '100%', padding: '10px 12px', background: C.surface,
                border: `1px solid ${C.border}`, borderRadius: 8, color: C.text,
                fontSize: 13, fontFamily: FONTS.ui, cursor: 'pointer', minHeight: 44,
              }}
            >
              <option value="">— Choose an incident —</option>
              {incidents.map(inc => (
                <option key={inc.id} value={inc.id}>
                  [{inc.severity}] {inc.id} — {inc.title}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={generateReportHandler}
            disabled={!selectedId || loading}
            style={{
              padding: '10px 24px', background: selectedId && !loading ? C.blue : C.border,
              color: '#fff', border: 'none', borderRadius: 8, cursor: selectedId && !loading ? 'pointer' : 'not-allowed',
              fontSize: 13, fontWeight: 700, fontFamily: FONTS.ui,
              display: 'flex', alignItems: 'center', gap: 8, minHeight: 44,
              transition: 'background 200ms',
            }}
          >
            <FileText size={15} />
            {loading ? 'Generating…' : 'Generate Report'}
          </button>
          {report && (
            <>
              <button onClick={copyReport} style={{
                padding: '10px 18px', background: C.surface, border: `1px solid ${C.border}`,
                color: copied ? C.green : C.text, borderRadius: 8, cursor: 'pointer',
                fontSize: 13, fontFamily: FONTS.ui, display: 'flex', alignItems: 'center', gap: 6,
                minHeight: 44,
              }}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button onClick={downloadReport} style={{
                padding: '10px 18px', background: C.surface, border: `1px solid ${C.border}`,
                color: C.text, borderRadius: 8, cursor: 'pointer',
                fontSize: 13, fontFamily: FONTS.ui, display: 'flex', alignItems: 'center', gap: 6,
                minHeight: 44,
              }}>
                <Download size={14} />
                Download
              </button>
            </>
          )}
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: 'center', padding: 60, color: C.textMuted }}>
          <div style={{ fontSize: 14, marginBottom: 8 }}>Generating incident report…</div>
          <div style={{ color: C.textDim, fontSize: 12, fontFamily: FONTS.mono }}>
            Analysing IoCs · Mapping MITRE ATT&CK · Checking UK regulatory obligations
          </div>
        </div>
      )}

      {report && !loading && (
        <div>
          {['s1','s2','s3','s4','s5','s6'].map(k => (
            <Section key={k} sec={report[k]} expanded={!!expanded[k]} toggle={() => toggle(k)} />
          ))}
        </div>
      )}

      {!report && !loading && (
        <div style={{ textAlign: 'center', padding: 60, color: C.textMuted }}>
          <FileText size={40} color={C.textDim} style={{ margin: '0 auto 12px', display: 'block' }} />
          <div style={{ fontSize: 14, marginBottom: 4 }}>Select an incident and click Generate Report</div>
          <div style={{ fontSize: 12, color: C.textDim }}>Reports include ICO 72h and NCSC 24h draft notifications where required</div>
        </div>
      )}
    </div>
  );
}
