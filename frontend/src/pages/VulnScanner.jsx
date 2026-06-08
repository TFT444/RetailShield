import { useState } from 'react';
import { C, SEV, FONTS } from '../lib/tokens.js';
import { VULN_FINDINGS } from '../lib/data.js';
import { Shield, Search, Download, AlertTriangle, CheckCircle, Info, Clock } from 'lucide-react';

function RiskGauge({ score }) {
  const r = 70, cx = 80, cy = 80;
  const startAngle = -210, sweepAngle = 240;
  const toRad = deg => (deg * Math.PI) / 180;
  const angle = startAngle + (score / 100) * sweepAngle;
  const x = cx + r * Math.cos(toRad(angle));
  const y = cy + r * Math.sin(toRad(angle));

  const color = score >= 75 ? C.red : score >= 50 ? C.amber : C.green;

  const arcPath = (start, end, col) => {
    const s = toRad(start), e = toRad(end);
    const x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s);
    const x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e);
    const large = (end - start) > 180 ? 1 : 0;
    return <path d={`M${x1},${y1} A${r},${r},0,${large},1,${x2},${y2}`} stroke={col} strokeWidth={10} fill="none" strokeLinecap="round" />;
  };

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width={160} height={120} style={{ display: 'block', margin: '0 auto' }}>
        {arcPath(startAngle, startAngle + sweepAngle, C.border)}
        {arcPath(startAngle, angle, color)}
        <circle cx={x} cy={y} r={6} fill={color} />
        <text x={cx} y={cy + 10} textAnchor="middle" fill={color} fontSize={28} fontWeight={700} fontFamily={FONTS.mono}>{score}</text>
        <text x={cx} y={cy + 26} textAnchor="middle" fill={C.textMuted} fontSize={10} fontFamily={FONTS.ui}>Risk Score</text>
      </svg>
      <div style={{ color, fontSize: 13, fontWeight: 700, marginTop: -8 }}>
        {score >= 75 ? 'HIGH RISK' : score >= 50 ? 'MEDIUM RISK' : 'LOW RISK'}
      </div>
    </div>
  );
}

function SeverityRow({ sev, count, total }) {
  const s = SEV[sev] || SEV.Info;
  const pct = total > 0 ? (count / total) * 100 : 0;
  const icon = { Critical: AlertTriangle, High: AlertTriangle, Medium: Info, Low: Info, Info: CheckCircle }[sev] || Info;
  const Icon = icon;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
      <Icon size={14} color={s.color} />
      <span style={{ color: C.textMuted, fontSize: 12, width: 60, fontFamily: FONTS.ui }}>{sev}</span>
      <div style={{ flex: 1, height: 8, background: C.border, borderRadius: 4, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: s.color, borderRadius: 4 }} />
      </div>
      <span style={{ color: s.color, fontSize: 13, fontWeight: 700, fontFamily: FONTS.mono, width: 24, textAlign: 'right' }}>{count}</span>
    </div>
  );
}

function FindingRow({ f, last }) {
  const s = SEV[f.severity] || SEV.Info;
  return (
    <tr style={{ borderBottom: last ? 'none' : `1px solid ${C.border}` }}>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{f.id}</td>
      <td style={{ padding: '10px 14px' }}>
        <span style={{
          background: s.bg || `${s.color}22`, color: s.color,
          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4, fontFamily: FONTS.mono,
        }}>{f.severity.toUpperCase()}</span>
      </td>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11 }}>{f.category}</td>
      <td style={{ padding: '10px 14px', color: C.text, fontSize: 12 }}>{f.title}</td>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{f.cve}</td>
      <td style={{ padding: '10px 14px', color: C.text, fontSize: 11 }}>{f.remediation}</td>
      <td style={{ padding: '10px 14px' }}>
        <span style={{
          color: f.status === 'Pending Review' ? C.amber : f.status === 'Open' ? C.red : C.green,
          fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono,
        }}>{f.status}</span>
      </td>
    </tr>
  );
}

export default function VulnScanner() {
  const [domain, setDomain] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [filter, setFilter] = useState('All');

  function startScan() {
    if (!confirmed || !domain.trim()) return;
    setScanning(true);
    setProgress(0);
    setResults(null);
    const steps = [5, 15, 30, 45, 60, 72, 85, 95, 100];
    let i = 0;
    const iv = setInterval(() => {
      if (i < steps.length) {
        setProgress(steps[i]);
        i++;
      } else {
        clearInterval(iv);
        setScanning(false);
        setResults({ ...VULN_FINDINGS, domain: domain.trim() });
      }
    }, 300);
  }

  const total = results ? Object.values(results.summary).reduce((a, b) => a + b, 0) : 0;
  const filtered = results ? (filter === 'All' ? results.findings : results.findings.filter(f => f.severity === filter)) : [];
  const pendingReview = results ? results.findings.filter(f => f.status === 'Pending Review') : [];

  function downloadReport() {
    if (!results) return;
    const lines = [
      `RetailShield Vulnerability Scan Report`,
      `Target: ${results.domain}`,
      `Date: ${new Date().toLocaleString('en-GB')}`,
      `Risk Score: ${results.riskScore}/100`,
      ``,
      `SUMMARY`,
      `Critical: ${results.summary.critical}`,
      `High: ${results.summary.high}`,
      `Medium: ${results.summary.medium}`,
      `Low: ${results.summary.low}`,
      `Info: ${results.summary.info}`,
      ``,
      `FINDINGS`,
      ...results.findings.map(f =>
        `[${f.severity}] ${f.id} — ${f.title}\n  Category: ${f.category}\n  CVE/CWE: ${f.cve}\n  Remediation: ${f.remediation}\n  Status: ${f.status}`
      ),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RetailShield_VulnScan_${results.domain}_${new Date().toISOString().slice(0,10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Vulnerability Scanner</h1>
        <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4 }}>Web application and network vulnerability assessment</div>
      </div>

      {/* Input + permission */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: 14 }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <label style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, display: 'block', marginBottom: 8 }}>Target Domain</label>
            <input
              type="text"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              placeholder="e.g. demo.retailshield.io"
              style={{
                width: '100%', padding: '10px 12px', background: C.surface,
                border: `1px solid ${C.border}`, borderRadius: 8, color: C.text,
                fontSize: 13, fontFamily: FONTS.mono, boxSizing: 'border-box', minHeight: 44,
              }}
            />
          </div>
          <button
            onClick={startScan}
            disabled={!confirmed || !domain.trim() || scanning}
            style={{
              padding: '10px 24px', minHeight: 44,
              background: confirmed && domain.trim() && !scanning ? C.blue : C.border,
              color: '#fff', border: 'none', borderRadius: 8,
              cursor: confirmed && domain.trim() && !scanning ? 'pointer' : 'not-allowed',
              fontSize: 13, fontWeight: 700, fontFamily: FONTS.ui,
              display: 'flex', alignItems: 'center', gap: 8, transition: 'background 200ms',
            }}
          >
            <Search size={15} />
            {scanning ? 'Scanning…' : 'Start Scan'}
          </button>
          {results && (
            <button onClick={downloadReport} style={{
              padding: '10px 18px', minHeight: 44, background: C.surface,
              border: `1px solid ${C.border}`, color: C.text, borderRadius: 8,
              cursor: 'pointer', fontSize: 13, fontFamily: FONTS.ui,
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
              <Download size={14} /> Download Report
            </button>
          )}
        </div>
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={confirmed}
            onChange={e => setConfirmed(e.target.checked)}
            style={{ marginTop: 2, accentColor: C.blue, width: 16, height: 16 }}
          />
          <span style={{ color: C.textMuted, fontSize: 12, lineHeight: 1.5 }}>
            I confirm I have explicit written authorisation to scan this domain. Unauthorised scanning may violate the Computer Misuse Act 1990 (UK).
          </span>
        </label>
      </div>

      {/* Progress bar */}
      {scanning && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
            <span style={{ color: C.text, fontSize: 13 }}>Scanning {domain}…</span>
            <span style={{ color: C.blue, fontSize: 13, fontFamily: FONTS.mono }}>{progress}%</span>
          </div>
          <div style={{ height: 8, background: C.border, borderRadius: 4, overflow: 'hidden' }}>
            <div style={{ width: `${progress}%`, height: '100%', background: C.blue, borderRadius: 4, transition: 'width 250ms' }} />
          </div>
          <div style={{ color: C.textMuted, fontSize: 11, marginTop: 8, fontFamily: FONTS.mono }}>
            {progress < 20 ? 'Resolving DNS and fingerprinting…'
              : progress < 50 ? 'Testing injection vectors…'
              : progress < 75 ? 'Checking authentication controls…'
              : progress < 90 ? 'Analysing headers and cryptography…'
              : 'Compiling results…'}
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <RiskGauge score={results.riskScore} />
            </div>
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '16px 20px' }}>
              <div style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>Findings by Severity</div>
              <SeverityRow sev="Critical" count={results.summary.critical} total={total} />
              <SeverityRow sev="High"     count={results.summary.high}     total={total} />
              <SeverityRow sev="Medium"   count={results.summary.medium}   total={total} />
              <SeverityRow sev="Low"      count={results.summary.low}      total={total} />
              <SeverityRow sev="Info"     count={results.summary.info}     total={total} />
            </div>
            <div style={{ background: C.card, border: `1px solid ${C.amber}44`, borderRadius: 10, padding: '16px 20px' }}>
              <div style={{ color: C.amber, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Clock size={12} /> Pending Review ({pendingReview.length})
              </div>
              {pendingReview.map(f => (
                <div key={f.id} style={{ marginBottom: 10, padding: '8px 10px', background: `${C.amber}11`, borderRadius: 6, border: `1px solid ${C.amber}33` }}>
                  <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>{f.title}</div>
                  <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2, fontFamily: FONTS.mono }}>{f.id} · {f.cve}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Findings table */}
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: C.text, fontWeight: 600, fontSize: 14, flex: 1 }}>All Findings</span>
              {['All','Critical','High','Medium','Low'].map(s => (
                <button key={s} onClick={() => setFilter(s)} style={{
                  padding: '4px 10px', border: `1px solid ${filter === s ? C.red : C.border}`,
                  background: filter === s ? `${C.red}22` : 'transparent',
                  color: filter === s ? C.text : C.textMuted,
                  borderRadius: 4, cursor: 'pointer', fontSize: 11, fontFamily: FONTS.ui,
                }}>{s}</button>
              ))}
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ background: C.surface }}>
                    {['ID','Severity','Category','Title','CWE','Remediation','Status'].map(h => (
                      <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: C.textMuted, fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((f, i) => (
                    <FindingRow key={f.id} f={f} last={i === filtered.length - 1} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {!results && !scanning && (
        <div style={{ textAlign: 'center', padding: 60, color: C.textMuted }}>
          <Shield size={40} color={C.textDim} style={{ margin: '0 auto 12px', display: 'block' }} />
          <div style={{ fontSize: 14, marginBottom: 4 }}>Enter a target domain and confirm authorisation to begin</div>
          <div style={{ fontSize: 12, color: C.textDim }}>Demo mode — results use simulated data from RetailShield's vulnerability database</div>
        </div>
      )}
    </div>
  );
}
