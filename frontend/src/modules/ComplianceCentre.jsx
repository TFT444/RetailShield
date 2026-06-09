import { useState, useEffect } from 'react';
import { FileCheck, Clock, AlertTriangle, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react';
import TopBar from '../components/TopBar.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { COMPLIANCE_REGULATIONS, SUBMISSION_HISTORY } from '../lib/data.js';

function useCountdown(targetIso) {
  const [remaining, setRemaining] = useState('');
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    if (!targetIso) return;
    const tick = () => {
      const diff = new Date(targetIso) - Date.now();
      if (diff <= 0) { setRemaining('EXPIRED'); setExpired(true); return; }
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setRemaining(`${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`);
      setExpired(false);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [targetIso]);

  return { remaining, expired };
}

function DeadlineCard({ incident, regulationType }) {
  const hoursRequired = regulationType === 'ICO' ? 72 : 24;
  const deadlineTime = incident.detectedAt
    ? new Date(new Date(incident.detectedAt).getTime() + hoursRequired * 3600000).toISOString()
    : null;
  const { remaining, expired } = useCountdown(deadlineTime);

  const fmtDeadline = deadlineTime
    ? new Date(deadlineTime).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'Unknown';

  const color = expired ? 'var(--accent)' : remaining && remaining.startsWith('00:') ? 'var(--warning)' : 'var(--success)';

  return (
    <div style={{
      background: 'var(--card)', border: `1px solid ${expired ? 'rgba(220,38,38,0.4)' : 'var(--border)'}`,
      borderRadius: 'var(--radius-card)', padding: '16px 20px',
      borderLeft: `3px solid ${color}`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginBottom: '4px' }}>
            {incident.id} — {incident.title}
          </div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>
            {regulationType === 'ICO' ? 'ICO Notification (UK GDPR Art.33)' : 'NCSC Report (CSR Bill 2025)'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
            Deadline: {fmtDeadline}
          </div>
        </div>
        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-mono)', color, letterSpacing: '0.02em', lineHeight: 1 }}>
            {remaining || '--:--:--'}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '3px' }}>
            {expired ? 'OVERDUE' : 'remaining'}
          </div>
        </div>
      </div>
    </div>
  );
}

function RegulationRow({ reg }) {
  const [expanded, setExpanded] = useState(false);
  const descriptions = {
    GDPR: 'UK GDPR Article 33 requires controllers to notify the ICO of a personal data breach within 72 hours of becoming aware of it, where feasible. Article 34 may also require notifying affected data subjects.',
    CSR:  'The Cyber Security and Resilience Bill 2025 mandates that in-scope organisations report significant cyber incidents to the NCSC within 24 hours. Operators of essential services and digital service providers are in scope.',
    PCI:  'PCI DSS v4.0 Requirement 12.10 mandates an incident response plan. Suspected cardholder data breaches must be reported to the acquiring bank and payment brands (Visa, Mastercard) promptly, typically within 24-72 hours.',
    NIS2:  'NIS2 Directive (and its UK equivalent) requires early warning to national authority within 24 hours, incident notification within 72 hours, and a final report within one month of the incident notification.',
  };

  return (
    <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
      <button
        onClick={() => setExpanded(v => !v)}
        style={{
          width: '100%', display: 'grid', gridTemplateColumns: '1fr 100px 80px 100px 32px',
          padding: '14px 20px', background: 'none', border: 'none',
          cursor: 'pointer', textAlign: 'left', transition: 'background var(--transition)',
          alignItems: 'center',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'none'}
      >
        <div>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>{reg.name}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>Authority: {reg.authority}</div>
        </div>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{reg.deadline}</span>
        <StatusBadge status={reg.status} />
        <span style={{ fontSize: '11px', color: 'var(--text-dim)', paddingRight: '8px' }}>{reg.threshold.slice(0, 30)}…</span>
        {expanded ? <ChevronUp size={14} color="var(--text-dim)" /> : <ChevronDown size={14} color="var(--text-dim)" />}
      </button>
      {expanded && (
        <div style={{ padding: '0 20px 16px', borderTop: '1px solid var(--border)', animation: 'fadeIn 150ms ease' }}>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.6, paddingTop: '12px' }}>
            {descriptions[reg.id] || reg.threshold}
          </p>
        </div>
      )}
    </div>
  );
}

export default function ComplianceCentre({ onBack, incidents }) {
  const icoIncidents  = incidents.filter(i => i.needsICO);
  const ncscIncidents = incidents.filter(i => i.needsNCSC);
  const needsAction   = icoIncidents.length + ncscIncidents.length;

  const fmtDate = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      <TopBar moduleName="Compliance Centre" onBack={onBack} />

      <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
        <div style={{ maxWidth: '1100px', display: 'flex', flexDirection: 'column', gap: '24px', animation: 'fadeIn 200ms ease' }}>

          {/* Summary strip */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
            {[
              { label: 'Frameworks',       value: COMPLIANCE_REGULATIONS.length, sub: 'monitored',       accent: 'var(--primary)' },
              { label: 'Action Required',  value: needsAction,                   sub: 'notifications',   accent: needsAction > 0 ? 'var(--accent)' : undefined },
              { label: 'ICO Incidents',    value: icoIncidents.length,           sub: '72h obligation',  accent: icoIncidents.length > 0 ? 'var(--warning)' : undefined },
              { label: 'NCSC Incidents',   value: ncscIncidents.length,          sub: '24h obligation',  accent: ncscIncidents.length > 0 ? 'var(--warning)' : undefined },
            ].map(s => (
              <div key={s.label} style={{
                background: 'var(--card)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-card)', padding: '16px 20px',
                borderLeft: s.accent ? `3px solid ${s.accent}` : undefined,
              }}>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>{s.label}</div>
                <div style={{ fontSize: '26px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: s.accent || 'var(--text)', lineHeight: 1.1 }}>{s.value}</div>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>{s.sub}</div>
              </div>
            ))}
          </div>

          {/* Active deadlines */}
          {needsAction > 0 && (
            <div>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={13} />
                Active Notification Deadlines
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {icoIncidents.map(inc  => <DeadlineCard key={`ico-${inc.id}`}  incident={inc} regulationType="ICO" />)}
                {ncscIncidents.map(inc => <DeadlineCard key={`ncsc-${inc.id}`} incident={inc} regulationType="NCSC" />)}
              </div>
            </div>
          )}

          {needsAction === 0 && (
            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', padding: '32px', display: 'flex', alignItems: 'center', gap: '16px' }}>
              <CheckCircle size={28} color="var(--success)" />
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text)', marginBottom: '4px' }}>No active notification deadlines</div>
                <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Run the attack simulation to populate ICO and NCSC deadline trackers for Critical incidents.</div>
              </div>
            </div>
          )}

          {/* Regulatory frameworks */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '10px' }}>
              Regulatory Frameworks
            </div>

            {/* Table header */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 80px 100px 32px', padding: '10px 20px', background: 'var(--surface)', borderRadius: 'var(--radius-badge)', marginBottom: '8px' }}>
              {['Framework', 'Deadline', 'Status', 'Trigger', ''].map((h, i) => (
                <span key={i} style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{h}</span>
              ))}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {COMPLIANCE_REGULATIONS.map(reg => <RegulationRow key={reg.id} reg={reg} />)}
            </div>
          </div>

          {/* Submission history */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '10px' }}>
              Submission History
            </div>
            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '90px 100px 110px 90px 140px', padding: '10px 20px', background: 'var(--surface)', borderBottom: '1px solid var(--border)' }}>
                {['Ref', 'Date', 'Incident', 'Framework', 'Status'].map(h => (
                  <span key={h} style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{h}</span>
                ))}
              </div>
              {SUBMISSION_HISTORY.map((sub, idx) => (
                <div key={sub.id} style={{
                  display: 'grid', gridTemplateColumns: '90px 100px 110px 90px 140px',
                  padding: '12px 20px', borderBottom: idx < SUBMISSION_HISTORY.length - 1 ? '1px solid var(--border)' : 'none',
                  alignItems: 'center',
                }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{sub.refNo.slice(0, 12)}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{fmtDate(sub.date)}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{sub.incident}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{sub.regulation}</span>
                  <StatusBadge status={sub.status} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
