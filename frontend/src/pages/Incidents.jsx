import { useState } from 'react';
import { C, SEV, STATUS, FONTS } from '../lib/tokens.js';
import {
  AlertTriangle, ChevronRight, X, Clock, Shield,
  Monitor, Globe, User, List, ArrowLeft,
} from 'lucide-react';

function Badge({ type, value }) {
  const map = type === 'sev' ? SEV : STATUS;
  const s = map[value] || { color: C.textMuted, bg: C.border, label: value };
  return (
    <span style={{
      background: s.bg || `${s.color}22`, color: s.color,
      fontSize: 10, fontWeight: 700, padding: '2px 8px',
      borderRadius: 4, fontFamily: FONTS.mono, letterSpacing: 0.5,
    }}>
      {s.label || value}
    </span>
  );
}

function IncidentDetail({ inc, onClose }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10 }}>
      <div style={{
        padding: '16px 20px', borderBottom: `1px solid ${C.border}`,
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <button onClick={onClose} style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: C.textMuted, display: 'flex', alignItems: 'center', gap: 4, padding: 0,
        }}>
          <ArrowLeft size={14} />
          <span style={{ fontSize: 12, fontFamily: FONTS.ui }}>Back</span>
        </button>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: C.textMuted, fontSize: 12, fontFamily: FONTS.mono }}>{inc.id}</span>
            <Badge type="sev" value={inc.severity} />
            <Badge type="status" value={inc.status} />
          </div>
          <h2 style={{ color: C.text, fontSize: 16, fontWeight: 700, margin: '4px 0 0' }}>{inc.title}</h2>
        </div>
      </div>

      <div style={{ padding: '20px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Left col */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Section title="Description">
            <p style={{ color: C.textMuted, fontSize: 13, margin: 0, lineHeight: 1.6 }}>{inc.description}</p>
          </Section>

          <Section title="MITRE ATT&CK">
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <Chip label="Technique" value={inc.technique} />
              <Chip label="Tactic" value={inc.tactic} />
            </div>
          </Section>

          <Section title="Incident Timeline">
            <div style={{ position: 'relative', paddingLeft: 16 }}>
              <div style={{ position: 'absolute', left: 5, top: 0, bottom: 0, width: 1, background: C.border }} />
              {(inc.timeline || []).map((ev, i) => (
                <div key={i} style={{ position: 'relative', marginBottom: 12 }}>
                  <div style={{
                    position: 'absolute', left: -12, top: 4, width: 8, height: 8,
                    borderRadius: '50%', background: i === 0 ? C.red : C.border,
                    border: `2px solid ${i === 0 ? C.red : C.borderHi}`,
                  }} />
                  <div style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{ev.time}</div>
                  <div style={{ color: C.text, fontSize: 12, marginTop: 2 }}>{ev.event}</div>
                </div>
              ))}
            </div>
          </Section>
        </div>

        {/* Right col */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Section title="Affected Entities">
            {(inc.affectedEntities || []).map((e, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <Monitor size={12} color={C.blue} />
                <span style={{ color: C.text, fontSize: 12, fontFamily: FONTS.mono }}>{e}</span>
              </div>
            ))}
          </Section>

          <Section title="Automated Defence Actions">
            {(inc.autoDefence || []).map((a, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                <Shield size={12} color={C.green} style={{ marginTop: 2, flexShrink: 0 }} />
                <span style={{ color: C.text, fontSize: 12 }}>{a}</span>
              </div>
            ))}
          </Section>

          <Section title="Recommended Actions">
            {(inc.recommendations || []).map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                <span style={{ color: C.amber, fontSize: 12, fontWeight: 700, flexShrink: 0 }}>{i + 1}.</span>
                <span style={{ color: C.text, fontSize: 12 }}>{r}</span>
              </div>
            ))}
          </Section>

          <Section title="Key Indicators">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {inc.mttd    && <KV label="MTTD" value={`${inc.mttd} min`} />}
              {inc.sourceIP && <KV label="Source IP" value={inc.sourceIP} />}
              {inc.country  && <KV label="Country" value={inc.country} />}
              {inc.entity   && <KV label="Entity" value={inc.entity} />}
              {inc.failedAttempts && <KV label="Failed Logins" value={inc.failedAttempts} />}
              {inc.phishingScore  && <KV label="Phishing Score" value={`${inc.phishingScore}/100`} />}
              {inc.filesModified  && <KV label="Files Encrypted" value={inc.filesModified} />}
              {inc.dataTransferredMB && <KV label="Data Exfiltrated" value={`${inc.dataTransferredMB} MB`} />}
            </div>
          </Section>
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8, fontFamily: FONTS.ui }}>{title}</div>
      {children}
    </div>
  );
}

function Chip({ label, value }) {
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: '4px 10px' }}>
      <span style={{ color: C.textMuted, fontSize: 10 }}>{label}: </span>
      <span style={{ color: C.text, fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>{value}</span>
    </div>
  );
}

function KV({ label, value }) {
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: '8px 10px' }}>
      <div style={{ color: C.textMuted, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
      <div style={{ color: C.text, fontSize: 12, fontFamily: FONTS.mono, marginTop: 2, wordBreak: 'break-all' }}>{value}</div>
    </div>
  );
}

export default function Incidents({ incidents, onNavigateReport }) {
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('All');

  const SEVS = ['All', 'Critical', 'High', 'Medium', 'Low'];
  const visible = filter === 'All' ? incidents : incidents.filter(i => i.severity === filter);

  if (selected) {
    return <IncidentDetail inc={selected} onClose={() => setSelected(null)} />;
  }

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Incidents</h1>
          <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4 }}>{incidents.length} total · {incidents.filter(i => i.status === 'Active').length} active</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {SEVS.map(s => (
            <button key={s} onClick={() => setFilter(s)} style={{
              padding: '6px 14px', border: `1px solid ${filter === s ? C.red : C.border}`,
              background: filter === s ? `${C.red}22` : 'transparent',
              color: filter === s ? C.text : C.textMuted,
              borderRadius: 6, cursor: 'pointer', fontSize: 12, fontFamily: FONTS.ui, minHeight: 36,
            }}>{s}</button>
          ))}
        </div>
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: C.surface }}>
              {['ID', 'Title', 'Severity', 'Tactic', 'Status', 'Detected', 'MTTD', ''].map(h => (
                <th key={h} style={{
                  padding: '10px 16px', textAlign: 'left', color: C.textMuted,
                  fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
                  borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((inc, i) => (
              <tr
                key={inc.id}
                onClick={() => setSelected(inc)}
                style={{
                  cursor: 'pointer', borderBottom: i < visible.length - 1 ? `1px solid ${C.border}` : 'none',
                  background: inc.severity === 'Critical' ? `${C.red}06` : 'transparent',
                  transition: 'background 150ms',
                }}
                onMouseEnter={e => e.currentTarget.style.background = `${C.blue}11`}
                onMouseLeave={e => e.currentTarget.style.background = inc.severity === 'Critical' ? `${C.red}06` : 'transparent'}
              >
                <td style={{ padding: '12px 16px', color: C.textMuted, fontSize: 12, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{inc.id}</td>
                <td style={{ padding: '12px 16px', color: C.text, fontSize: 13, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title}</td>
                <td style={{ padding: '12px 16px' }}><Badge type="sev" value={inc.severity} /></td>
                <td style={{ padding: '12px 16px', color: C.textMuted, fontSize: 12 }}>{inc.tactic}</td>
                <td style={{ padding: '12px 16px' }}><Badge type="status" value={inc.status} /></td>
                <td style={{ padding: '12px 16px', color: C.textMuted, fontSize: 12, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>
                  {inc.detectedAt ? new Date(inc.detectedAt).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : 'just now'}
                </td>
                <td style={{ padding: '12px 16px', color: C.text, fontSize: 12, fontFamily: FONTS.mono }}>{inc.mttd ? `${inc.mttd}m` : '—'}</td>
                <td style={{ padding: '12px 16px' }}>
                  <ChevronRight size={14} color={C.textMuted} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {visible.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: C.textMuted, fontSize: 14 }}>
            No incidents matching filter
          </div>
        )}
      </div>
    </div>
  );
}
