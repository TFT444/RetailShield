import { useState } from 'react';
import { C, SEV, FONTS } from '../lib/tokens.js';
import { DETECTION_RULES, MITRE_COVERAGE } from '../lib/data.js';
import { Code2, Activity, CheckCircle, XCircle } from 'lucide-react';

function SeverityBadge({ sev }) {
  const s = SEV[sev] || SEV.Info;
  return (
    <span style={{
      background: s.bg || `${s.color}22`, color: s.color, fontSize: 10,
      fontWeight: 700, padding: '2px 8px', borderRadius: 4, fontFamily: FONTS.mono,
    }}>
      {(s.label || sev).toUpperCase()}
    </span>
  );
}

function TacticBadge({ tactic }) {
  const colors = {
    'Initial Access':     C.blue,
    'Execution':          '#f97316',
    'Persistence':        C.purple,
    'Privilege Escalation': '#ec4899',
    'Defence Evasion':    C.teal,
    'Credential Access':  C.amber,
    'Discovery':          '#84cc16',
    'Lateral Movement':   '#06b6d4',
    'Collection':         '#6366f1',
    'C2':                 '#e879f9',
    'Exfiltration':       C.red,
    'Impact':             '#f43f5e',
  };
  const color = colors[tactic] || C.textMuted;
  return (
    <span style={{ color, fontSize: 11, fontFamily: FONTS.ui }}>{tactic}</span>
  );
}

function RuleRow({ rule }) {
  const active = rule.status === 'Active';
  return (
    <tr style={{ borderBottom: `1px solid ${C.border}` }}>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{rule.id}</td>
      <td style={{ padding: '10px 14px', color: C.text, fontSize: 13 }}>{rule.name}</td>
      <td style={{ padding: '10px 14px' }}>
        <span style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono, background: C.surface, border: `1px solid ${C.border}`, padding: '2px 6px', borderRadius: 4 }}>
          {rule.technique}
        </span>
      </td>
      <td style={{ padding: '10px 14px' }}><TacticBadge tactic={rule.tactic} /></td>
      <td style={{ padding: '10px 14px' }}><SeverityBadge sev={rule.severity} /></td>
      <td style={{ padding: '10px 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {active
            ? <CheckCircle size={12} color={C.green} />
            : <XCircle size={12} color={C.textMuted} />}
          <span style={{ color: active ? C.green : C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{rule.status}</span>
        </div>
      </td>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{rule.lastTriggered}</td>
      <td style={{ padding: '10px 14px', color: C.text, fontSize: 11, fontFamily: FONTS.mono }}>
        {rule.triggerCount > 0
          ? <span style={{ color: rule.triggerCount > 50 ? C.amber : C.text }}>{rule.triggerCount}</span>
          : <span style={{ color: C.textDim }}>—</span>}
      </td>
      <td style={{ padding: '10px 14px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{rule.file}</td>
    </tr>
  );
}

function CoverageMatrix() {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden', marginBottom: 20 }}>
      <div style={{ padding: '14px 18px', borderBottom: `1px solid ${C.border}` }}>
        <span style={{ color: C.text, fontWeight: 600, fontSize: 14 }}>MITRE ATT&amp;CK Coverage Matrix</span>
      </div>
      <div style={{ padding: '16px 18px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
          {MITRE_COVERAGE.map(({ tactic, covered, total }) => {
            const pct = Math.round((covered / total) * 100);
            const color = pct >= 60 ? C.green : pct >= 35 ? C.amber : C.red;
            return (
              <div key={tactic} style={{
                background: `${color}11`, border: `1px solid ${color}33`,
                borderRadius: 8, padding: '10px 12px',
              }}>
                <div style={{ color: C.text, fontSize: 11, fontWeight: 600, marginBottom: 4 }}>{tactic}</div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{covered}/{total}</span>
                  <span style={{ color, fontSize: 12, fontWeight: 700, fontFamily: FONTS.mono }}>{pct}%</span>
                </div>
                <div style={{ height: 4, background: C.border, borderRadius: 2, overflow: 'hidden', marginTop: 6 }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2 }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function Rules() {
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');

  const active   = DETECTION_RULES.filter(r => r.status === 'Active').length;
  const disabled = DETECTION_RULES.filter(r => r.status === 'Disabled').length;

  const visible = DETECTION_RULES.filter(r => {
    if (filter !== 'All' && r.severity !== filter) return false;
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) &&
        !r.technique.toLowerCase().includes(search.toLowerCase()) &&
        !r.tactic.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Detection Rules</h1>
        <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4 }}>
          {DETECTION_RULES.length} rules total · {active} active · {disabled} disabled
        </div>
      </div>

      <CoverageMatrix />

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search rules…"
          style={{
            padding: '8px 12px', background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 8, color: C.text, fontSize: 12, fontFamily: FONTS.ui, minHeight: 36, minWidth: 200,
          }}
        />
        {['All','Critical','High','Medium','Low'].map(s => (
          <button key={s} onClick={() => setFilter(s)} style={{
            padding: '6px 12px', border: `1px solid ${filter === s ? C.red : C.border}`,
            background: filter === s ? `${C.red}22` : 'transparent',
            color: filter === s ? C.text : C.textMuted,
            borderRadius: 6, cursor: 'pointer', fontSize: 12, fontFamily: FONTS.ui, minHeight: 36,
          }}>{s}</button>
        ))}
        <span style={{ marginLeft: 'auto', color: C.textMuted, fontSize: 12 }}>{visible.length} rules</span>
      </div>

      {/* Rules table */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 900 }}>
          <thead>
            <tr style={{ background: C.surface }}>
              {['ID','Name','Technique','Tactic','Severity','Status','Last Triggered','Fires (24h)','File'].map(h => (
                <th key={h} style={{
                  padding: '10px 14px', textAlign: 'left', color: C.textMuted,
                  fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
                  borderBottom: `1px solid ${C.border}`, whiteSpace: 'nowrap',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map(rule => <RuleRow key={rule.id} rule={rule} />)}
          </tbody>
        </table>
        {visible.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: C.textMuted, fontSize: 14 }}>
            No rules match the current filter
          </div>
        )}
      </div>
    </div>
  );
}
