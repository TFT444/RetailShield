import { useState } from 'react';
import { Search, Filter } from 'lucide-react';
import TopBar from '../components/TopBar.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import StatCard from '../components/StatCard.jsx';
import { DETECTION_RULES, MITRE_COVERAGE } from '../lib/data.js';

const TACTIC_COLORS = {
  'Initial Access':       '#DC2626',
  'Execution':            '#D97706',
  'Persistence':          '#D97706',
  'Privilege Escalation': '#F97316',
  'Defence Evasion':      '#8B5CF6',
  'Credential Access':    '#EC4899',
  'Discovery':            '#0891B2',
  'Lateral Movement':     '#EF4444',
  'Collection':           '#6366F1',
  'C2':                   '#DC2626',
  'Exfiltration':         '#DC2626',
  'Impact':               '#DC2626',
};

export default function DetectionRules({ onBack }) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');

  const activeRules   = DETECTION_RULES.filter(r => r.status === 'Active').length;
  const disabledRules = DETECTION_RULES.filter(r => r.status === 'Disabled').length;
  const criticalRules = DETECTION_RULES.filter(r => r.severity === 'Critical').length;
  const totalTriggers = DETECTION_RULES.reduce((s, r) => s + r.triggerCount, 0);

  const filtered = DETECTION_RULES.filter(r => {
    const q = search.toLowerCase();
    const matchSearch = !search || r.name.toLowerCase().includes(q) || r.technique.toLowerCase().includes(q) || r.tactic.toLowerCase().includes(q);
    const matchSev    = sevFilter === 'All' || r.severity === sevFilter;
    const matchStatus = statusFilter === 'All' || r.status === statusFilter;
    return matchSearch && matchSev && matchStatus;
  });

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      <TopBar moduleName="Detection Rules" onBack={onBack} />

      <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
        <div style={{ maxWidth: '1300px', display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fadeIn 200ms ease' }}>

          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
            <StatCard label="Active Rules"    value={activeRules}   sub="running in Sentinel" accent="var(--success)" />
            <StatCard label="Critical Rules"  value={criticalRules} sub="highest severity"     accent="var(--accent)" />
            <StatCard label="Disabled"        value={disabledRules} sub="pending review"       />
            <StatCard label="Total Triggers"  value={totalTriggers} sub="events this session"  accent="var(--primary)" />
          </div>

          {/* MITRE coverage matrix */}
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>MITRE ATT&CK Coverage Matrix</span>
                <span style={{ fontSize: '12px', color: 'var(--text-dim)', marginLeft: '12px' }}>12 of 12 tactics covered</span>
              </div>
              <div style={{ display: 'flex', gap: '16px', fontSize: '11px', color: 'var(--text-dim)' }}>
                <LegendItem color="var(--success)"  label="≥60%" />
                <LegendItem color="var(--warning)"  label="30–59%" />
                <LegendItem color="var(--accent)"   label="<30%" />
              </div>
            </div>
            <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
              {MITRE_COVERAGE.map(m => {
                const pct = m.covered / m.total;
                const color = pct >= 0.6 ? 'var(--success)' : pct >= 0.3 ? 'var(--warning)' : 'var(--accent)';
                return (
                  <div key={m.tactic} style={{
                    background: 'var(--surface)', borderRadius: '8px', padding: '12px',
                    borderLeft: `3px solid ${color}`,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text)', lineHeight: 1.2 }}>
                        {m.tactic}
                      </span>
                      <span style={{ fontSize: '13px', fontWeight: 700, color, fontFamily: 'var(--font-mono)', flexShrink: 0, marginLeft: '8px' }}>
                        {m.covered}/{m.total}
                      </span>
                    </div>
                    <div style={{ height: '4px', background: 'var(--border)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${pct * 100}%`, background: color, borderRadius: '2px' }} />
                    </div>
                    <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '5px' }}>
                      {Math.round(pct * 100)}% technique coverage
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Rules table */}
          <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
            {/* Filters */}
            <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
                <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search by name, technique, tactic…"
                  style={{
                    width: '100%', padding: '7px 10px 7px 32px',
                    background: 'var(--surface)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-btn)', color: 'var(--text)', fontSize: '13px', outline: 'none',
                  }}
                />
              </div>
              <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                {['All', 'Critical', 'High', 'Medium'].map(s => (
                  <FilterBtn key={s} label={s} active={sevFilter === s} onClick={() => setSevFilter(s)} />
                ))}
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                {['All', 'Active', 'Disabled'].map(s => (
                  <FilterBtn key={s} label={s} active={statusFilter === s} onClick={() => setStatusFilter(s)} />
                ))}
              </div>
              <span style={{ fontSize: '12px', color: 'var(--text-dim)', marginLeft: 'auto', flexShrink: 0 }}>
                {filtered.length} / {DETECTION_RULES.length} rules
              </span>
            </div>

            {/* Table header */}
            <div style={{
              display: 'grid', gridTemplateColumns: '70px 1fr 110px 140px 80px 100px 80px',
              padding: '10px 20px', background: 'var(--surface)', borderBottom: '1px solid var(--border)',
            }}>
              {['ID', 'Rule Name', 'Technique', 'Tactic', 'Severity', 'Last Trigger', 'Hits'].map(h => (
                <span key={h} style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{h}</span>
              ))}
            </div>

            {filtered.length === 0 ? (
              <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                No rules match current filters
              </div>
            ) : filtered.map((rule, idx) => {
              const tacticColor = TACTIC_COLORS[rule.tactic] || 'var(--text-dim)';
              return (
                <div
                  key={rule.id}
                  style={{
                    display: 'grid', gridTemplateColumns: '70px 1fr 110px 140px 80px 100px 80px',
                    padding: '11px 20px', borderBottom: idx < filtered.length - 1 ? '1px solid var(--border)' : 'none',
                    alignItems: 'center', opacity: rule.status === 'Disabled' ? 0.55 : 1,
                    transition: 'background var(--transition)',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{rule.id}</span>
                  <span style={{ fontSize: '13px', color: 'var(--text)', fontWeight: 500, paddingRight: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rule.name}</span>
                  <span style={{ fontSize: '11px', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>{rule.technique}</span>
                  <div>
                    <span style={{
                      fontSize: '11px', fontWeight: 500, color: tacticColor,
                      background: `${tacticColor}15`, padding: '2px 7px',
                      borderRadius: '4px', border: `1px solid ${tacticColor}30`,
                      whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'inline-block', maxWidth: '130px',
                    }}>
                      {rule.tactic}
                    </span>
                  </div>
                  <SeverityBadge severity={rule.severity} />
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{rule.lastTriggered}</span>
                  <span style={{ fontSize: '13px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {rule.triggerCount > 0 ? rule.triggerCount : <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}>—</span>}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterBtn({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '5px 11px', borderRadius: 'var(--radius-btn)',
        border: '1px solid var(--border)',
        background: active ? 'var(--primary)' : 'var(--surface)',
        color: active ? 'white' : 'var(--text-muted)',
        fontSize: '12px', fontWeight: active ? 600 : 400, cursor: 'pointer',
        transition: 'all var(--transition)',
      }}
    >
      {label}
    </button>
  );
}

function LegendItem({ color, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
      <div style={{ width: '10px', height: '10px', borderRadius: '2px', background: color }} />
      <span>{label}</span>
    </div>
  );
}
