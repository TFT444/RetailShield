import { useState, useEffect, useCallback } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import {
  Activity, AlertTriangle, Shield, Zap, Clock, Globe, Terminal,
  ChevronRight, X, Download, Copy, Check, RefreshCw, FileText,
  Search,
} from 'lucide-react';
import TopBar from '../components/TopBar.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import StatCard from '../components/StatCard.jsx';
import { ATTACK_SIM_EVENTS, MITRE_COVERAGE, DETECTION_RULES } from '../lib/data.js';

const TIMELINE_BASE = [
  { time: '06:00', alerts: 1 }, { time: '06:30', alerts: 0 },
  { time: '07:00', alerts: 2 }, { time: '07:30', alerts: 1 },
  { time: '08:00', alerts: 3 }, { time: '08:30', alerts: 5 },
  { time: '09:00', alerts: 7 }, { time: '09:30', alerts: 4 },
  { time: '10:00', alerts: 2 }, { time: '10:30', alerts: 3 },
  { time: '11:00', alerts: 6 }, { time: '11:30', alerts: 8 },
];

function generateReport(inc, now) {
  if (!inc) return '';
  const detectedTime = inc.detectedAt ? new Date(inc.detectedAt) : now;
  const icoDeadline = new Date(detectedTime.getTime() + 72 * 3600 * 1000);
  const ncscDeadline = new Date(detectedTime.getTime() + 24 * 3600 * 1000);
  const fmt = (d) => d.toLocaleString('en-GB', { timeZone: 'Europe/London', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });

  const sections = [];

  sections.push(`RETAILSHIELD — INCIDENT REPORT`);
  sections.push(`Generated: ${fmt(now)}  |  Classification: CONFIDENTIAL`);
  sections.push(`${'─'.repeat(60)}`);

  sections.push(`\n§1  EXECUTIVE SUMMARY`);
  sections.push(`Incident ID  : ${inc.id}`);
  sections.push(`Title        : ${inc.title}`);
  sections.push(`Severity     : ${inc.severity}`);
  sections.push(`MITRE Tactic : ${inc.tactic} (${inc.technique})`);
  sections.push(`Status       : ${inc.status}`);
  sections.push(`Detected     : ${inc.detectedAt ? fmt(new Date(inc.detectedAt)) : 'During simulation'}`);
  sections.push(`MTTD         : ${inc.mttd} minutes`);
  sections.push(`\n${inc.description}`);

  sections.push(`\n§2  TIMELINE OF EVENTS`);
  (inc.timeline || []).forEach(e => sections.push(`  ${e.time.padEnd(8)} ${e.event}`));

  sections.push(`\n§3  AFFECTED SYSTEMS & DATA`);
  (inc.affectedEntities || []).forEach(e => sections.push(`  • ${e}`));
  if (inc.dataCategories?.length) {
    sections.push(`\nData categories potentially involved:`);
    inc.dataCategories.forEach(d => sections.push(`  • ${d}`));
  }
  sections.push(`\nImpact level: ${inc.impactLevel || 'Under assessment'}`);

  sections.push(`\n§4  TECHNICAL ANALYSIS`);
  sections.push(`Attack technique: ${inc.technique} — ${inc.tactic}`);
  if (inc.sourceIP)    sections.push(`Source IP      : ${inc.sourceIP} (${inc.country || 'Unknown'})`);
  if (inc.sourceEmail) sections.push(`Source email   : ${inc.sourceEmail}`);
  if (inc.deviceName)  sections.push(`Affected device: ${inc.deviceName}`);
  if (inc.failedAttempts) sections.push(`Failed attempts: ${inc.failedAttempts.toLocaleString()}`);
  if (inc.filesModified)  sections.push(`Files modified : ${inc.filesModified.toLocaleString()}`);
  sections.push(`\nAutomated defences activated:`);
  (inc.autoDefence || []).forEach(d => sections.push(`  [+] ${d}`));

  sections.push(`\n§5  REGULATORY NOTIFICATIONS`);
  if (!inc.needsICO && !inc.needsNCSC) {
    sections.push(`No mandatory regulatory notification required based on current assessment.`);
    sections.push(`Reassess if investigation confirms personal data exfiltration or essential service disruption.`);
  }
  if (inc.needsICO) {
    sections.push(`\nICO NOTIFICATION — UK GDPR Article 33 (72-hour obligation)`);
    sections.push(`Deadline     : ${fmt(icoDeadline)}`);
    sections.push(`Portal       : https://ico.org.uk/for-organisations/report-a-breach/`);
    sections.push(`\nDRAFT NOTIFICATION TEXT:`);
    sections.push(`We are writing to notify the ICO of a personal data breach affecting`);
    sections.push(`${inc.dataCategories?.join(', ') || 'personal data'} in connection with incident ${inc.id}.`);
    sections.push(`The breach was detected on ${fmt(detectedTime)}. Immediate containment measures`);
    sections.push(`have been initiated. A full assessment is ongoing. We will provide a`);
    sections.push(`supplementary report within 72 hours of this initial notification.`);
  }
  if (inc.needsNCSC) {
    sections.push(`\nNCSC REPORT — Cyber Security and Resilience Bill 2025 (24-hour obligation)`);
    sections.push(`Deadline     : ${fmt(ncscDeadline)}`);
    sections.push(`Portal       : https://report.ncsc.gov.uk/`);
    sections.push(`\nDRAFT NOTIFICATION TEXT:`);
    sections.push(`We are reporting a significant cyber incident under the Cyber Security and`);
    sections.push(`Resilience Bill 2025. Incident ${inc.id} — "${inc.title}" — was detected on`);
    sections.push(`${fmt(detectedTime)} affecting ${inc.entity || 'critical systems'}.`);
    sections.push(`MITRE ATT&CK technique: ${inc.technique} (${inc.tactic}).`);
    sections.push(`Impact level: ${inc.impactLevel || 'Under assessment'}. Containment in progress.`);
  }

  sections.push(`\n§6  RECOMMENDED ACTIONS`);
  (inc.recommendations || []).forEach((r, i) => sections.push(`  ${i + 1}. ${r}`));

  sections.push(`\n${'─'.repeat(60)}`);
  sections.push(`Report generated by RetailShield · ShieldTech Ltd · Tanvir Farhad`);
  sections.push(`DOI: https://doi.org/10.5281/zenodo.20608262`);

  return sections.join('\n');
}

export default function ThreatDetection({ onBack, incidents, setIncidents }) {
  const [view, setView] = useState('dashboard');
  const [simulating, setSimulating] = useState(false);
  const [selectedInc, setSelectedInc] = useState(null);
  const [reportInc, setReportInc] = useState(null);
  const [reportText, setReportText] = useState('');
  const [generating, setGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [clock, setClock] = useState(new Date());
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const runSimulation = useCallback(() => {
    if (simulating) return;
    setSimulating(true);
    ATTACK_SIM_EVENTS.forEach((evt, i) => {
      setTimeout(() => {
        setIncidents(prev => {
          if (prev.find(x => x.id === evt.id)) return prev;
          return [{ ...evt, detectedAt: new Date().toISOString() }, ...prev];
        });
        if (i === ATTACK_SIM_EVENTS.length - 1) setSimulating(false);
      }, (i + 1) * 800);
    });
  }, [simulating, setIncidents]);

  const handleGenerateReport = () => {
    if (!reportInc) return;
    setGenerating(true);
    setReportText('');
    setTimeout(() => {
      setReportText(generateReport(reportInc, clock));
      setGenerating(false);
    }, 1100);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(reportText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleDownload = () => {
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RetailShield-${reportInc?.id || 'report'}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeCount   = incidents.filter(i => i.status === 'Active').length;
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length;

  const filteredInc = incidents.filter(i => {
    const matchSearch = !searchQuery || i.title.toLowerCase().includes(searchQuery.toLowerCase()) || i.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchSev = severityFilter === 'All' || i.severity === severityFilter;
    return matchSearch && matchSev;
  });

  const timelineData = TIMELINE_BASE.map(d => ({
    ...d,
    alerts: simulating ? d.alerts + Math.floor(Math.random() * 3) : d.alerts,
  }));

  const NAV_TABS = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'incidents', label: `Incidents (${incidents.length})` },
    { id: 'report', label: 'AI Report' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      <TopBar moduleName="Threat Detection" onBack={onBack} />

      {/* Sub-nav */}
      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '0 24px', display: 'flex', gap: '0' }}>
        {NAV_TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => { setView(tab.id); setSelectedInc(null); }}
            style={{
              padding: '12px 16px', background: 'none', border: 'none',
              borderBottom: view === tab.id ? '2px solid var(--primary)' : '2px solid transparent',
              color: view === tab.id ? 'var(--text)' : 'var(--text-muted)',
              fontSize: '13px', fontWeight: view === tab.id ? 600 : 400,
              cursor: 'pointer', transition: 'color var(--transition)',
              marginBottom: '-1px',
            }}
          >
            {tab.label}
          </button>
        ))}

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <div className="live-dot" />
            <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
              {clock.toLocaleTimeString('en-GB')}
            </span>
          </div>
          <button
            onClick={runSimulation}
            disabled={simulating}
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '6px 14px', borderRadius: 'var(--radius-btn)',
              background: simulating ? 'rgba(220,38,38,0.4)' : 'var(--accent)',
              border: 'none', color: 'white', fontSize: '12px', fontWeight: 600,
              cursor: simulating ? 'not-allowed' : 'pointer',
              transition: 'background var(--transition)', minHeight: '32px',
            }}
          >
            <Zap size={13} />
            {simulating ? 'Simulating…' : 'Simulate Attack'}
          </button>
        </div>
      </div>

      <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>

        {/* ── DASHBOARD VIEW ── */}
        {view === 'dashboard' && (
          <div style={{ animation: 'fadeIn 200ms ease', maxWidth: '1400px' }}>

            {/* Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
              <StatCard label="Active Incidents" value={activeCount} sub="requiring attention" accent={activeCount > 0 ? 'var(--accent)' : undefined} icon={AlertTriangle} />
              <StatCard label="Critical Threats" value={criticalCount} sub="this session" accent={criticalCount > 0 ? '#F97316' : undefined} icon={Shield} />
              <StatCard label="Avg MTTD" value="22.5 min" sub="mean time to detect" icon={Clock} />
              <StatCard label="Rules Active" value="19" sub="MITRE ATT&CK mapped" icon={Activity} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>

              {/* Live Feed */}
              <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="live-dot" />
                    <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>Live Threat Feed</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    {incidents.length} events
                  </span>
                </div>
                <div style={{ maxHeight: '340px', overflowY: 'auto' }}>
                  {incidents.length === 0 ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                      No incidents detected
                    </div>
                  ) : incidents.slice(0, 10).map(inc => (
                    <button
                      key={inc.id}
                      onClick={() => { setSelectedInc(inc); setView('incidents'); }}
                      style={{
                        width: '100%', padding: '12px 20px', background: 'none', border: 'none',
                        borderBottom: '1px solid var(--border)', cursor: 'pointer', textAlign: 'left',
                        transition: 'background var(--transition)',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--card-hover)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'none'}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                        <span style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {inc.title}
                        </span>
                        <SeverityBadge severity={inc.severity} />
                      </div>
                      <div style={{ display: 'flex', gap: '12px', marginTop: '4px' }}>
                        <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{inc.id}</span>
                        <StatusBadge status={inc.status} />
                      </div>
                    </button>
                  ))}
                </div>
                {incidents.length > 10 && (
                  <button
                    onClick={() => setView('incidents')}
                    style={{ width: '100%', padding: '10px', background: 'none', border: 'none', borderTop: '1px solid var(--border)', color: 'var(--primary)', fontSize: '12px', cursor: 'pointer', fontWeight: 500 }}
                  >
                    View all {incidents.length} incidents
                  </button>
                )}
              </div>

              {/* MITRE ATT&CK */}
              <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>MITRE ATT&CK Coverage</span>
                </div>
                <div style={{ padding: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  {MITRE_COVERAGE.map(m => {
                    const pct = m.covered / m.total;
                    const color = pct >= 0.6 ? 'var(--success)' : pct >= 0.3 ? 'var(--warning)' : 'var(--accent)';
                    return (
                      <div key={m.tactic} style={{ background: 'var(--surface)', borderRadius: '6px', padding: '10px 12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '130px' }}>
                            {m.tactic}
                          </span>
                          <span style={{ fontSize: '11px', color, fontFamily: 'var(--font-mono)', fontWeight: 600, flexShrink: 0 }}>
                            {m.covered}/{m.total}
                          </span>
                        </div>
                        <div style={{ height: '4px', background: 'var(--border)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct * 100}%`, background: color, borderRadius: '2px', transition: 'width 0.3s ease' }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Timeline chart */}
            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', padding: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)' }}>Alert Timeline — Today</span>
                <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>30-min intervals</span>
              </div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={timelineData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#5A6478' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: '#5A6478' }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: '6px', fontSize: '12px' }}
                    labelStyle={{ color: 'var(--text-muted)' }}
                    itemStyle={{ color: 'var(--primary)' }}
                  />
                  <Bar dataKey="alerts" radius={[3, 3, 0, 0]}>
                    {timelineData.map((d, i) => (
                      <Cell key={i} fill={d.alerts >= 6 ? '#DC2626' : d.alerts >= 4 ? '#D97706' : '#2563EB'} opacity={0.8} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ── INCIDENTS VIEW ── */}
        {view === 'incidents' && (
          <div style={{ animation: 'fadeIn 200ms ease', maxWidth: '1400px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: selectedInc ? '1fr 420px' : '1fr', gap: '16px' }}>

              {/* Table */}
              <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
                {/* Filters */}
                <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                  <div style={{ position: 'relative', flex: 1, minWidth: '180px' }}>
                    <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
                    <input
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                      placeholder="Search incidents…"
                      style={{
                        width: '100%', padding: '7px 10px 7px 32px',
                        background: 'var(--surface)', border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-btn)', color: 'var(--text)', fontSize: '13px', outline: 'none',
                      }}
                    />
                  </div>
                  {['All', 'Critical', 'High', 'Medium', 'Low'].map(s => (
                    <button
                      key={s}
                      onClick={() => setSeverityFilter(s)}
                      style={{
                        padding: '6px 12px', borderRadius: 'var(--radius-btn)', border: '1px solid var(--border)',
                        background: severityFilter === s ? 'var(--primary)' : 'var(--surface)',
                        color: severityFilter === s ? 'white' : 'var(--text-muted)',
                        fontSize: '12px', fontWeight: 500, cursor: 'pointer', transition: 'all var(--transition)',
                      }}
                    >
                      {s}
                    </button>
                  ))}
                </div>

                {/* Table header */}
                <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr 90px 110px 90px', padding: '10px 20px', borderBottom: '1px solid var(--border)', background: 'var(--surface)' }}>
                  {['ID', 'Title', 'Severity', 'Status', 'MTTD'].map(h => (
                    <span key={h} style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>{h}</span>
                  ))}
                </div>

                {filteredInc.length === 0 ? (
                  <div style={{ padding: '48px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                    No incidents match current filters
                  </div>
                ) : filteredInc.map(inc => (
                  <button
                    key={inc.id}
                    onClick={() => setSelectedInc(selectedInc?.id === inc.id ? null : inc)}
                    style={{
                      width: '100%', display: 'grid', gridTemplateColumns: '90px 1fr 90px 110px 90px',
                      padding: '12px 20px', background: selectedInc?.id === inc.id ? 'var(--card-hover)' : 'none',
                      border: 'none', borderBottom: '1px solid var(--border)', cursor: 'pointer',
                      textAlign: 'left', transition: 'background var(--transition)', alignItems: 'center',
                    }}
                    onMouseEnter={e => { if (selectedInc?.id !== inc.id) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                    onMouseLeave={e => { if (selectedInc?.id !== inc.id) e.currentTarget.style.background = 'none'; }}
                  >
                    <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{inc.id}</span>
                    <span style={{ fontSize: '13px', color: 'var(--text)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: '16px' }}>{inc.title}</span>
                    <SeverityBadge severity={inc.severity} />
                    <StatusBadge status={inc.status} />
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{inc.mttd}m</span>
                  </button>
                ))}
              </div>

              {/* Detail panel */}
              {selectedInc && (
                <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden', animation: 'fadeIn 200ms ease', display: 'flex', flexDirection: 'column' }}>
                  <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>{selectedInc.id}</div>
                      <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text)', lineHeight: 1.3 }}>{selectedInc.title}</div>
                    </div>
                    <button onClick={() => setSelectedInc(null)} aria-label="Close detail panel" style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', padding: '4px' }}>
                      <X size={16} />
                    </button>
                  </div>

                  <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <SeverityBadge severity={selectedInc.severity} size="lg" />
                      <StatusBadge status={selectedInc.status} />
                      <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', alignSelf: 'center' }}>
                        {selectedInc.technique}
                      </span>
                    </div>

                    <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.6 }}>{selectedInc.description}</p>

                    <Section title="Timeline">
                      {(selectedInc.timeline || []).map((e, i) => (
                        <div key={i} style={{ display: 'flex', gap: '12px', paddingBottom: '8px' }}>
                          <span style={{ fontSize: '11px', color: 'var(--primary)', fontFamily: 'var(--font-mono)', flexShrink: 0, paddingTop: '1px' }}>{e.time}</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{e.event}</span>
                        </div>
                      ))}
                    </Section>

                    <Section title="Automated Defence">
                      {(selectedInc.autoDefence || []).map((d, i) => (
                        <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}>
                          <Check size={13} color="var(--success)" style={{ flexShrink: 0, marginTop: '2px' }} />
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{d}</span>
                        </div>
                      ))}
                    </Section>

                    <Section title="Recommendations">
                      {(selectedInc.recommendations || []).map((r, i) => (
                        <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '4px' }}>
                          <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', flexShrink: 0, paddingTop: '2px' }}>{i + 1}.</span>
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{r}</span>
                        </div>
                      ))}
                    </Section>

                    {(selectedInc.needsICO || selectedInc.needsNCSC) && (
                      <div style={{ background: 'var(--accent-dim)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: '6px', padding: '12px' }}>
                        <div style={{ fontSize: '12px', fontWeight: 600, color: '#F87171', marginBottom: '6px' }}>Regulatory Notification Required</div>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          {selectedInc.needsICO  && <span style={{ fontSize: '11px', background: 'rgba(220,38,38,0.1)', color: '#F87171', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(220,38,38,0.2)' }}>ICO — 72h deadline</span>}
                          {selectedInc.needsNCSC && <span style={{ fontSize: '11px', background: 'rgba(220,38,38,0.1)', color: '#F87171', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(220,38,38,0.2)' }}>NCSC — 24h deadline</span>}
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => { setReportInc(selectedInc); setView('report'); setReportText(''); }}
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                        padding: '10px', borderRadius: 'var(--radius-btn)', background: 'var(--primary)',
                        border: 'none', color: 'white', fontSize: '13px', fontWeight: 600, cursor: 'pointer',
                        transition: 'background var(--transition)',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--primary-dark)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'var(--primary)'}
                    >
                      <FileText size={14} />
                      Generate AI Report
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── AI REPORT VIEW ── */}
        {view === 'report' && (
          <div style={{ animation: 'fadeIn 200ms ease', maxWidth: '900px' }}>
            <div style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-card)', overflow: 'hidden' }}>
              <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text)', marginBottom: '4px' }}>AI Incident Report Generator</div>
                <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>Generates a structured 6-section report with pre-filled ICO/NCSC draft notifications where required.</div>
              </div>

              <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>Select incident</label>
                  <select
                    value={reportInc?.id || ''}
                    onChange={e => { const inc = incidents.find(i => i.id === e.target.value); setReportInc(inc || null); setReportText(''); }}
                    style={{
                      width: '100%', padding: '8px 12px', background: 'var(--surface)',
                      border: '1px solid var(--border)', borderRadius: 'var(--radius-btn)',
                      color: 'var(--text)', fontSize: '13px', cursor: 'pointer', outline: 'none',
                    }}
                  >
                    <option value="">— choose an incident —</option>
                    {incidents.map(i => <option key={i.id} value={i.id}>{i.id} — {i.title}</option>)}
                  </select>
                </div>
                <button
                  onClick={handleGenerateReport}
                  disabled={!reportInc || generating}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    padding: '9px 18px', borderRadius: 'var(--radius-btn)',
                    background: !reportInc || generating ? 'rgba(37,99,235,0.5)' : 'var(--primary)',
                    border: 'none', color: 'white', fontSize: '13px', fontWeight: 600,
                    cursor: !reportInc || generating ? 'not-allowed' : 'pointer',
                    transition: 'background var(--transition)', minHeight: '38px',
                  }}
                  onMouseEnter={e => { if (reportInc && !generating) e.currentTarget.style.background = 'var(--primary-dark)'; }}
                  onMouseLeave={e => { if (reportInc && !generating) e.currentTarget.style.background = 'var(--primary)'; }}
                >
                  {generating ? <><span style={{ width: '12px', height: '12px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} /> Generating…</> : <><RefreshCw size={13} /> Generate Report</>}
                </button>
              </div>

              {reportText && (
                <>
                  <div style={{ padding: '4px 24px', background: 'var(--surface)', borderBottom: '1px solid var(--border)', display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                    <button
                      onClick={handleCopy}
                      style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '5px 12px', background: 'none', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--text-muted)', fontSize: '12px', cursor: 'pointer', transition: 'all var(--transition)' }}
                      onMouseEnter={e => e.currentTarget.style.color = 'var(--text)'}
                      onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
                    >
                      {copied ? <Check size={13} color="var(--success)" /> : <Copy size={13} />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      onClick={handleDownload}
                      style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '5px 12px', background: 'none', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--text-muted)', fontSize: '12px', cursor: 'pointer', transition: 'all var(--transition)' }}
                      onMouseEnter={e => e.currentTarget.style.color = 'var(--text)'}
                      onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
                    >
                      <Download size={13} /> Download .txt
                    </button>
                  </div>
                  <pre style={{
                    padding: '24px', fontSize: '12px', lineHeight: 1.7, color: 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    maxHeight: '600px', overflowY: 'auto', margin: 0, background: 'var(--surface)',
                    animation: 'fadeIn 300ms ease',
                  }}>
                    {reportText}
                  </pre>
                </>
              )}

              {!reportText && !generating && (
                <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '13px' }}>
                  Select an incident and click Generate Report
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '8px' }}>{title}</div>
      {children}
    </div>
  );
}
