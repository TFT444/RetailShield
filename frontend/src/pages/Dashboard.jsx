import { useState, useEffect } from 'react';
import { C, SEV, FONTS } from '../lib/tokens.js';
import { MITRE_COVERAGE } from '../lib/data.js';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { AlertTriangle, Zap, Clock, Activity, CheckCircle, Cpu, HardDrive, Wifi } from 'lucide-react';

function StatCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 10,
      padding: '18px 20px', flex: 1, minWidth: 150,
      borderTop: `3px solid ${color}`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.ui, textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
          <div style={{ color, fontSize: 32, fontWeight: 700, fontFamily: FONTS.mono, marginTop: 4 }}>{value}</div>
          {sub && <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2 }}>{sub}</div>}
        </div>
        {Icon && <Icon size={20} color={color} style={{ opacity: 0.7 }} />}
      </div>
    </div>
  );
}

function SeverityBadge({ sev }) {
  const s = SEV[sev] || SEV.Info;
  return (
    <span style={{
      background: s.bg, color: s.color, fontSize: 10, fontWeight: 700,
      padding: '2px 7px', borderRadius: 4, fontFamily: FONTS.mono, letterSpacing: 0.5,
    }}>
      {s.label}
    </span>
  );
}

function LiveFeed({ incidents }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
      <div style={{
        padding: '14px 18px', borderBottom: `1px solid ${C.border}`,
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: C.red, animation: 'pulse 1.5s infinite' }} />
        <span style={{ color: C.text, fontWeight: 600, fontSize: 14 }}>Live Threat Feed</span>
        <span style={{ marginLeft: 'auto', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{incidents.length} events</span>
      </div>
      <div style={{ maxHeight: 320, overflowY: 'auto' }}>
        {incidents.slice(0, 10).map((inc, i) => (
          <div key={inc.id} style={{
            padding: '12px 18px', borderBottom: i < 9 ? `1px solid ${C.border}` : 'none',
            display: 'flex', alignItems: 'flex-start', gap: 12,
            background: inc.severity === 'Critical' ? `${C.red}08` : 'transparent',
            transition: 'background 200ms',
          }}>
            <AlertTriangle size={14} color={SEV[inc.severity]?.color || C.textMuted} style={{ marginTop: 2, flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: C.text, fontSize: 13, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {inc.title}
              </div>
              <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2, fontFamily: FONTS.mono }}>
                {inc.id} · {inc.tactic} · {inc.technique}
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
              <SeverityBadge sev={inc.severity} />
              <span style={{ color: C.textDim, fontSize: 10, fontFamily: FONTS.mono }}>
                {inc.detectedAt ? new Date(inc.detectedAt).toLocaleTimeString() : 'just now'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function MitreHeatmap() {
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: `1px solid ${C.border}` }}>
        <span style={{ color: C.text, fontWeight: 600, fontSize: 14 }}>MITRE ATT&amp;CK Coverage</span>
      </div>
      <div style={{ padding: '16px 18px' }}>
        {MITRE_COVERAGE.map(({ tactic, covered, total }) => {
          const pct = Math.round((covered / total) * 100);
          const color = pct >= 60 ? C.green : pct >= 35 ? C.amber : C.red;
          return (
            <div key={tactic} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.ui }}>{tactic}</span>
                <span style={{ color, fontSize: 11, fontFamily: FONTS.mono }}>{covered}/{total}</span>
              </div>
              <div style={{ height: 6, background: C.border, borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 600ms' }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AttackTimelineChart({ incidents }) {
  const hours = Array.from({ length: 24 }, (_, i) => ({ hour: `${String(i).padStart(2,'0')}:00`, count: 0 }));
  incidents.forEach(inc => {
    if (inc.detectedAt) {
      const h = new Date(inc.detectedAt).getHours();
      hours[h].count += 1;
    } else {
      const h = new Date().getHours();
      hours[h].count += 1;
    }
  });

  const COLORS = { 0: C.green, 1: C.amber, 2: C.amber, 3: C.red };
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: `1px solid ${C.border}` }}>
        <span style={{ color: C.text, fontWeight: 600, fontSize: 14 }}>Attack Timeline — Last 24 Hours</span>
      </div>
      <div style={{ padding: '16px 18px' }}>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={hours} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
            <XAxis dataKey="hour" tick={{ fill: C.textMuted, fontSize: 10, fontFamily: FONTS.mono }}
              tickFormatter={v => v.slice(0,2)} interval={3} />
            <YAxis tick={{ fill: C.textMuted, fontSize: 10, fontFamily: FONTS.mono }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6 }}
              labelStyle={{ color: C.text, fontFamily: FONTS.mono, fontSize: 12 }}
              itemStyle={{ color: C.textMuted, fontSize: 12 }}
            />
            <Bar dataKey="count" radius={[3, 3, 0, 0]}>
              {hours.map((h, i) => (
                <Cell key={i} fill={COLORS[Math.min(h.count, 3)] || C.red} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function SystemHealth() {
  const systems = [
    { name: 'SIEM / Log Analytics', status: 'Operational', uptime: '99.98%', icon: Activity },
    { name: 'Endpoint Detection (MDE)', status: 'Operational', uptime: '99.95%', icon: Cpu },
    { name: 'Email Security Gateway', status: 'Operational', uptime: '100%',   icon: CheckCircle },
    { name: 'Network Monitoring',    status: 'Degraded',    uptime: '97.2%',  icon: Wifi },
    { name: 'Backup & Recovery',     status: 'Operational', uptime: '99.91%', icon: HardDrive },
  ];
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: `1px solid ${C.border}` }}>
        <span style={{ color: C.text, fontWeight: 600, fontSize: 14 }}>System Health</span>
      </div>
      <div style={{ padding: '8px 0' }}>
        {systems.map(({ name, status, uptime, icon: Icon }) => {
          const color = status === 'Operational' ? C.green : status === 'Degraded' ? C.amber : C.red;
          return (
            <div key={name} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '10px 18px', borderBottom: `1px solid ${C.border}`,
            }}>
              <Icon size={14} color={color} />
              <span style={{ flex: 1, color: C.text, fontSize: 13 }}>{name}</span>
              <span style={{ color, fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>{status}</span>
              <span style={{ color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono, minWidth: 48, textAlign: 'right' }}>{uptime}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function Dashboard({ incidents, onSimulate, simulating }) {
  const [clock, setClock] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const critical = incidents.filter(i => i.severity === 'Critical').length;
  const high     = incidents.filter(i => i.severity === 'High').length;
  const mttd     = incidents.length ? Math.round(incidents.reduce((a, i) => a + (i.mttd || 5), 0) / incidents.length) : 0;
  const active   = incidents.filter(i => i.status === 'Active' || i.status === 'Investigating').length;

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }`}</style>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Security Operations Centre</h1>
          <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4, fontFamily: FONTS.mono }}>
            {clock.toLocaleDateString('en-GB', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            {' · '}{clock.toLocaleTimeString('en-GB')} GMT
          </div>
        </div>
        <button
          onClick={onSimulate}
          disabled={simulating}
          style={{
            padding: '10px 20px', background: simulating ? C.border : C.red,
            color: '#fff', border: 'none', borderRadius: 8, cursor: simulating ? 'not-allowed' : 'pointer',
            fontSize: 13, fontWeight: 700, fontFamily: FONTS.ui,
            display: 'flex', alignItems: 'center', gap: 8,
            transition: 'background 200ms', minHeight: 44,
            boxShadow: simulating ? 'none' : `0 0 20px ${C.redGlow}`,
          }}
        >
          <Zap size={16} />
          {simulating ? 'SIMULATING…' : 'SIMULATE ATTACK'}
        </button>
      </div>

      {/* Stats bar */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24, flexWrap: 'wrap' }}>
        <StatCard label="Total Incidents Today" value={incidents.length} sub={`${active} active`}        color={C.blue}  icon={AlertTriangle} />
        <StatCard label="Critical"              value={critical}         sub="Immediate response"         color={C.red}   icon={AlertTriangle} />
        <StatCard label="High"                  value={high}             sub="Escalation required"        color='#f97316' icon={AlertTriangle} />
        <StatCard label="MTTD Average"          value={`${mttd}m`}      sub="Mean time to detect"         color={C.green} icon={Clock}        />
        <StatCard label="System Status"         value="97.2%"            sub="Network monitoring degraded" color={C.amber} icon={Activity}     />
      </div>

      {/* Main grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, marginBottom: 16 }}>
        <LiveFeed incidents={incidents} />
        <MitreHeatmap />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>
        <AttackTimelineChart incidents={incidents} />
        <SystemHealth />
      </div>
    </div>
  );
}
