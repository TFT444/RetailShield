import { useState, useEffect } from 'react';
import { C, FONTS } from './lib/tokens.js';
import { BASELINE_INCIDENTS, ATTACK_SIM_EVENTS } from './lib/data.js';
import Sidebar from './components/Sidebar.jsx';
import Dashboard   from './pages/Dashboard.jsx';
import Incidents   from './pages/Incidents.jsx';
import AIReport    from './pages/AIReport.jsx';
import VulnScanner from './pages/VulnScanner.jsx';
import Compliance  from './pages/Compliance.jsx';
import Rules       from './pages/Rules.jsx';

const STAGGER_MS = 800;

export default function RetailShield() {
  const [page, setPage]             = useState('dashboard');
  const [incidents, setIncidents]   = useState(BASELINE_INCIDENTS);
  const [simulating, setSimulating] = useState(false);
  const [banner, setBanner]         = useState(null);

  function runAttackSimulation() {
    if (simulating) return;
    setSimulating(true);
    const now = new Date();
    ATTACK_SIM_EVENTS.forEach((ev, i) => {
      setTimeout(() => {
        const enriched = { ...ev, detectedAt: new Date(now.getTime() + i * STAGGER_MS).toISOString() };
        setIncidents(prev => {
          if (prev.find(p => p.id === enriched.id)) return prev;
          return [enriched, ...prev];
        });
        if (enriched.severity === 'Critical') {
          setBanner(enriched);
          setTimeout(() => setBanner(null), 6000);
        }
        if (i === ATTACK_SIM_EVENTS.length - 1) {
          setSimulating(false);
        }
      }, i * STAGGER_MS);
    });
  }

  const activeCount = incidents.filter(i => i.status === 'Active' || i.status === 'Investigating').length;

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: C.bg, fontFamily: FONTS.ui }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        body { margin: 0; background: ${C.bg}; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: ${C.borderHi}; }
        select option { background: ${C.surface}; color: ${C.text}; }
        input::placeholder { color: ${C.textDim}; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes slideIn { from { transform: translateX(110%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
      `}</style>

      <Sidebar currentPage={page} onNavigate={setPage} incidentCount={activeCount} />

      <main style={{ flex: 1, padding: '28px 32px', overflowY: 'auto', position: 'relative' }}>
        {banner && (
          <div style={{
            position: 'fixed', top: 16, right: 16, zIndex: 1000,
            background: C.card, border: `1px solid ${C.red}`,
            borderRadius: 10, padding: '14px 18px', maxWidth: 380,
            boxShadow: `0 0 30px ${C.redGlow}`,
            animation: 'slideIn 300ms ease',
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: C.red, marginTop: 4, flexShrink: 0, animation: 'pulse 1s infinite' }} />
              <div>
                <div style={{ color: C.red, fontSize: 10, fontWeight: 700, fontFamily: FONTS.mono, letterSpacing: 1 }}>CRITICAL ALERT</div>
                <div style={{ color: C.text, fontSize: 13, fontWeight: 600, marginTop: 2 }}>{banner.title}</div>
                <div style={{ color: C.textMuted, fontSize: 11, marginTop: 4 }}>{banner.id} · {banner.tactic}</div>
              </div>
            </div>
          </div>
        )}

        {page === 'dashboard'  && <Dashboard   incidents={incidents} onSimulate={runAttackSimulation} simulating={simulating} />}
        {page === 'incidents'  && <Incidents   incidents={incidents} />}
        {page === 'ai-report'  && <AIReport    incidents={incidents} />}
        {page === 'vuln'       && <VulnScanner />}
        {page === 'compliance' && <Compliance  incidents={incidents} />}
        {page === 'rules'      && <Rules />}
      </main>
    </div>
  );
}
