import { useState } from 'react';
import {
  Shield, Activity, Search, FileCheck, BookOpen,
  ShoppingCart, Link2, LogOut, User, ChevronRight, Clock,
} from 'lucide-react';

const MODULES = [
  {
    id: 'threat',
    icon: Activity,
    name: 'Threat Detection',
    desc: 'Real-time SOC monitoring, incident response, and AI-powered threat analysis.',
    status: 'ACTIVE',
    color: '#DC2626',
  },
  {
    id: 'vuln',
    icon: Search,
    name: 'Vulnerability Scanner',
    desc: 'Web and network security assessment with severity-ranked findings.',
    status: 'ACTIVE',
    color: '#D97706',
  },
  {
    id: 'compliance',
    icon: FileCheck,
    name: 'Compliance Centre',
    desc: 'UK regulatory deadline tracking — ICO, NCSC, PCI DSS, and NIS2.',
    status: 'ACTIVE',
    color: '#16A34A',
  },
  {
    id: 'rules',
    icon: BookOpen,
    name: 'Detection Rules',
    desc: 'KQL rule management, MITRE ATT&CK coverage, and rule performance.',
    status: 'ACTIVE',
    color: '#2563EB',
  },
  {
    id: null,
    icon: ShoppingCart,
    name: 'Loss Prevention',
    desc: 'Financial fraud detection, void/refund abuse patterns, and store risk scoring.',
    status: 'COMING SOON',
    color: '#5A6478',
  },
  {
    id: null,
    icon: Link2,
    name: 'ChainShield',
    desc: 'Supply chain and third-party supplier compromise detection and monitoring.',
    status: 'COMING SOON',
    color: '#5A6478',
  },
];

export default function Portal({ nav, incidents, onSignOut }) {
  const [hoveredMod, setHoveredMod] = useState(null);

  const activeCount = incidents.filter(i => i.status === 'Active').length;
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length;

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>

      {/* Top bar */}
      <header style={{
        position: 'sticky', top: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 32px', height: '60px',
        background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={20} color="var(--primary)" strokeWidth={2} />
          <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em' }}>
            RetailShield
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {activeCount > 0 && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '4px 10px', borderRadius: '20px',
              background: 'var(--accent-dim)', border: '1px solid rgba(220,38,38,0.25)',
            }}>
              <div className="live-dot" style={{ background: 'var(--accent)' }} />
              <span style={{ fontSize: '12px', fontWeight: 600, color: '#F87171' }}>
                {activeCount} Active Incident{activeCount !== 1 ? 's' : ''}
              </span>
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{
              width: '32px', height: '32px', borderRadius: '50%',
              background: 'var(--primary-dim)', border: '1px solid rgba(37,99,235,0.25)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <User size={15} color="var(--primary)" />
            </div>
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text)', lineHeight: 1.2 }}>Tanvir Farhad</div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>SOC Analyst</div>
            </div>
          </div>
          <button
            onClick={onSignOut}
            aria-label="Sign out"
            style={{
              display: 'flex', alignItems: 'center', gap: '5px',
              padding: '6px 12px', borderRadius: 'var(--radius-btn)',
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--text-dim)', fontSize: '12px', cursor: 'pointer',
              transition: 'all var(--transition)',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)'; e.currentTarget.style.borderColor = 'var(--text-dim)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-dim)'; e.currentTarget.style.borderColor = 'var(--border)'; }}
          >
            <LogOut size={13} />
            Sign out
          </button>
        </div>
      </header>

      <main style={{ flex: 1, padding: '48px 32px', maxWidth: '1200px', width: '100%', margin: '0 auto' }}>

        {/* Welcome */}
        <div style={{ marginBottom: '40px' }}>
          <h1 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em', marginBottom: '6px' }}>
            Good day, Tanvir.
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
              {incidents.length} incident{incidents.length !== 1 ? 's' : ''} in view
            </span>
            {criticalCount > 0 && (
              <span style={{ fontSize: '13px', color: '#F87171', fontWeight: 500 }}>
                {criticalCount} critical requiring attention
              </span>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <div className="live-dot" />
              <span style={{ fontSize: '12px', color: 'var(--success)' }}>All systems operational</span>
            </div>
          </div>
        </div>

        {/* Module grid */}
        <div style={{ marginBottom: '16px' }}>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Modules
          </span>
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
          gap: '16px',
        }}>
          {MODULES.map((mod) => {
            const Icon = mod.icon;
            const active = mod.status === 'ACTIVE';
            const hovered = hoveredMod === mod.name;
            return (
              <div
                key={mod.name}
                onClick={() => active && mod.id && nav(mod.id)}
                onMouseEnter={() => setHoveredMod(mod.name)}
                onMouseLeave={() => setHoveredMod(null)}
                role={active ? 'button' : undefined}
                tabIndex={active ? 0 : undefined}
                aria-label={active ? `Open ${mod.name}` : `${mod.name} — coming soon`}
                onKeyDown={e => { if (active && (e.key === 'Enter' || e.key === ' ')) nav(mod.id); }}
                style={{
                  background: hovered && active ? 'var(--card-hover)' : 'var(--card)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-card)',
                  padding: '24px',
                  cursor: active ? 'pointer' : 'default',
                  opacity: active ? 1 : 0.55,
                  transition: 'all var(--transition)',
                  display: 'flex', flexDirection: 'column', gap: '16px',
                  transform: hovered && active ? 'translateY(-2px)' : 'translateY(0)',
                  boxShadow: hovered && active ? 'var(--shadow-md)' : 'none',
                  userSelect: 'none',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                  <div style={{
                    width: '44px', height: '44px', borderRadius: '10px',
                    background: `${mod.color}18`,
                    border: `1px solid ${mod.color}30`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <Icon size={20} color={mod.color} />
                  </div>
                  <span style={{
                    fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
                    padding: '3px 8px', borderRadius: 'var(--radius-badge)',
                    ...(active
                      ? { color: 'var(--success)', background: 'var(--success-dim)', border: '1px solid rgba(22,163,74,0.25)' }
                      : { color: 'var(--text-dim)', background: 'rgba(90,100,120,0.1)', border: '1px solid var(--border)' }
                    ),
                  }}>
                    {mod.status}
                  </span>
                </div>

                <div>
                  <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {mod.name}
                    {active && hovered && <ChevronRight size={14} color="var(--text-dim)" />}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    {mod.desc}
                  </div>
                  {!active && (
                    <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                      <Clock size={12} color="var(--text-dim)" />
                      <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>Coming soon</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </main>

      <footer style={{
        borderTop: '1px solid var(--border)', padding: '16px 32px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>RetailShield · ShieldTech Ltd · Demo environment</span>
        <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>DOI: 10.5281/zenodo.20608262</span>
      </footer>
    </div>
  );
}
