import { useState } from 'react';
import {
  Activity, Search, FileCheck, BookOpen,
  ShoppingCart, Link2, LogOut, User, ChevronRight, Clock, Menu,
} from 'lucide-react';
import { useBreakpoint } from '../lib/hooks.js';
import MobileDrawer from '../components/MobileDrawer.jsx';

const MODULES = [
  { id:'threat',     icon:Activity,     name:'Threat Detection',      desc:'Real-time SOC monitoring, incident response, and AI-powered analysis.', color:'#DC2626', active:true  },
  { id:'vuln',       icon:Search,       name:'Vulnerability Scanner', desc:'Web and network security assessment with severity-ranked findings.',      color:'#D97706', active:true  },
  { id:'compliance', icon:FileCheck,    name:'Compliance Centre',     desc:'UK regulatory deadline tracking — ICO, NCSC, PCI DSS, and NIS2.',        color:'#16A34A', active:true  },
  { id:'rules',      icon:BookOpen,     name:'Detection Rules',       desc:'KQL rule management, MITRE ATT&CK coverage, and rule performance.',      color:'#2563EB', active:true  },
  { id:'lp',         icon:ShoppingCart, name:'Loss Prevention',       desc:'Financial fraud detection, void/refund abuse, and store risk scoring.',   color:'#F97316', active:true  },
  { id:null,         icon:Link2,        name:'ChainShield',           desc:'Supply chain and third-party supplier compromise detection.',              color:'#5A6478', active:false },
];

export default function Portal({ nav, incidents, onSignOut }) {
  const [hovered, setHovered]     = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { isMobile } = useBreakpoint();

  const activeCount   = incidents.filter(i => i.status === 'Active').length;
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length;

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex', flexDirection:'column', overflowX:'hidden' }}>

      {/* Top bar */}
      <header style={{
        position:'sticky', top:0, zIndex:100,
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:`0 clamp(14px,3vw,32px)`, height:'56px',
        background:'var(--surface)', borderBottom:'1px solid var(--border)', gap:'12px',
      }}>
        {/* Left */}
        <div style={{ display:'flex', alignItems:'center', gap:'10px', minWidth:0 }}>
          {isMobile && (
            <button onClick={() => setDrawerOpen(true)} aria-label="Open navigation"
              style={{ padding:'8px', background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', minWidth:'44px', minHeight:'44px', display:'flex', alignItems:'center', justifyContent:'center', borderRadius:'6px', flexShrink:0 }}>
              <Menu size={20} />
            </button>
          )}
          <div style={{ display:'flex', alignItems:'center', gap:'7px' }}>
            <img src="/retailshield_logo.png" alt="RetailShield" width="36" style={{ display:'block' }} />
          </div>
        </div>

        {/* Right */}
        <div style={{ display:'flex', alignItems:'center', gap:'10px', flexShrink:0 }}>
          {activeCount > 0 && !isMobile && (
            <div style={{ display:'flex', alignItems:'center', gap:'6px', padding:'4px 10px', borderRadius:'20px', background:'var(--accent-dim)', border:'1px solid rgba(220,38,38,0.25)', whiteSpace:'nowrap' }}>
              <span className="live-dot" style={{ background:'var(--accent)' }} />
              <span style={{ fontSize:'12px', fontWeight:600, color:'#F87171' }}>{activeCount} Active</span>
            </div>
          )}

          {!isMobile && (
            <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
              <div style={{ width:'30px', height:'30px', borderRadius:'50%', background:'var(--primary-dim)', border:'1px solid rgba(37,99,235,0.25)', display:'flex', alignItems:'center', justifyContent:'center' }}>
                <User size={14} color="var(--primary)" />
              </div>
              <div>
                <div style={{ fontSize:'12px', fontWeight:600, color:'var(--text)', lineHeight:1.2 }}>Tanvir Farhad</div>
                <div style={{ fontSize:'10px', color:'var(--text-dim)' }}>SOC Analyst</div>
              </div>
            </div>
          )}

          <button onClick={onSignOut} aria-label="Sign out"
            style={{ display:'flex', alignItems:'center', gap:'5px', padding:'6px 10px', borderRadius:'var(--r-btn)', background:'transparent', border:'1px solid var(--border)', color:'var(--text-dim)', fontSize:'12px', cursor:'pointer', transition:'all var(--t)', minHeight:'36px', whiteSpace:'nowrap' }}
            onMouseEnter={e => { e.currentTarget.style.color='var(--text)'; e.currentTarget.style.borderColor='var(--text-dim)'; }}
            onMouseLeave={e => { e.currentTarget.style.color='var(--text-dim)'; e.currentTarget.style.borderColor='var(--border)'; }}
          >
            <LogOut size={13} />
            {!isMobile && 'Sign out'}
          </button>
        </div>
      </header>

      {/* Content */}
      <main style={{ flex:1, padding:'clamp(20px,4vw,40px) clamp(14px,3vw,32px)', maxWidth:'1200px', width:'100%', margin:'0 auto' }}>

        {/* Welcome */}
        <div style={{ marginBottom:'28px' }}>
          <h1 style={{ fontSize:'clamp(18px,3vw,22px)', fontWeight:700, color:'var(--text)', letterSpacing:'-0.02em', marginBottom:'6px' }}>
            Good day, Tanvir.
          </h1>
          <div style={{ display:'flex', alignItems:'center', gap:'16px', flexWrap:'wrap', rowGap:'6px' }}>
            <span style={{ fontSize:'14px', color:'var(--text-muted)' }}>{incidents.length} incident{incidents.length !== 1 ? 's' : ''} in view</span>
            {criticalCount > 0 && <span style={{ fontSize:'13px', color:'#F87171', fontWeight:500 }}>{criticalCount} critical</span>}
            <div style={{ display:'flex', alignItems:'center', gap:'5px' }}>
              <span className="live-dot" />
              <span style={{ fontSize:'12px', color:'var(--success)' }}>All systems operational</span>
            </div>
          </div>
        </div>

        <div style={{ marginBottom:'12px' }}>
          <span style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.08em' }}>Modules</span>
        </div>

        {/* Module grid — rs-modules handles responsiveness */}
        <div className="rs-modules">
          {MODULES.map((mod) => {
            const Icon = mod.icon;
            const isHovered = hovered === mod.name;
            return (
              <div
                key={mod.name}
                onClick={() => mod.active && mod.id && nav(mod.id)}
                onMouseEnter={() => setHovered(mod.name)}
                onMouseLeave={() => setHovered(null)}
                role={mod.active ? 'button' : undefined}
                tabIndex={mod.active ? 0 : undefined}
                aria-label={mod.active ? `Open ${mod.name}` : `${mod.name} — coming soon`}
                onKeyDown={e => { if (mod.active && mod.id && (e.key === 'Enter' || e.key === ' ')) nav(mod.id); }}
                style={{
                  background: isHovered && mod.active ? 'var(--card-hover)' : 'var(--card)',
                  border:'1px solid var(--border)', borderRadius:'var(--r-card)',
                  padding:'clamp(16px,3vw,22px)',
                  cursor: mod.active ? 'pointer' : 'default',
                  opacity: mod.active ? 1 : 0.5,
                  transition:'all var(--t)',
                  display:'flex', flexDirection:'column', gap:'14px',
                  transform: isHovered && mod.active ? 'translateY(-2px)' : 'none',
                  boxShadow: isHovered && mod.active ? 'var(--shadow-md)' : 'none',
                  userSelect:'none', minHeight:'0',
                }}
              >
                <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:'8px' }}>
                  <div style={{ width:'42px', height:'42px', borderRadius:'10px', background:`${mod.color}18`, border:`1px solid ${mod.color}30`, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
                    <Icon size={19} color={mod.color} />
                  </div>
                  <span style={{
                    fontSize:'10px', fontWeight:700, letterSpacing:'0.08em',
                    padding:'3px 7px', borderRadius:'var(--r-badge)',
                    ...(mod.active
                      ? { color:'var(--success)', background:'var(--success-dim)', border:'1px solid rgba(22,163,74,0.25)' }
                      : { color:'var(--text-dim)', background:'rgba(90,100,120,0.1)', border:'1px solid var(--border)' }),
                  }}>
                    {mod.active ? 'ACTIVE' : 'SOON'}
                  </span>
                </div>
                <div>
                  <div style={{ fontSize:'14px', fontWeight:600, color:'var(--text)', marginBottom:'5px', display:'flex', alignItems:'center', gap:'5px' }}>
                    {mod.name}
                    {mod.active && isHovered && <ChevronRight size={13} color="var(--text-dim)" />}
                  </div>
                  <div style={{ fontSize:'12px', color:'var(--text-muted)', lineHeight:1.5 }}>{mod.desc}</div>
                  {!mod.active && (
                    <div style={{ marginTop:'8px', display:'flex', alignItems:'center', gap:'4px' }}>
                      <Clock size={11} color="var(--text-dim)" />
                      <span style={{ fontSize:'11px', color:'var(--text-dim)' }}>Coming soon</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </main>

      <footer style={{ borderTop:'1px solid var(--border)', padding:'14px clamp(14px,3vw,32px)', display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:'8px' }}>
        <span style={{ fontSize:'11px', color:'var(--text-dim)' }}>RetailShield · ShieldTech Ltd · Demo environment</span>
        <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>DOI: 10.5281/zenodo.20608262</span>
      </footer>

      <MobileDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} nav={nav} currentRoute="portal" />
    </div>
  );
}
