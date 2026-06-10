import { useEffect } from 'react';
import { Shield, Activity, Search, FileCheck, BookOpen, ShoppingCart, Link2, X, LogOut, Home } from 'lucide-react';

const NAV_ITEMS = [
  { id:'portal',     icon:Home,         label:'Portal Hub',           desc:'Module overview'  },
  { id:'threat',     icon:Activity,     label:'Threat Detection',     desc:'SOC monitoring',  active:true },
  { id:'vuln',       icon:Search,       label:'Vulnerability Scanner',desc:'Security scan',   active:true },
  { id:'compliance', icon:FileCheck,    label:'Compliance Centre',    desc:'UK frameworks',   active:true },
  { id:'rules',      icon:BookOpen,     label:'Detection Rules',      desc:'KQL + MITRE',     active:true },
  { id:null,         icon:ShoppingCart, label:'Loss Prevention',      desc:'Coming soon',     active:false },
  { id:null,         icon:Link2,        label:'ChainShield',          desc:'Coming soon',     active:false },
];

export default function MobileDrawer({ open, onClose, nav, currentRoute }) {
  /* Trap body scroll while open */
  useEffect(() => {
    if (open) document.body.style.overflow = 'hidden';
    else      document.body.style.overflow = '';
    return () => { document.body.style.overflow = ''; };
  }, [open]);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position:'fixed', inset:0, background:'rgba(0,0,0,0.65)',
          zIndex:299, opacity: open ? 1 : 0, pointerEvents: open ? 'auto' : 'none',
          transition:'opacity 220ms ease',
        }}
        aria-hidden="true"
      />

      {/* Drawer */}
      <nav
        aria-label="Mobile navigation"
        style={{
          position:'fixed', top:0, left:0, height:'100%', width:'280px', maxWidth:'80vw',
          background:'var(--surface)', borderRight:'1px solid var(--border)',
          zIndex:300, display:'flex', flexDirection:'column',
          transform: open ? 'translateX(0)' : 'translateX(-100%)',
          transition:'transform 250ms ease',
          boxShadow: open ? '4px 0 24px rgba(0,0,0,0.6)' : 'none',
          overflowY:'auto',
        }}
      >
        {/* Header */}
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'16px', borderBottom:'1px solid var(--border)', flexShrink:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
            <Shield size={18} color="var(--primary)" strokeWidth={2} />
            <span style={{ fontSize:'14px', fontWeight:700, color:'var(--text)', letterSpacing:'-0.01em' }}>RetailShield</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close navigation"
            style={{ padding:'8px', background:'none', border:'none', color:'var(--text-dim)', cursor:'pointer', borderRadius:'6px', display:'flex', alignItems:'center', justifyContent:'center', minWidth:'44px', minHeight:'44px' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Nav links */}
        <div style={{ flex:1, padding:'8px 0' }}>
          {NAV_ITEMS.map((item, i) => {
            const Icon = item.icon;
            const isCurrent = item.id && item.id === currentRoute;
            const isActive  = item.active !== false;
            return (
              <button
                key={i}
                onClick={() => { if (isActive && item.id) { nav(item.id); onClose(); } }}
                disabled={!isActive || !item.id}
                style={{
                  width:'100%', display:'flex', alignItems:'center', gap:'12px',
                  padding:'10px 16px', background: isCurrent ? 'var(--primary-dim)' : 'none',
                  border:'none', borderLeft: isCurrent ? '3px solid var(--primary)' : '3px solid transparent',
                  cursor: isActive && item.id ? 'pointer' : 'default',
                  opacity: !isActive ? 0.45 : 1,
                  transition:'background var(--t)', minHeight:'44px',
                }}
                onMouseEnter={e => { if (isActive && item.id) e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; }}
                onMouseLeave={e => { if (!isCurrent) e.currentTarget.style.background = 'none'; }}
              >
                <div style={{ width:'32px', height:'32px', borderRadius:'8px', background:'rgba(255,255,255,0.04)', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
                  <Icon size={16} color={isCurrent ? 'var(--primary)' : isActive ? 'var(--text-muted)' : 'var(--text-dim)'} />
                </div>
                <div style={{ textAlign:'left', minWidth:0 }}>
                  <div style={{ fontSize:'13px', fontWeight: isCurrent ? 600 : 500, color: isCurrent ? 'var(--text)' : isActive ? 'var(--text)' : 'var(--text-dim)', lineHeight:1.2 }}>
                    {item.label}
                  </div>
                  <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'1px' }}>
                    {!isActive ? 'Coming soon' : item.desc}
                  </div>
                </div>
              </button>
            );
          })}
        </div>

        {/* Footer */}
        <div style={{ padding:'12px 16px', borderTop:'1px solid var(--border)', flexShrink:0 }}>
          <div style={{ fontSize:'12px', color:'var(--text-dim)', lineHeight:1.5 }}>
            <div style={{ fontWeight:500, color:'var(--text-muted)' }}>Tanvir Farhad</div>
            <div>SOC Analyst · ShieldTech Ltd</div>
          </div>
        </div>
      </nav>
    </>
  );
}
