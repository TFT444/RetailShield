import { useState } from 'react';
import { Shield, ArrowLeft, Menu } from 'lucide-react';
import { useBreakpoint } from '../lib/hooks.js';
import MobileDrawer from './MobileDrawer.jsx';

export default function TopBar({ moduleName, onBack, nav, currentRoute }) {
  const { isMobile } = useBreakpoint();
  const [drawerOpen, setDrawerOpen] = useState(false);

  return (
    <>
      <header style={{
        position:'sticky', top:0, zIndex:100,
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 16px', height:'52px',
        background:'var(--surface)', borderBottom:'1px solid var(--border)',
        gap:'12px', flexShrink:0,
      }}>
        {/* Left */}
        <div style={{ display:'flex', alignItems:'center', gap:'10px', minWidth:0 }}>
          {isMobile ? (
            <button
              onClick={() => setDrawerOpen(true)}
              aria-label="Open navigation menu"
              style={{ padding:'8px', background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', display:'flex', alignItems:'center', minWidth:'44px', minHeight:'44px', justifyContent:'center', borderRadius:'6px', flexShrink:0 }}
            >
              <Menu size={20} />
            </button>
          ) : (
            <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
              <Shield size={17} color="var(--primary)" strokeWidth={2} />
              <span style={{ fontSize:'13px', fontWeight:700, color:'var(--text)', letterSpacing:'-0.01em' }}>RetailShield</span>
              <span style={{ color:'var(--border)', fontSize:'13px' }}>/</span>
            </div>
          )}
          <span style={{
            fontSize: isMobile ? '14px' : '13px',
            fontWeight:600, color:'var(--text)',
            overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
          }}>
            {moduleName}
          </span>
        </div>

        {/* Back button */}
        <button
          onClick={onBack}
          aria-label="Back to portal"
          style={{
            display:'flex', alignItems:'center', gap:'5px',
            padding:'6px 12px', borderRadius:'var(--r-btn)',
            background:'transparent', border:'1px solid var(--border)',
            color:'var(--text-muted)', fontSize:'13px', fontWeight:500,
            cursor:'pointer', transition:'all var(--t)',
            minHeight:'36px', flexShrink:0, whiteSpace:'nowrap',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor='var(--text-dim)'; e.currentTarget.style.color='var(--text)'; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)';   e.currentTarget.style.color='var(--text-muted)'; }}
        >
          <ArrowLeft size={13} />
          {!isMobile && 'Back to Portal'}
        </button>
      </header>

      <MobileDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        nav={nav || (() => {})}
        currentRoute={currentRoute || ''}
      />
    </>
  );
}
