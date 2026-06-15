import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

export default function StatCard({ label, value, sub, accent, icon: Icon, breakdown, breakdownSource }) {
  const [open, setOpen] = useState(false);
  const hasBreakdown = breakdown?.length > 0;

  return (
    <div style={{
      background:'var(--card)', border:'1px solid var(--border)',
      borderRadius:'var(--r-card)', padding:'18px 20px',
      display:'flex', flexDirection:'column', gap:'4px',
      borderLeft: accent ? `3px solid ${accent}` : undefined,
      minWidth:0,
    }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:'8px' }}>
        <span style={{ fontSize:'11px', fontWeight:600, color:'var(--text-muted)', textTransform:'uppercase', letterSpacing:'0.07em', lineHeight:1.3 }}>
          {label}
        </span>
        {Icon && <Icon size={14} color="var(--text-dim)" style={{ flexShrink:0 }} />}
      </div>
      <div style={{ fontSize:'26px', fontWeight:700, color: accent || 'var(--text)', fontFamily:'var(--font-mono)', lineHeight:1.1, wordBreak:'break-all' }}>
        {value}
      </div>
      {sub && <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'1px' }}>{sub}</div>}
      {hasBreakdown && (
        <>
          <button
            onClick={() => setOpen(v => !v)}
            style={{ display:'flex', alignItems:'center', gap:'3px', background:'none', border:'none', padding:'4px 0 0', color:'var(--primary)', fontSize:'11px', fontWeight:500, cursor:'pointer', marginTop:'2px', width:'fit-content' }}
          >
            <ChevronDown size={11} style={{ transform: open ? 'rotate(180deg)' : 'none', transition:'transform 0.15s ease' }} />
            {open ? 'Hide breakdown' : 'View breakdown'}
          </button>
          {open && (
            <div style={{ marginTop:'6px', borderTop:'1px solid var(--border)', paddingTop:'8px', animation:'fadeIn 150ms ease' }}>
              {breakdown.map(row => (
                <div key={row.label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'3px 0', borderBottom:'1px solid rgba(255,255,255,0.04)' }}>
                  <span style={{ fontSize:'11px', color:'var(--text-muted)' }}>{row.label}</span>
                  <span style={{ fontSize:'12px', fontWeight:600, color:'var(--text)', fontFamily:'var(--font-mono)' }}>{row.value}</span>
                </div>
              ))}
              {breakdownSource && (
                <div style={{ fontSize:'10px', color:'var(--text-dim)', marginTop:'7px', lineHeight:1.5 }}>{breakdownSource}</div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
