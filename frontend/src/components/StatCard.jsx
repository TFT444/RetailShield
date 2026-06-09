export default function StatCard({ label, value, sub, accent, icon: Icon }) {
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
    </div>
  );
}
