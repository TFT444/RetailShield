export default function StatCard({ label, value, sub, accent, icon: Icon }) {
  return (
    <div style={{
      background: 'var(--card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-card)', padding: '20px 24px',
      display: 'flex', flexDirection: 'column', gap: '4px',
      borderLeft: accent ? `3px solid ${accent}` : undefined,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          {label}
        </span>
        {Icon && <Icon size={15} color="var(--text-dim)" />}
      </div>
      <div style={{ fontSize: '28px', fontWeight: 700, color: accent || 'var(--text)', fontFamily: 'var(--font-mono)', lineHeight: 1.2 }}>
        {value}
      </div>
      {sub && <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{sub}</div>}
    </div>
  );
}
