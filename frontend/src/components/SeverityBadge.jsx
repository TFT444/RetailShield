const SEV_STYLES = {
  Critical: { color: '#DC2626', bg: 'rgba(220,38,38,0.12)', border: 'rgba(220,38,38,0.3)' },
  High:     { color: '#F97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  Medium:   { color: '#D97706', bg: 'rgba(217,119,6,0.12)',  border: 'rgba(217,119,6,0.3)' },
  Low:      { color: '#16A34A', bg: 'rgba(22,163,74,0.12)', border: 'rgba(22,163,74,0.3)' },
  Info:     { color: '#0891B2', bg: 'rgba(8,145,178,0.12)', border: 'rgba(8,145,178,0.3)' },
};

export default function SeverityBadge({ severity, size = 'sm' }) {
  const s = SEV_STYLES[severity] || SEV_STYLES.Info;
  const pad = size === 'lg' ? '4px 12px' : '2px 8px';
  const fs  = size === 'lg' ? '12px' : '11px';
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: pad, borderRadius: 'var(--radius-badge)',
      fontSize: fs, fontWeight: 600, letterSpacing: '0.05em',
      fontFamily: 'var(--font-ui)',
      color: s.color, background: s.bg,
      border: `1px solid ${s.border}`,
      whiteSpace: 'nowrap',
    }}>
      {severity?.toUpperCase()}
    </span>
  );
}
