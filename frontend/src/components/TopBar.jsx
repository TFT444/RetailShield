import { Shield, ArrowLeft } from 'lucide-react';

export default function TopBar({ moduleName, onBack }) {
  return (
    <header style={{
      position: 'sticky', top: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 24px', height: '56px',
      background: 'var(--surface)', borderBottom: '1px solid var(--border)',
      boxShadow: '0 1px 0 var(--border)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={18} color="var(--primary)" strokeWidth={2} />
          <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.01em' }}>
            RetailShield
          </span>
        </div>
        <span style={{ color: 'var(--border)', fontSize: '14px' }}>/</span>
        <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--text-muted)' }}>
          {moduleName}
        </span>
      </div>
      <button
        onClick={onBack}
        aria-label="Back to portal"
        style={{
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '6px 12px', borderRadius: 'var(--radius-btn)',
          background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--text-muted)', fontSize: '13px', fontWeight: 500,
          cursor: 'pointer', transition: 'all var(--transition)',
        }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--text-dim)'; e.currentTarget.style.color = 'var(--text)'; }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; }}
      >
        <ArrowLeft size={14} />
        Back to Portal
      </button>
    </header>
  );
}
