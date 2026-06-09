import { useState } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, ChevronRight, ExternalLink, Search, FileText } from 'lucide-react';

const STATS = [
  { value: '19',       label: 'Detection Rules',    sub: 'MITRE ATT&CK mapped' },
  { value: '22.5 min', label: 'Avg MTTD',           sub: 'Mean time to detect' },
  { value: '12',       label: 'MITRE Tactics',       sub: 'Full kill-chain coverage' },
  { value: 'UK Ready', label: 'Compliance',          sub: 'ICO · NCSC · PCI DSS' },
];

const STEPS = [
  { icon: Activity,      title: 'Detect',  desc: '19 KQL rules continuously monitor your Microsoft Sentinel workspace for retail-specific threat patterns — credential stuffing, ransomware, POS malware, and more.' },
  { icon: AlertTriangle, title: 'Respond', desc: 'Automated playbooks isolate endpoints, quarantine emails, and block IPs within seconds. AI-generated incident reports brief your team in plain English.' },
  { icon: CheckCircle,   title: 'Comply',  desc: 'Built-in deadline trackers for UK GDPR (ICO 72h), Cyber Security and Resilience Bill (NCSC 24h), PCI DSS, and NIS2 — pre-filled draft notifications included.' },
];

export default function Landing({ onDemo, onSignIn }) {
  const [hoveredStep, setHoveredStep] = useState(null);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>

      {/* Nav */}
      <nav style={{
        position: 'sticky', top: 0, zIndex: 100,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 48px', height: '60px',
        background: 'rgba(7,11,20,0.9)', backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={20} color="var(--primary)" strokeWidth={2} />
          <span style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em' }}>
            RetailShield
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            onClick={onSignIn}
            style={{
              padding: '7px 16px', borderRadius: 'var(--radius-btn)',
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--text-muted)', fontSize: '13px', fontWeight: 500,
              cursor: 'pointer', transition: 'all var(--transition)',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--text-dim)'; e.currentTarget.style.color = 'var(--text)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; }}
          >
            Sign In
          </button>
          <button
            onClick={onDemo}
            style={{
              padding: '7px 16px', borderRadius: 'var(--radius-btn)',
              background: 'var(--primary)', border: 'none',
              color: 'white', fontSize: '13px', fontWeight: 600,
              cursor: 'pointer', transition: 'background var(--transition)',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--primary-dark)'}
            onMouseLeave={e => e.currentTarget.style.background = 'var(--primary)'}
          >
            Live Demo
          </button>
        </div>
      </nav>

      {/* Hero */}
      <section style={{
        flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', textAlign: 'center',
        padding: '96px 24px 80px',
        background: 'radial-gradient(ellipse 800px 400px at 50% 0%, rgba(37,99,235,0.06) 0%, transparent 70%)',
      }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          padding: '4px 12px', borderRadius: '20px',
          background: 'var(--primary-dim)', border: '1px solid rgba(37,99,235,0.3)',
          marginBottom: '32px',
        }}>
          <div className="live-dot" />
          <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--primary)', letterSpacing: '0.03em' }}>
            Live demo environment
          </span>
        </div>

        <h1 style={{
          fontSize: 'clamp(32px, 5vw, 56px)', fontWeight: 700, lineHeight: 1.1,
          color: 'var(--text)', maxWidth: '780px', letterSpacing: '-0.03em',
          marginBottom: '20px',
        }}>
          Retail Cyber Defence for{' '}
          <span style={{ color: 'var(--primary)' }}>Microsoft Sentinel</span>
        </h1>

        <p style={{
          fontSize: '18px', color: 'var(--text-muted)', maxWidth: '560px',
          lineHeight: 1.6, marginBottom: '40px',
        }}>
          19 production-ready KQL detection rules covering the full MITRE ATT&CK kill chain —
          built for UK retail organisations operating under ICO and NCSC reporting obligations.
        </p>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center' }}>
          <button
            onClick={onDemo}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '8px',
              padding: '12px 28px', borderRadius: 'var(--radius-btn)',
              background: 'var(--primary)', border: 'none',
              color: 'white', fontSize: '15px', fontWeight: 600,
              cursor: 'pointer', transition: 'background var(--transition)',
              minHeight: '44px',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--primary-dark)'}
            onMouseLeave={e => e.currentTarget.style.background = 'var(--primary)'}
          >
            Explore Live Demo
            <ChevronRight size={16} />
          </button>
          <button
            onClick={onSignIn}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '8px',
              padding: '12px 28px', borderRadius: 'var(--radius-btn)',
              background: 'transparent', border: '1px solid var(--border)',
              color: 'var(--text)', fontSize: '15px', fontWeight: 500,
              cursor: 'pointer', transition: 'all var(--transition)',
              minHeight: '44px',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--text-dim)'; e.currentTarget.style.background = 'var(--card)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'transparent'; }}
          >
            Sign In
          </button>
        </div>
      </section>

      {/* Stats strip */}
      <section style={{
        background: 'var(--surface)', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)',
        padding: '0 48px',
      }}>
        <div style={{
          maxWidth: '1100px', margin: '0 auto',
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        }}>
          {STATS.map((stat, i) => (
            <div key={i} style={{
              padding: '28px 24px', textAlign: 'center',
              borderRight: i < 3 ? '1px solid var(--border)' : 'none',
            }}>
              <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text)', fontFamily: 'var(--font-mono)', letterSpacing: '-0.02em' }}>
                {stat.value}
              </div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', marginTop: '4px' }}>
                {stat.label}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                {stat.sub}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section style={{ padding: '80px 48px', maxWidth: '1100px', margin: '0 auto', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '56px' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--primary)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '12px' }}>
            How it works
          </div>
          <h2 style={{ fontSize: '32px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em' }}>
            Detect. Respond. Comply.
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
          {STEPS.map((step, i) => {
            const Icon = step.icon;
            const hovered = hoveredStep === i;
            return (
              <div
                key={i}
                onMouseEnter={() => setHoveredStep(i)}
                onMouseLeave={() => setHoveredStep(null)}
                style={{
                  background: hovered ? 'var(--card-hover)' : 'var(--card)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-card)', padding: '32px',
                  transition: 'background var(--transition)',
                }}
              >
                <div style={{
                  width: '44px', height: '44px', borderRadius: '10px',
                  background: 'var(--primary-dim)', border: '1px solid rgba(37,99,235,0.2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  marginBottom: '20px',
                }}>
                  <Icon size={20} color="var(--primary)" />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    0{i + 1}
                  </span>
                  <h3 style={{ fontSize: '17px', fontWeight: 600, color: 'var(--text)' }}>
                    {step.title}
                  </h3>
                </div>
                <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  {step.desc}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Trust signals */}
      <section style={{
        background: 'var(--surface)', borderTop: '1px solid var(--border)',
        padding: '48px',
      }}>
        <div style={{ maxWidth: '1100px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '40px', flexWrap: 'wrap' }}>
          <TrustItem label="Open source" sub="MIT licensed" />
          <Divider />
          <TrustItem label="Peer reviewed" sub="Zenodo DOI" link="https://doi.org/10.5281/zenodo.20608262" />
          <Divider />
          <TrustItem label="MITRE ATT&CK" sub="Enterprise framework" />
          <Divider />
          <TrustItem label="UK regulatory" sub="ICO · NCSC · PCI DSS · NIS2" />
        </div>
      </section>

      {/* Footer */}
      <footer style={{
        background: 'var(--bg)', borderTop: '1px solid var(--border)',
        padding: '24px 48px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={15} color="var(--text-dim)" strokeWidth={2} />
          <span style={{ fontSize: '13px', color: 'var(--text-dim)' }}>
            Tanvir Farhad · ShieldTech Ltd · London
          </span>
        </div>
        <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
          <a
            href="https://github.com/TFT444/RetailShield"
            target="_blank" rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px', color: 'var(--text-dim)', textDecoration: 'none' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--text-muted)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-dim)'}
          >
            GitHub <ExternalLink size={11} />
          </a>
          <span style={{ fontSize: '13px', color: 'var(--text-dim)' }}>OWASP ref NFRSD-7408</span>
        </div>
      </footer>
    </div>
  );
}

function TrustItem({ label, sub, link }) {
  return (
    <div style={{ textAlign: 'center' }}>
      {link ? (
        <a href={link} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)' }}>{label}</div>
          <div style={{ fontSize: '11px', color: 'var(--primary)', marginTop: '2px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '3px' }}>
            {sub} <ExternalLink size={10} />
          </div>
        </a>
      ) : (
        <>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)' }}>{label}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>{sub}</div>
        </>
      )}
    </div>
  );
}

function Divider() {
  return <div style={{ width: '1px', height: '32px', background: 'var(--border)' }} />;
}
