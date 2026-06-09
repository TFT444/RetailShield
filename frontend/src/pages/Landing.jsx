import { useState } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle, ChevronRight, ExternalLink, Menu, X } from 'lucide-react';

const STATS = [
  { value:'19',       label:'Detection Rules',  sub:'MITRE ATT&CK mapped' },
  { value:'22.5 min', label:'Avg MTTD',         sub:'Mean time to detect'  },
  { value:'12',       label:'MITRE Tactics',    sub:'Full kill-chain'      },
  { value:'UK Ready', label:'Compliance',       sub:'ICO · NCSC · PCI DSS' },
];

const STEPS = [
  { icon:Activity,      n:'01', title:'Detect',  desc:'19 production-ready KQL rules monitor your Microsoft Sentinel workspace 24/7 for retail-specific threats — credential stuffing, ransomware, POS malware, and more.' },
  { icon:AlertTriangle, n:'02', title:'Respond', desc:'Automated playbooks isolate endpoints, quarantine emails, and block IPs in seconds. AI-generated incident reports brief your team in plain English.' },
  { icon:CheckCircle,   n:'03', title:'Comply',  desc:'Built-in deadline counters for UK GDPR (ICO 72h), Cyber Security and Resilience Bill (NCSC 24h), PCI DSS, and NIS2 with pre-filled draft notifications.' },
];

export default function Landing({ onDemo, onSignIn }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div style={{ minHeight:'100vh', display:'flex', flexDirection:'column', background:'var(--bg)', overflowX:'hidden' }}>

      {/* ── Nav ── */}
      <nav style={{
        position:'sticky', top:0, zIndex:100,
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 clamp(16px,4vw,48px)', height:'60px',
        background:'rgba(7,11,20,0.92)', backdropFilter:'blur(12px)',
        borderBottom:'1px solid var(--border)',
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
          <Shield size={20} color="var(--primary)" strokeWidth={2} />
          <span style={{ fontSize:'16px', fontWeight:700, color:'var(--text)', letterSpacing:'-0.02em' }}>RetailShield</span>
        </div>

        {/* Desktop nav actions */}
        <div className="rs-hide-mobile" style={{ gap:'8px' }}>
          <button onClick={onSignIn} style={secondaryBtnStyle()}>Sign In</button>
          <button onClick={onDemo}   style={primaryBtnStyle()}>Live Demo</button>
        </div>

        {/* Mobile hamburger */}
        <button
          className="rs-show-mobile"
          onClick={() => setMobileMenuOpen(v => !v)}
          aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
          style={{ padding:'10px', background:'none', border:'none', color:'var(--text)', cursor:'pointer', minWidth:'44px', minHeight:'44px', display:'flex', alignItems:'center', justifyContent:'center', borderRadius:'6px' }}
        >
          {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      {/* Mobile dropdown menu */}
      {mobileMenuOpen && (
        <div style={{ background:'var(--surface)', borderBottom:'1px solid var(--border)', padding:'16px', display:'flex', flexDirection:'column', gap:'10px', zIndex:99 }}>
          <button onClick={() => { setMobileMenuOpen(false); onSignIn(); }} style={{ ...secondaryBtnStyle(), width:'100%', justifyContent:'center', minHeight:'44px' }}>Sign In</button>
          <button onClick={() => { setMobileMenuOpen(false); onDemo(); }}   style={{ ...primaryBtnStyle(),   width:'100%', justifyContent:'center', minHeight:'44px' }}>Explore Live Demo</button>
        </div>
      )}

      {/* ── Hero ── */}
      <section style={{
        display:'flex', flexDirection:'column', alignItems:'center',
        textAlign:'center', padding:'clamp(48px,8vw,96px) clamp(16px,4vw,48px) clamp(48px,6vw,80px)',
        background:'radial-gradient(ellipse 800px 400px at 50% 0%, rgba(37,99,235,0.06) 0%, transparent 70%)',
      }}>
        {/* Live pill */}
        <div style={{
          display:'inline-flex', alignItems:'center', gap:'6px',
          padding:'4px 12px', borderRadius:'20px',
          background:'var(--primary-dim)', border:'1px solid rgba(37,99,235,0.3)',
          marginBottom:'28px',
        }}>
          <span className="live-dot" />
          <span style={{ fontSize:'12px', fontWeight:500, color:'var(--primary)', letterSpacing:'0.03em' }}>Live demo environment</span>
        </div>

        <h1 style={{
          fontSize:'clamp(28px,5vw,54px)', fontWeight:700, lineHeight:1.1,
          color:'var(--text)', maxWidth:'720px', letterSpacing:'-0.03em',
          marginBottom:'18px',
        }}>
          Retail Cyber Defence for{' '}
          <span style={{ color:'var(--primary)' }}>Microsoft Sentinel</span>
        </h1>

        <p style={{ fontSize:'clamp(15px,2vw,18px)', color:'var(--text-muted)', maxWidth:'540px', lineHeight:1.65, marginBottom:'36px' }}>
          19 production-ready KQL detection rules covering the full MITRE ATT&CK kill chain —
          built for UK retail organisations under ICO and NCSC reporting obligations.
        </p>

        <div style={{ display:'flex', gap:'12px', flexWrap:'wrap', justifyContent:'center' }}>
          <button onClick={onDemo}   style={{ ...primaryBtnStyle(),   fontSize:'15px', padding:'12px 28px', minHeight:'48px', gap:'8px' }}>
            Explore Live Demo <ChevronRight size={16} />
          </button>
          <button onClick={onSignIn} style={{ ...secondaryBtnStyle(), fontSize:'15px', padding:'12px 28px', minHeight:'48px' }}>
            Sign In
          </button>
        </div>
      </section>

      {/* ── Stats strip ── */}
      <section style={{ background:'var(--surface)', borderTop:'1px solid var(--border)', borderBottom:'1px solid var(--border)' }}>
        <div style={{ maxWidth:'1100px', margin:'0 auto' }}>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(160px, 1fr))' }}>
            {STATS.map((s, i, arr) => (
              <div key={i} style={{
                padding:'24px 20px', textAlign:'center',
                borderRight: i < arr.length - 1 ? '1px solid var(--border)' : 'none',
              }}>
                <div style={{ fontSize:'clamp(20px,3vw,28px)', fontWeight:700, color:'var(--text)', fontFamily:'var(--font-mono)', letterSpacing:'-0.02em' }}>{s.value}</div>
                <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text-muted)', marginTop:'4px' }}>{s.label}</div>
                <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'2px' }}>{s.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section style={{ padding:'clamp(48px,6vw,80px) clamp(16px,4vw,48px)', width:'100%', maxWidth:'1100px', margin:'0 auto', boxSizing:'border-box' }}>
        <div style={{ textAlign:'center', marginBottom:'48px' }}>
          <div style={{ fontSize:'12px', fontWeight:600, color:'var(--primary)', letterSpacing:'0.1em', textTransform:'uppercase', marginBottom:'10px' }}>How it works</div>
          <h2 style={{ fontSize:'clamp(22px,3vw,32px)', fontWeight:700, color:'var(--text)', letterSpacing:'-0.02em' }}>Detect. Respond. Comply.</h2>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(240px, 1fr))', gap:'20px' }}>
          {STEPS.map((step, i) => {
            const Icon = step.icon;
            return (
              <div key={i} style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', padding:'28px 24px' }}>
                <div style={{ width:'42px', height:'42px', borderRadius:'10px', background:'var(--primary-dim)', border:'1px solid rgba(37,99,235,0.2)', display:'flex', alignItems:'center', justifyContent:'center', marginBottom:'18px' }}>
                  <Icon size={20} color="var(--primary)" />
                </div>
                <div style={{ display:'flex', alignItems:'center', gap:'10px', marginBottom:'10px' }}>
                  <span style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{step.n}</span>
                  <h3 style={{ fontSize:'16px', fontWeight:600, color:'var(--text)' }}>{step.title}</h3>
                </div>
                <p style={{ fontSize:'13px', color:'var(--text-muted)', lineHeight:1.65 }}>{step.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* ── Trust signals ── */}
      <section style={{ background:'var(--surface)', borderTop:'1px solid var(--border)', padding:'clamp(28px,4vw,44px) clamp(16px,4vw,48px)' }}>
        <div style={{ maxWidth:'1100px', margin:'0 auto', display:'flex', alignItems:'center', justifyContent:'center', gap:'clamp(16px,3vw,40px)', flexWrap:'wrap', rowGap:'16px' }}>
          <Trust label="Open source"    sub="MIT licensed"   />
          <Sep /><Trust label="Peer reviewed" sub="Zenodo DOI" link="https://doi.org/10.5281/zenodo.20608262" />
          <Sep /><Trust label="MITRE ATT&CK"  sub="Enterprise framework" />
          <Sep /><Trust label="UK Compliant"  sub="ICO · NCSC · PCI DSS · NIS2" />
        </div>
      </section>

      {/* ── Footer ── */}
      <footer style={{
        borderTop:'1px solid var(--border)', padding:'20px clamp(16px,4vw,48px)',
        display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:'12px',
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:'7px' }}>
          <Shield size={13} color="var(--text-dim)" />
          <span style={{ fontSize:'12px', color:'var(--text-dim)' }}>Tanvir Farhad · ShieldTech Ltd · London</span>
        </div>
        <div style={{ display:'flex', gap:'16px', alignItems:'center', flexWrap:'wrap' }}>
          <a href="https://github.com/TFT444/RetailShield" target="_blank" rel="noopener noreferrer"
            style={{ display:'flex', alignItems:'center', gap:'4px', fontSize:'12px', color:'var(--text-dim)', textDecoration:'none', minHeight:'32px' }}
            onMouseEnter={e => e.currentTarget.style.color='var(--text-muted)'}
            onMouseLeave={e => e.currentTarget.style.color='var(--text-dim)'}
          >
            GitHub <ExternalLink size={11} />
          </a>
          <span style={{ fontSize:'12px', color:'var(--text-dim)' }}>OWASP ref NFRSD-7408</span>
        </div>
      </footer>
    </div>
  );
}

function Trust({ label, sub, link }) {
  const inner = (
    <>
      <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text-muted)' }}>{label}</div>
      <div style={{ fontSize:'11px', color: link ? 'var(--primary)' : 'var(--text-dim)', marginTop:'2px', display:'flex', alignItems:'center', gap:'3px', justifyContent:'center' }}>
        {sub} {link && <ExternalLink size={10} />}
      </div>
    </>
  );
  return link
    ? <a href={link} target="_blank" rel="noopener noreferrer" style={{ textAlign:'center', textDecoration:'none' }}>{inner}</a>
    : <div style={{ textAlign:'center' }}>{inner}</div>;
}
function Sep() {
  return <div style={{ width:'1px', height:'28px', background:'var(--border)', flexShrink:0 }} />;
}

function primaryBtnStyle() {
  return {
    display:'inline-flex', alignItems:'center', gap:'6px',
    padding:'8px 18px', borderRadius:'var(--r-btn)',
    background:'var(--primary)', border:'none',
    color:'white', fontSize:'14px', fontWeight:600,
    cursor:'pointer', transition:'background var(--t)',
    minHeight:'40px', whiteSpace:'nowrap',
  };
}
function secondaryBtnStyle() {
  return {
    display:'inline-flex', alignItems:'center', gap:'6px',
    padding:'8px 18px', borderRadius:'var(--r-btn)',
    background:'transparent', border:'1px solid var(--border)',
    color:'var(--text)', fontSize:'14px', fontWeight:500,
    cursor:'pointer', transition:'all var(--t)',
    minHeight:'40px', whiteSpace:'nowrap',
  };
}
