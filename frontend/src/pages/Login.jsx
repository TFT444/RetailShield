import { useState } from 'react';
import { Shield, Eye, EyeOff } from 'lucide-react';

export default function Login({ onSuccess, onDemo }) {
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [showPw,   setShowPw]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [eFocus,   setEFocus]   = useState(false);
  const [pFocus,   setPFocus]   = useState(false);

  const submit = (e) => {
    e.preventDefault();
    if (!email.trim())  { setError('Email address is required.'); return; }
    if (!password)      { setError('Password is required.');      return; }
    setError(''); setLoading(true);
    setTimeout(onSuccess, 950);
  };

  const inp = (focused) => ({
    width:'100%', padding:'11px 14px',
    background:'var(--bg)', border:`1px solid ${focused ? 'var(--primary)' : 'var(--border)'}`,
    borderRadius:'var(--r-btn)', color:'var(--text)', fontSize:'16px', outline:'none',
    transition:'border-color var(--t)',
    boxShadow: focused ? '0 0 0 3px rgba(37,99,235,0.1)' : 'none',
  });

  return (
    <div style={{
      minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center',
      background:'var(--bg)', padding:'24px', overflowX:'hidden',
    }}>
      <div style={{ position:'fixed', inset:0, pointerEvents:'none', background:'radial-gradient(ellipse 600px 400px at 50% 20%, rgba(37,99,235,0.04) 0%, transparent 70%)' }} />

      <div style={{ width:'100%', maxWidth:'400px', position:'relative', animation:'fadeIn 250ms ease' }}>
        <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', padding:'clamp(24px,5vw,40px) clamp(20px,5vw,36px)', boxShadow:'var(--shadow-lg)' }}>

          {/* Logo */}
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:'8px', marginBottom:'28px' }}>
            <div style={{ width:'48px', height:'48px', borderRadius:'12px', background:'var(--primary-dim)', border:'1px solid rgba(37,99,235,0.25)', display:'flex', alignItems:'center', justifyContent:'center' }}>
              <Shield size={24} color="var(--primary)" strokeWidth={2} />
            </div>
            <div style={{ textAlign:'center' }}>
              <div style={{ fontSize:'18px', fontWeight:700, color:'var(--text)', letterSpacing:'-0.02em' }}>RetailShield</div>
              <div style={{ fontSize:'12px', color:'var(--text-dim)', marginTop:'2px' }}>ShieldTech Ltd · SOC Platform</div>
            </div>
          </div>

          <h1 style={{ fontSize:'15px', fontWeight:600, color:'var(--text)', marginBottom:'20px', textAlign:'center' }}>
            Sign in to your workspace
          </h1>

          {error && (
            <div style={{ background:'var(--accent-dim)', border:'1px solid rgba(220,38,38,0.3)', borderRadius:'var(--r-badge)', padding:'10px 14px', fontSize:'14px', color:'#F87171', marginBottom:'16px' }}>
              {error}
            </div>
          )}

          <form onSubmit={submit} noValidate style={{ display:'flex', flexDirection:'column', gap:'16px' }}>
            <div>
              <label style={{ display:'block', fontSize:'13px', fontWeight:500, color:'var(--text-muted)', marginBottom:'6px' }}>Work email</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                onFocus={() => setEFocus(true)} onBlur={() => setEFocus(false)}
                placeholder="you@organisation.co.uk" autoComplete="email"
                style={inp(eFocus)} />
            </div>
            <div>
              <label style={{ display:'block', fontSize:'13px', fontWeight:500, color:'var(--text-muted)', marginBottom:'6px' }}>Password</label>
              <div style={{ position:'relative' }}>
                <input type={showPw ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  onFocus={() => setPFocus(true)} onBlur={() => setPFocus(false)}
                  placeholder="••••••••••••" autoComplete="current-password"
                  style={{ ...inp(pFocus), paddingRight:'48px' }} />
                <button type="button" onClick={() => setShowPw(v => !v)} aria-label={showPw ? 'Hide password' : 'Show password'}
                  style={{ position:'absolute', right:0, top:0, height:'100%', padding:'0 14px', background:'none', border:'none', color:'var(--text-dim)', cursor:'pointer', display:'flex', alignItems:'center', minWidth:'44px' }}>
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button type="submit" disabled={loading}
              style={{
                marginTop:'4px', padding:'12px', borderRadius:'var(--r-btn)',
                background: loading ? 'rgba(37,99,235,0.6)' : 'var(--primary)',
                border:'none', color:'white', fontSize:'15px', fontWeight:600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition:'background var(--t)',
                display:'flex', alignItems:'center', justifyContent:'center', gap:'8px',
                minHeight:'48px',
              }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.background='var(--primary-dk)'; }}
              onMouseLeave={e => { if (!loading) e.currentTarget.style.background='var(--primary)'; }}
            >
              {loading
                ? <><span style={{ width:'15px', height:'15px', border:'2px solid rgba(255,255,255,0.3)', borderTopColor:'white', borderRadius:'50%', animation:'spin 0.7s linear infinite', display:'inline-block' }} /> Signing in…</>
                : 'Sign In'}
            </button>
          </form>

          <div style={{ marginTop:'20px', textAlign:'center' }}>
            <button onClick={onDemo} style={{ background:'none', border:'none', padding:'8px', color:'var(--primary)', fontSize:'14px', cursor:'pointer', textDecoration:'underline', textDecorationColor:'rgba(37,99,235,0.4)', minHeight:'40px' }}>
              Explore demo instead
            </button>
          </div>
        </div>
        <p style={{ textAlign:'center', marginTop:'14px', fontSize:'12px', color:'var(--text-dim)' }}>
          Demo environment — no real authentication
        </p>
      </div>
    </div>
  );
}
