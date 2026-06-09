import { useState } from 'react';
import { Shield, Eye, EyeOff } from 'lucide-react';

export default function Login({ onSuccess, onDemo }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [emailFocus, setEmailFocus] = useState(false);
  const [pwFocus, setPwFocus] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email.trim()) { setError('Email address is required.'); return; }
    if (!password) { setError('Password is required.'); return; }
    setError('');
    setLoading(true);
    setTimeout(onSuccess, 900);
  };

  const inputStyle = (focused) => ({
    width: '100%', padding: '11px 14px',
    background: 'var(--bg)', border: `1px solid ${focused ? 'var(--primary)' : 'var(--border)'}`,
    borderRadius: 'var(--radius-btn)', color: 'var(--text)',
    fontSize: '14px', outline: 'none',
    transition: 'border-color var(--transition)',
    boxShadow: focused ? '0 0 0 3px rgba(37,99,235,0.1)' : 'none',
  });

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg)', padding: '24px',
    }}>
      {/* Background glow */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 600px 400px at 50% 20%, rgba(37,99,235,0.04) 0%, transparent 70%)',
      }} />

      <div style={{
        width: '100%', maxWidth: '400px', position: 'relative',
        animation: 'fadeIn 250ms ease',
      }}>
        {/* Card */}
        <div style={{
          background: 'var(--card)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-card)', padding: '40px 36px',
          boxShadow: 'var(--shadow-lg)',
        }}>
          {/* Logo */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', marginBottom: '32px' }}>
            <div style={{
              width: '48px', height: '48px', borderRadius: '12px',
              background: 'var(--primary-dim)', border: '1px solid rgba(37,99,235,0.25)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={24} color="var(--primary)" strokeWidth={2} />
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text)', letterSpacing: '-0.02em' }}>
                RetailShield
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '2px' }}>
                ShieldTech Ltd · SOC Platform
              </div>
            </div>
          </div>

          <h1 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text)', marginBottom: '24px', textAlign: 'center' }}>
            Sign in to your workspace
          </h1>

          {error && (
            <div style={{
              background: 'var(--accent-dim)', border: '1px solid rgba(220,38,38,0.3)',
              borderRadius: 'var(--radius-badge)', padding: '10px 14px',
              fontSize: '13px', color: '#F87171', marginBottom: '16px',
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Work email
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onFocus={() => setEmailFocus(true)}
                onBlur={() => setEmailFocus(false)}
                placeholder="you@organisation.co.uk"
                autoComplete="email"
                style={inputStyle(emailFocus)}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: 'var(--text-muted)', marginBottom: '6px' }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onFocus={() => setPwFocus(true)}
                  onBlur={() => setPwFocus(false)}
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  style={{ ...inputStyle(pwFocus), paddingRight: '44px' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  style={{
                    position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', padding: '4px',
                    color: 'var(--text-dim)', cursor: 'pointer', display: 'flex', alignItems: 'center',
                  }}
                >
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                marginTop: '4px', padding: '11px', borderRadius: 'var(--radius-btn)',
                background: loading ? 'rgba(37,99,235,0.6)' : 'var(--primary)',
                border: 'none', color: 'white', fontSize: '14px', fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'background var(--transition)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                minHeight: '44px',
              }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.background = 'var(--primary-dark)'; }}
              onMouseLeave={e => { if (!loading) e.currentTarget.style.background = 'var(--primary)'; }}
            >
              {loading ? (
                <>
                  <span style={{ width: '14px', height: '14px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} />
                  Signing in…
                </>
              ) : 'Sign In'}
            </button>
          </form>

          <div style={{ marginTop: '24px', textAlign: 'center' }}>
            <button
              onClick={onDemo}
              style={{
                background: 'none', border: 'none', padding: '4px 8px',
                color: 'var(--primary)', fontSize: '13px', cursor: 'pointer',
                textDecoration: 'underline', textDecorationColor: 'rgba(37,99,235,0.4)',
              }}
            >
              Explore demo instead
            </button>
          </div>
        </div>

        <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '12px', color: 'var(--text-dim)' }}>
          Demo environment — no real authentication
        </p>
      </div>
    </div>
  );
}
