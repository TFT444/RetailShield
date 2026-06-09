import { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, ChevronDown, ChevronUp } from 'lucide-react';
import TopBar      from '../components/TopBar.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { COMPLIANCE_REGULATIONS, SUBMISSION_HISTORY } from '../lib/data.js';

function useCountdown(targetIso) {
  const [rem, setRem]     = useState('');
  const [expired, setExp] = useState(false);
  useEffect(() => {
    if (!targetIso) return;
    const tick = () => {
      const diff = new Date(targetIso) - Date.now();
      if (diff <= 0) { setRem('EXPIRED'); setExp(true); return; }
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setRem(`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`);
      setExp(false);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [targetIso]);
  return { rem, expired };
}

const REG_DETAIL = {
  GDPR:'UK GDPR Article 33 requires controllers to notify the ICO within 72 hours of becoming aware of a personal data breach, where feasible. Article 34 may also require notifying affected data subjects.',
  CSR: 'The Cyber Security and Resilience Bill 2025 mandates that in-scope organisations report significant cyber incidents to the NCSC within 24 hours. Operators of essential services and digital service providers are in scope.',
  PCI: 'PCI DSS v4.0 Requirement 12.10 mandates an incident response plan. Suspected cardholder data breaches must be reported to the acquiring bank and payment brands promptly, typically within 24–72 hours.',
  NIS2:'NIS2 (and its UK equivalent) requires early warning within 24 hours, incident notification within 72 hours, and a final report within one month.',
};

function DeadlineCard({ incident, type }) {
  const hours   = type === 'ICO' ? 72 : 24;
  const deadline = incident.detectedAt ? new Date(new Date(incident.detectedAt).getTime() + hours * 3600000).toISOString() : null;
  const { rem, expired } = useCountdown(deadline);
  const fmtDl = deadline ? new Date(deadline).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'}) : 'Unknown';
  const color  = expired ? 'var(--accent)' : rem.startsWith('00:') ? 'var(--warning)' : 'var(--success)';

  return (
    <div style={{ background:'var(--card)', border:`1px solid ${expired?'rgba(220,38,38,0.4)':'var(--border)'}`, borderRadius:'var(--r-card)', padding:'clamp(14px,3vw,18px) clamp(16px,3vw,20px)', borderLeft:`3px solid ${color}` }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:'12px', flexWrap:'wrap' }}>
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:'12px', color:'var(--text-dim)', marginBottom:'3px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{incident.id} — {incident.title}</div>
          <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text)' }}>
            {type==='ICO'?'ICO Notification (UK GDPR Art.33)':'NCSC Report (CSR Bill 2025)'}
          </div>
          <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'3px' }}>Deadline: {fmtDl}</div>
        </div>
        <div style={{ textAlign:'right', flexShrink:0 }}>
          <div style={{ fontSize:'clamp(18px,4vw,24px)', fontWeight:700, fontFamily:'var(--font-mono)', color, lineHeight:1, letterSpacing:'0.02em' }}>{rem||'--:--:--'}</div>
          <div style={{ fontSize:'10px', color:'var(--text-dim)', marginTop:'3px' }}>{expired?'OVERDUE':'remaining'}</div>
        </div>
      </div>
    </div>
  );
}

function RegRow({ reg }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
      <button onClick={() => setOpen(v=>!v)}
        style={{ width:'100%', display:'grid', gridTemplateColumns:'1fr auto auto auto', gap:'10px', padding:'12px 16px', background:'none', border:'none', cursor:'pointer', textAlign:'left', alignItems:'center', transition:'background var(--t)', minHeight:'52px' }}
        onMouseEnter={e => e.currentTarget.style.background='rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background='none'}
      >
        <div style={{ minWidth:0 }}>
          <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{reg.name}</div>
          <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'2px' }}>Authority: {reg.authority}</div>
        </div>
        <span style={{ fontSize:'12px', color:'var(--text-muted)', fontFamily:'var(--font-mono)', whiteSpace:'nowrap' }}>{reg.deadline}</span>
        <StatusBadge status={reg.status} />
        {open ? <ChevronUp size={14} color="var(--text-dim)" /> : <ChevronDown size={14} color="var(--text-dim)" />}
      </button>
      {open && (
        <div style={{ padding:'0 16px 14px', borderTop:'1px solid var(--border)', animation:'fadeIn 150ms ease' }}>
          <p style={{ fontSize:'13px', color:'var(--text-muted)', lineHeight:1.65, paddingTop:'12px' }}>{REG_DETAIL[reg.id]||reg.threshold}</p>
        </div>
      )}
    </div>
  );
}

export default function ComplianceCentre({ onBack, nav, incidents }) {
  const icoInc  = incidents.filter(i => i.needsICO);
  const ncscInc = incidents.filter(i => i.needsNCSC);
  const needsAct = icoInc.length + ncscInc.length;
  const fmt = iso => new Date(iso).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex', flexDirection:'column' }}>
      <TopBar moduleName="Compliance Centre" onBack={onBack} nav={nav} currentRoute="compliance" />

      <div className="rs-page" style={{ flex:1, overflowY:'auto' }}>
        <div className="rs-page-inner" style={{ margin:'0 auto', display:'flex', flexDirection:'column', gap:'20px', animation:'fadeIn 200ms ease' }}>

          {/* Summary */}
          <div className="rs-comp-stats">
            {[
              { label:'Frameworks',      value:COMPLIANCE_REGULATIONS.length, sub:'monitored',      accent:'var(--primary)' },
              { label:'Action Required', value:needsAct,                       sub:'notifications',  accent: needsAct>0?'var(--accent)':undefined },
              { label:'ICO Incidents',   value:icoInc.length,                  sub:'72h obligation', accent: icoInc.length>0?'var(--warning)':undefined },
              { label:'NCSC Incidents',  value:ncscInc.length,                 sub:'24h obligation', accent: ncscInc.length>0?'var(--warning)':undefined },
            ].map(s => (
              <div key={s.label} style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', padding:'clamp(14px,3vw,18px) clamp(14px,3vw,20px)', borderLeft: s.accent?`3px solid ${s.accent}`:undefined }}>
                <div style={{ fontSize:'11px', color:'var(--text-muted)', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'4px' }}>{s.label}</div>
                <div style={{ fontSize:'clamp(22px,4vw,26px)', fontWeight:700, fontFamily:'var(--font-mono)', color:s.accent||'var(--text)', lineHeight:1 }}>{s.value}</div>
                <div style={{ fontSize:'11px', color:'var(--text-dim)', marginTop:'3px' }}>{s.sub}</div>
              </div>
            ))}
          </div>

          {/* Active deadlines */}
          {needsAct > 0 && (
            <div>
              <div style={{ fontSize:'12px', fontWeight:600, color:'var(--accent)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:'10px', display:'flex', alignItems:'center', gap:'5px' }}>
                <AlertTriangle size={12} />Active Notification Deadlines
              </div>
              <div style={{ display:'flex', flexDirection:'column', gap:'10px' }}>
                {icoInc.map(inc  => <DeadlineCard key={`ico-${inc.id}`}  incident={inc} type="ICO"  />)}
                {ncscInc.map(inc => <DeadlineCard key={`ncsc-${inc.id}`} incident={inc} type="NCSC" />)}
              </div>
            </div>
          )}

          {needsAct === 0 && (
            <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', padding:'28px', display:'flex', alignItems:'center', gap:'14px', flexWrap:'wrap' }}>
              <CheckCircle size={26} color="var(--success)" style={{ flexShrink:0 }} />
              <div>
                <div style={{ fontSize:'14px', fontWeight:600, color:'var(--text)', marginBottom:'4px' }}>No active notification deadlines</div>
                <div style={{ fontSize:'13px', color:'var(--text-muted)' }}>Run the attack simulation to populate ICO and NCSC deadline trackers.</div>
              </div>
            </div>
          )}

          {/* Regulatory frameworks */}
          <div>
            <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:'10px' }}>Regulatory Frameworks</div>
            <div style={{ display:'flex', flexDirection:'column', gap:'8px' }}>
              {COMPLIANCE_REGULATIONS.map(reg => <RegRow key={reg.id} reg={reg} />)}
            </div>
          </div>

          {/* Submission history */}
          <div>
            <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:'10px' }}>Submission History</div>
            <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
              <div className="rs-table-wrap">
                <div style={{ minWidth:'480px' }}>
                  <div style={{ display:'grid', gridTemplateColumns:'1fr 90px 100px 90px 110px', padding:'9px 16px', background:'var(--surface)', borderBottom:'1px solid var(--border)' }}>
                    {['Reference','Date','Incident','Framework','Status'].map(h=><span key={h} style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em' }}>{h}</span>)}
                  </div>
                  {SUBMISSION_HISTORY.map((sub,idx) => (
                    <div key={sub.id} style={{ display:'grid', gridTemplateColumns:'1fr 90px 100px 90px 110px', padding:'11px 16px', borderBottom: idx<SUBMISSION_HISTORY.length-1?'1px solid var(--border)':'none', alignItems:'center' }}>
                      <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{sub.refNo}</span>
                      <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{fmt(sub.date)}</span>
                      <span style={{ fontSize:'12px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{sub.incident}</span>
                      <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{sub.regulation}</span>
                      <StatusBadge status={sub.status} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
