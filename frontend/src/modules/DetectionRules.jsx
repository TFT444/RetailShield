import { useState } from 'react';
import { Search } from 'lucide-react';
import TopBar        from '../components/TopBar.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatCard      from '../components/StatCard.jsx';
import { DETECTION_RULES, MITRE_COVERAGE } from '../lib/data.js';

const TACTIC_COLS = {
  'Initial Access':'#DC2626','Execution':'#D97706','Persistence':'#D97706',
  'Privilege Escalation':'#F97316','Defence Evasion':'#8B5CF6',
  'Credential Access':'#EC4899','Discovery':'#0891B2','Lateral Movement':'#EF4444',
  'Collection':'#6366F1','C2':'#DC2626','Exfiltration':'#DC2626','Impact':'#DC2626',
};

function FilterBtn({ label, active, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding:'5px 10px', borderRadius:'var(--r-btn)', border:'1px solid var(--border)',
      background: active?'var(--primary)':'var(--surface)', color: active?'white':'var(--text-muted)',
      fontSize:'12px', fontWeight: active?600:400, cursor:'pointer', transition:'all var(--t)', minHeight:'32px',
    }}>{label}</button>
  );
}

export default function DetectionRules({ onBack, nav }) {
  const [search,  setSearch]  = useState('');
  const [sevF,    setSevF]    = useState('All');
  const [statusF, setStatusF] = useState('All');

  const active   = DETECTION_RULES.filter(r=>r.status==='Active').length;
  const disabled = DETECTION_RULES.filter(r=>r.status==='Disabled').length;
  const critical = DETECTION_RULES.filter(r=>r.severity==='Critical').length;
  const triggers = DETECTION_RULES.reduce((s,r)=>s+r.triggerCount,0);

  const filtered = DETECTION_RULES.filter(r => {
    const q = search.toLowerCase();
    return (!search || r.name.toLowerCase().includes(q) || r.technique.toLowerCase().includes(q) || r.tactic.toLowerCase().includes(q))
      && (sevF==='All'||r.severity===sevF)
      && (statusF==='All'||r.status===statusF);
  });

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex', flexDirection:'column' }}>
      <TopBar moduleName="Detection Rules" onBack={onBack} nav={nav} currentRoute="rules" />

      <div className="rs-page" style={{ flex:1, overflowY:'auto' }}>
        <div className="rs-page-inner" style={{ margin:'0 auto', display:'flex', flexDirection:'column', gap:'16px', animation:'fadeIn 200ms ease' }}>

          {/* Stats */}
          <div className="rs-stats">
            <StatCard label="Active Rules"   value={active}   sub="running in Sentinel" accent="var(--success)" />
            <StatCard label="Critical Rules" value={critical} sub="highest severity"     accent="var(--accent)"  />
            <StatCard label="Disabled"       value={disabled} sub="pending review"       />
            <StatCard label="Total Triggers" value={triggers} sub="events this session"  accent="var(--primary)" />
          </div>

          {/* MITRE matrix */}
          <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
            <div style={{ padding:'14px 16px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:'8px' }}>
              <div>
                <span style={{ fontSize:'13px', fontWeight:600, color:'var(--text)' }}>MITRE ATT&CK Coverage</span>
                <span style={{ fontSize:'12px', color:'var(--text-dim)', marginLeft:'10px' }}>12 of 12 tactics</span>
              </div>
              <div style={{ display:'flex', gap:'12px', fontSize:'11px', color:'var(--text-dim)', flexWrap:'wrap' }}>
                {[['var(--success)','≥60%'],['var(--warning)','30–59%'],['var(--accent)','<30%']].map(([c,l])=>(
                  <div key={l} style={{ display:'flex', alignItems:'center', gap:'4px' }}>
                    <div style={{ width:'9px', height:'9px', borderRadius:'2px', background:c }} />
                    <span>{l}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="rs-mitre-lg">
              {MITRE_COVERAGE.map(m => {
                const pct = m.covered / m.total;
                const col = pct>=0.6?'var(--success)':pct>=0.3?'var(--warning)':'var(--accent)';
                return (
                  <div key={m.tactic} style={{ background:'var(--surface)', borderRadius:'7px', padding:'10px 12px', borderLeft:`3px solid ${col}` }}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'6px', gap:'6px' }}>
                      <span style={{ fontSize:'11px', fontWeight:600, color:'var(--text)', lineHeight:1.2, flex:1 }}>{m.tactic}</span>
                      <span style={{ fontSize:'12px', fontWeight:700, color:col, fontFamily:'var(--font-mono)', flexShrink:0 }}>{m.covered}/{m.total}</span>
                    </div>
                    <div style={{ height:'3px', background:'var(--border)', borderRadius:'2px', overflow:'hidden' }}>
                      <div style={{ height:'100%', width:`${pct*100}%`, background:col, borderRadius:'2px' }} />
                    </div>
                    <div style={{ fontSize:'10px', color:'var(--text-dim)', marginTop:'4px' }}>{Math.round(pct*100)}% coverage</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Rules table */}
          <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
            {/* Filters */}
            <div style={{ padding:'12px 16px', borderBottom:'1px solid var(--border)', display:'flex', gap:'8px', flexWrap:'wrap', alignItems:'center' }}>
              <div style={{ position:'relative', flex:1, minWidth:'160px' }}>
                <Search size={13} color="var(--text-dim)" style={{ position:'absolute', left:'9px', top:'50%', transform:'translateY(-50%)' }} />
                <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search rules…"
                  style={{ width:'100%', padding:'7px 9px 7px 28px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:'var(--r-btn)', color:'var(--text)', fontSize:'14px', outline:'none' }} />
              </div>
              <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
                {['All','Critical','High','Medium'].map(s=><FilterBtn key={s} label={s} active={sevF===s} onClick={()=>setSevF(s)} />)}
              </div>
              <div style={{ display:'flex', gap:'4px' }}>
                {['All','Active','Disabled'].map(s=><FilterBtn key={s} label={s} active={statusF===s} onClick={()=>setStatusF(s)} />)}
              </div>
              <span style={{ fontSize:'12px', color:'var(--text-dim)', marginLeft:'auto', flexShrink:0 }}>{filtered.length}/{DETECTION_RULES.length}</span>
            </div>

            {/* Table — horizontal scroll on mobile */}
            <div className="rs-table-wrap">
              <div style={{ minWidth:'640px' }}>
                <div style={{ display:'grid', gridTemplateColumns:'70px 1fr 100px 130px 80px 90px 55px', padding:'9px 16px', background:'var(--surface)', borderBottom:'1px solid var(--border)' }}>
                  {['ID','Rule Name','Technique','Tactic','Severity','Last Trigger','Hits'].map(h=><span key={h} style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em' }}>{h}</span>)}
                </div>
                {filtered.length===0
                  ? <div style={{ padding:'40px', textAlign:'center', color:'var(--text-dim)', fontSize:'13px' }}>No rules match current filters</div>
                  : filtered.map((r,idx) => {
                    const tc = TACTIC_COLS[r.tactic] || 'var(--text-dim)';
                    return (
                      <div key={r.id}
                        style={{ display:'grid', gridTemplateColumns:'70px 1fr 100px 130px 80px 90px 55px', padding:'10px 16px', borderBottom: idx<filtered.length-1?'1px solid var(--border)':'none', alignItems:'center', opacity: r.status==='Disabled'?0.55:1, transition:'background var(--t)' }}
                        onMouseEnter={e=>e.currentTarget.style.background='rgba(255,255,255,0.02)'}
                        onMouseLeave={e=>e.currentTarget.style.background='transparent'}
                      >
                        <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>{r.id}</span>
                        <span style={{ fontSize:'13px', color:'var(--text)', fontWeight:500, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', paddingRight:'10px' }}>{r.name}</span>
                        <span style={{ fontSize:'11px', color:'var(--primary)', fontFamily:'var(--font-mono)' }}>{r.technique}</span>
                        <span style={{ fontSize:'11px', fontWeight:500, color:tc, background:`${tc}18`, padding:'2px 7px', borderRadius:'4px', border:`1px solid ${tc}30`, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', display:'inline-block', maxWidth:'120px' }}>{r.tactic}</span>
                        <SeverityBadge severity={r.severity} />
                        <span style={{ fontSize:'11px', color:'var(--text-dim)' }}>{r.lastTriggered}</span>
                        <span style={{ fontSize:'13px', color:'var(--text-muted)', fontFamily:'var(--font-mono)', fontWeight:600 }}>
                          {r.triggerCount>0 ? r.triggerCount : <span style={{ color:'var(--text-dim)', fontWeight:400 }}>—</span>}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
