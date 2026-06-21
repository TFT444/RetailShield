import { useState, useMemo } from 'react';
import {
  ShoppingCart, AlertTriangle, TrendingUp, TrendingDown,
  Minus, X, Clock, User, Monitor, ChevronRight,
  PoundSterling, Store, BarChart2,
} from 'lucide-react';
import TopBar      from '../components/TopBar.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatCard    from '../components/StatCard.jsx';
import { LP_INCIDENTS, LP_STORE_RISK } from '../lib/data.js';
import { useBreakpoint } from '../lib/hooks.js';

const LP_COLOR = '#F97316';
const LP_DIM   = 'rgba(249,115,22,0.12)';

const SIGNAL_LABELS = {
  HighVolumeVoidRefund:              'High-volume voids',
  HighValueVoidNoOverride:           'High-value void, no override',
  RapidVoidBurst:                    'Rapid void burst',
  BulkGiftCardActivation:            'Bulk card activation',
  RapidCrossChannelRedemption:       'Cross-channel redemption',
  HighValueActivationSession:        'High-value activation',
  RepeatHighDiscountRelationship:    'Repeat discount relationship',
  BelowAverageBasketForCustomer:     'Below-average basket',
  HighDiscountConcentrationAtTerminal: 'Discount concentration',
  AfterHoursHighValueSale:           'After-hours sale',
  GhostEmployeeAfterHours:           'Ghost employee',
  ClosedStoreTerminalBurst:          'Closed-store terminal burst',
};

const RULE_LABELS = {
  'LP-001': 'POS Void/Refund Abuse',
  'LP-002': 'Gift Card Rapid Redemption',
  'LP-003': 'Sweethearting',
  'LP-004': 'After-Hours POS',
};

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-GB', {
    day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', timeZone:'UTC',
  });
}

function fmtGBP(v) {
  if (!v && v !== 0) return '—';
  return `£${v.toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function TrendIcon({ trend }) {
  if (trend === 'up')   return <TrendingUp   size={13} color="#DC2626" />;
  if (trend === 'down') return <TrendingDown size={13} color="#16A34A" />;
  return <Minus size={13} color="var(--text-dim)" />;
}

function RiskBar({ score }) {
  const color = score >= 80 ? '#DC2626' : score >= 60 ? '#F97316' : '#16A34A';
  return (
    <div style={{ display:'flex', alignItems:'center', gap:'8px', minWidth:0 }}>
      <div style={{ flex:1, height:'4px', background:'var(--border)', borderRadius:'2px', overflow:'hidden' }}>
        <div style={{ width:`${score}%`, height:'100%', background:color, borderRadius:'2px', transition:'width var(--t)' }} />
      </div>
      <span style={{ fontSize:'11px', fontWeight:700, color, fontFamily:'var(--font-mono)', flexShrink:0, minWidth:'26px', textAlign:'right' }}>{score}</span>
    </div>
  );
}

function IncidentDetail({ inc, onClose }) {
  if (!inc) return null;
  return (
    <div style={{
      position:'fixed', inset:0, zIndex:200,
      background:'rgba(7,11,20,0.75)', backdropFilter:'blur(4px)',
      display:'flex', alignItems:'flex-start', justifyContent:'flex-end',
      padding:'16px',
    }}
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width:'min(520px, calc(100vw - 32px))', maxHeight:'calc(100vh - 32px)',
          overflowY:'auto', background:'var(--surface)',
          border:'1px solid var(--border)', borderRadius:'var(--r-card)',
          boxShadow:'var(--shadow-lg)', display:'flex', flexDirection:'column',
        }}
      >
        {/* Detail header */}
        <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)', display:'flex', alignItems:'flex-start', gap:'12px' }}>
          <div style={{ flex:1, minWidth:0 }}>
            <div style={{ display:'flex', alignItems:'center', gap:'8px', flexWrap:'wrap', marginBottom:'6px' }}>
              <SeverityBadge severity={inc.severity} />
              <span style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:'var(--text-dim)', background:'var(--card)', padding:'2px 7px', borderRadius:'var(--r-badge)', border:'1px solid var(--border)' }}>{inc.id}</span>
              <span style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:LP_COLOR, background:LP_DIM, padding:'2px 7px', borderRadius:'var(--r-badge)', border:'1px solid rgba(249,115,22,0.25)' }}>{inc.ruleId}</span>
            </div>
            <div style={{ fontSize:'14px', fontWeight:600, color:'var(--text)', lineHeight:1.4 }}>{inc.title}</div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{ padding:'6px', background:'none', border:'none', color:'var(--text-dim)', cursor:'pointer', flexShrink:0, borderRadius:'6px' }}
            onMouseEnter={e => { e.currentTarget.style.color='var(--text)'; e.currentTarget.style.background='var(--card)'; }}
            onMouseLeave={e => { e.currentTarget.style.color='var(--text-dim)'; e.currentTarget.style.background='none'; }}
          >
            <X size={16} />
          </button>
        </div>

        <div style={{ padding:'16px 20px', display:'flex', flexDirection:'column', gap:'16px' }}>

          {/* Meta row */}
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'8px' }}>
            {[
              { label:'Detection signal', value: SIGNAL_LABELS[inc.detectionSignal] || inc.detectionSignal },
              { label:'MTTD',             value: `${inc.mttd} min` },
              { label:'Store',            value: inc.storeId },
              { label:'Operator',         value: inc.operatorId || '—' },
              { label:'Terminal',         value: inc.terminalId || '—' },
              { label:'Risk score',       value: inc.riskScore },
              { label:'Estimated loss',   value: fmtGBP(inc.estimatedLossGBP) },
              { label:'Detected',         value: fmtDate(inc.detectedAt) },
            ].map(row => (
              <div key={row.label} style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'6px', padding:'8px 10px' }}>
                <div style={{ fontSize:'10px', color:'var(--text-dim)', marginBottom:'2px', textTransform:'uppercase', letterSpacing:'0.06em' }}>{row.label}</div>
                <div style={{ fontSize:'12px', fontWeight:600, color:'var(--text)', fontFamily:'var(--font-mono)', wordBreak:'break-all' }}>{row.value}</div>
              </div>
            ))}
          </div>

          {/* Description */}
          <div>
            <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'6px' }}>Description</div>
            <p style={{ fontSize:'13px', color:'var(--text-muted)', lineHeight:1.6 }}>{inc.description}</p>
          </div>

          {/* Timeline */}
          {inc.timeline?.length > 0 && (
            <div>
              <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'8px' }}>Event timeline</div>
              <div style={{ display:'flex', flexDirection:'column', gap:'0' }}>
                {inc.timeline.map((ev, i) => (
                  <div key={i} style={{ display:'flex', gap:'10px', paddingBottom: i < inc.timeline.length - 1 ? '10px' : '0' }}>
                    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', flexShrink:0 }}>
                      <div style={{ width:'6px', height:'6px', borderRadius:'50%', background:LP_COLOR, marginTop:'5px', flexShrink:0 }} />
                      {i < inc.timeline.length - 1 && <div style={{ width:'1px', flex:1, background:'var(--border)', marginTop:'4px' }} />}
                    </div>
                    <div style={{ minWidth:0 }}>
                      <span style={{ fontSize:'11px', fontFamily:'var(--font-mono)', color:LP_COLOR, fontWeight:600 }}>{ev.time} </span>
                      <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{ev.event}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Auto-defence */}
          {inc.autoDefence?.length > 0 && (
            <div>
              <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'6px' }}>Automated response</div>
              <div style={{ display:'flex', flexDirection:'column', gap:'4px' }}>
                {inc.autoDefence.map((a, i) => (
                  <div key={i} style={{ display:'flex', alignItems:'flex-start', gap:'6px' }}>
                    <div style={{ width:'4px', height:'4px', borderRadius:'50%', background:'var(--success)', flexShrink:0, marginTop:'6px' }} />
                    <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{a}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {inc.recommendations?.length > 0 && (
            <div>
              <div style={{ fontSize:'11px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:'6px' }}>Recommendations</div>
              <div style={{ display:'flex', flexDirection:'column', gap:'4px' }}>
                {inc.recommendations.map((r, i) => (
                  <div key={i} style={{ display:'flex', alignItems:'flex-start', gap:'6px' }}>
                    <div style={{ width:'4px', height:'4px', borderRadius:'50%', background:LP_COLOR, flexShrink:0, marginTop:'6px' }} />
                    <span style={{ fontSize:'12px', color:'var(--text-muted)' }}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function LossPrevention({ nav, onBack }) {
  const { isMobile } = useBreakpoint();
  const [selectedInc, setSelectedInc]   = useState(null);
  const [filterRule,  setFilterRule]    = useState('All');
  const [filterSev,   setFilterSev]     = useState('All');

  const incidents = LP_INCIDENTS;
  const storeRisk = LP_STORE_RISK;

  const filtered = useMemo(() => incidents.filter(inc => {
    if (filterRule !== 'All' && inc.ruleId !== filterRule) return false;
    if (filterSev  !== 'All' && inc.severity !== filterSev)  return false;
    return true;
  }), [incidents, filterRule, filterSev]);

  const totalLoss     = incidents.reduce((s, i) => s + (i.estimatedLossGBP || 0), 0);
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length;
  const avgRisk       = storeRisk.length > 0 ? Math.round(storeRisk.reduce((s, r) => s + r.riskScore, 0) / storeRisk.length) : 0;
  const highRiskCount = storeRisk.filter(r => r.riskScore >= 80).length;

  const selectBtnStyle = (active) => ({
    padding:'4px 10px', borderRadius:'var(--r-btn)', fontSize:'11px', fontWeight:600,
    cursor:'pointer', border:`1px solid ${active ? LP_COLOR : 'var(--border)'}`,
    background: active ? LP_DIM : 'transparent',
    color: active ? LP_COLOR : 'var(--text-dim)',
    transition:'all var(--t)',
  });

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex', flexDirection:'column' }}>

      <TopBar moduleName="Loss Prevention" onBack={onBack} nav={nav} currentRoute="lp" />

      <main style={{ flex:1, padding:'clamp(16px,3vw,28px) clamp(14px,3vw,28px)', maxWidth:'1200px', width:'100%', margin:'0 auto', display:'flex', flexDirection:'column', gap:'20px' }}>

        {/* Page header */}
        <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
          <div style={{ width:'36px', height:'36px', borderRadius:'9px', background:LP_DIM, border:`1px solid rgba(249,115,22,0.25)`, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
            <ShoppingCart size={18} color={LP_COLOR} />
          </div>
          <div>
            <h1 style={{ fontSize:'16px', fontWeight:700, color:'var(--text)', letterSpacing:'-0.02em' }}>Loss Prevention</h1>
            <p style={{ fontSize:'12px', color:'var(--text-muted)' }}>Financial fraud detection, void/refund abuse, and store risk scoring</p>
          </div>
        </div>

        {/* KPI cards */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(150px, 1fr))', gap:'12px' }}>
          <StatCard
            label="Open LP incidents"
            value={incidents.filter(i => i.status !== 'Resolved').length}
            sub={`${criticalCount} critical`}
            accent={criticalCount > 0 ? '#DC2626' : LP_COLOR}
            icon={AlertTriangle}
          />
          <StatCard
            label="Est. total exposure"
            value={`£${(totalLoss / 1000).toFixed(1)}k`}
            sub="across open incidents"
            accent={LP_COLOR}
            icon={PoundSterling}
          />
          <StatCard
            label="High-risk stores"
            value={highRiskCount}
            sub={`of ${storeRisk.length} monitored`}
            accent={highRiskCount >= 3 ? '#DC2626' : LP_COLOR}
            icon={Store}
          />
          <StatCard
            label="Portfolio avg risk"
            value={avgRisk}
            sub="out of 100"
            accent={avgRisk >= 70 ? '#DC2626' : avgRisk >= 50 ? LP_COLOR : '#16A34A'}
            icon={BarChart2}
          />
        </div>

        {/* Main layout — two columns on wide screens */}
        <div style={{ display:'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 340px', gap:'16px', alignItems:'start' }}>

          {/* Left: Incident feed */}
          <div style={{ display:'flex', flexDirection:'column', gap:'12px' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:'10px', flexWrap:'wrap' }}>
              <span style={{ fontSize:'12px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.08em' }}>
                LP Incidents ({filtered.length})
              </span>
              <div style={{ display:'flex', gap:'6px', flexWrap:'wrap' }}>
                {['All', 'LP-001', 'LP-002', 'LP-003', 'LP-004'].map(r => (
                  <button key={r} style={selectBtnStyle(filterRule === r)} onClick={() => setFilterRule(r)}>
                    {r === 'All' ? 'All rules' : r}
                  </button>
                ))}
                <div style={{ width:'1px', background:'var(--border)', margin:'0 2px' }} />
                {['All', 'Critical', 'High'].map(s => (
                  <button key={s} style={selectBtnStyle(filterSev === s)} onClick={() => setFilterSev(s)}>
                    {s === 'All' ? 'All sev.' : s}
                  </button>
                ))}
              </div>
            </div>

            {filtered.length === 0 ? (
              <div style={{ padding:'32px', textAlign:'center', background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', color:'var(--text-dim)', fontSize:'13px' }}>
                No incidents match the selected filters.
              </div>
            ) : (
              <div style={{ display:'flex', flexDirection:'column', gap:'8px' }}>
                {filtered.map(inc => (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedInc(inc)}
                    role="button"
                    tabIndex={0}
                    aria-label={`View incident ${inc.id}`}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelectedInc(inc); }}
                    style={{
                      background:'var(--card)', border:'1px solid var(--border)',
                      borderRadius:'var(--r-card)', padding:'14px 16px',
                      cursor:'pointer', transition:'all var(--t)',
                      display:'flex', flexDirection:'column', gap:'8px',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background='var(--card-hover)'; e.currentTarget.style.borderColor='rgba(249,115,22,0.25)'; e.currentTarget.style.transform='translateY(-1px)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background='var(--card)'; e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.transform='none'; }}
                  >
                    <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:'10px' }}>
                      <div style={{ minWidth:0, flex:1 }}>
                        <div style={{ display:'flex', alignItems:'center', gap:'6px', flexWrap:'wrap', marginBottom:'5px' }}>
                          <SeverityBadge severity={inc.severity} />
                          <span style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:'var(--text-dim)' }}>{inc.id}</span>
                          <span style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:LP_COLOR, background:LP_DIM, padding:'1px 6px', borderRadius:'4px', border:'1px solid rgba(249,115,22,0.2)' }}>
                            {inc.ruleId}
                          </span>
                        </div>
                        <div style={{ fontSize:'13px', fontWeight:600, color:'var(--text)', lineHeight:1.4 }}>{inc.title}</div>
                      </div>
                      <ChevronRight size={14} color="var(--text-dim)" style={{ flexShrink:0, marginTop:'2px' }} />
                    </div>

                    <div style={{ display:'flex', alignItems:'center', gap:'16px', flexWrap:'wrap' }}>
                      <div style={{ display:'flex', alignItems:'center', gap:'4px' }}>
                        <Store size={11} color="var(--text-dim)" />
                        <span style={{ fontSize:'11px', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{inc.storeId}</span>
                      </div>
                      {inc.operatorId && (
                        <div style={{ display:'flex', alignItems:'center', gap:'4px' }}>
                          <User size={11} color="var(--text-dim)" />
                          <span style={{ fontSize:'11px', color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{inc.operatorId}</span>
                        </div>
                      )}
                      <div style={{ display:'flex', alignItems:'center', gap:'4px' }}>
                        <Clock size={11} color="var(--text-dim)" />
                        <span style={{ fontSize:'11px', color:'var(--text-muted)' }}>{fmtDate(inc.detectedAt)}</span>
                      </div>
                      {inc.estimatedLossGBP > 0 && (
                        <span style={{ fontSize:'11px', fontWeight:700, color:LP_COLOR, fontFamily:'var(--font-mono)', marginLeft:'auto' }}>
                          {fmtGBP(inc.estimatedLossGBP)}
                        </span>
                      )}
                    </div>

                    <div style={{ fontSize:'11px', color:'var(--text-dim)', padding:'4px 8px', background:'var(--bg)', borderRadius:'5px', border:'1px solid var(--border)' }}>
                      Signal: <span style={{ color:'var(--text-muted)', fontWeight:500 }}>{SIGNAL_LABELS[inc.detectionSignal] || inc.detectionSignal}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Right: Store Risk Leaderboard */}
          <div style={{ display:'flex', flexDirection:'column', gap:'10px' }}>
            <span style={{ fontSize:'12px', fontWeight:600, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.08em' }}>
              Store Risk Leaderboard
            </span>
            <div style={{ background:'var(--card)', border:'1px solid var(--border)', borderRadius:'var(--r-card)', overflow:'hidden' }}>
              {storeRisk.map((s, i) => (
                <div
                  key={s.storeId}
                  style={{
                    padding:'10px 14px',
                    borderBottom: i < storeRisk.length - 1 ? '1px solid var(--border)' : 'none',
                    display:'flex', flexDirection:'column', gap:'6px',
                  }}
                >
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:'8px' }}>
                    <div style={{ minWidth:0 }}>
                      <div style={{ display:'flex', alignItems:'center', gap:'6px' }}>
                        <span style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:'var(--text-dim)', flexShrink:0 }}>
                          #{i + 1}
                        </span>
                        <span style={{ fontSize:'12px', fontWeight:600, color:'var(--text)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                          {s.storeName}
                        </span>
                      </div>
                      <div style={{ fontSize:'10px', fontFamily:'var(--font-mono)', color:'var(--text-dim)', marginTop:'1px' }}>{s.storeId}</div>
                    </div>
                    <div style={{ display:'flex', alignItems:'center', gap:'6px', flexShrink:0 }}>
                      <TrendIcon trend={s.trend} />
                      {s.openIncidents > 0 && (
                        <span style={{ fontSize:'10px', fontWeight:700, color:'#DC2626', background:'rgba(220,38,38,0.12)', padding:'1px 6px', borderRadius:'4px', border:'1px solid rgba(220,38,38,0.2)', whiteSpace:'nowrap' }}>
                          {s.openIncidents} open
                        </span>
                      )}
                    </div>
                  </div>
                  <RiskBar score={s.riskScore} />
                  {s.highestSignal && (
                    <div style={{ fontSize:'10px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>
                      {SIGNAL_LABELS[s.highestSignal] || s.highestSignal}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

        </div>
      </main>

      <footer style={{ borderTop:'1px solid var(--border)', padding:'12px clamp(14px,3vw,28px)', display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:'8px' }}>
        <span style={{ fontSize:'11px', color:'var(--text-dim)' }}>Loss Prevention · 4 active detection rules · T1657 — Financial Theft</span>
        <span style={{ fontSize:'11px', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>MITRE ATT&CK · Impact</span>
      </footer>

      {selectedInc && <IncidentDetail inc={selectedInc} onClose={() => setSelectedInc(null)} />}
    </div>
  );
}
