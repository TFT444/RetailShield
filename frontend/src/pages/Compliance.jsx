import { useState, useEffect } from 'react';
import { C, FONTS } from '../lib/tokens.js';
import { COMPLIANCE_REGULATIONS, SUBMISSION_HISTORY } from '../lib/data.js';
import { CheckSquare, AlertTriangle, Clock, FileText, ExternalLink, CheckCircle } from 'lucide-react';

function Countdown({ hours, label, color }) {
  const [remaining, setRemaining] = useState(hours * 3600);
  useEffect(() => {
    if (remaining <= 0) return;
    const t = setInterval(() => setRemaining(r => Math.max(0, r - 1)), 1000);
    return () => clearInterval(t);
  }, []);

  const h = Math.floor(remaining / 3600);
  const m = Math.floor((remaining % 3600) / 60);
  const s = remaining % 60;
  const pct = (remaining / (hours * 3600)) * 100;
  const urgent = remaining < 3600 * 4;

  return (
    <div style={{ background: C.card, border: `1px solid ${urgent ? color : C.border}`, borderRadius: 10, padding: '18px 20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <Clock size={14} color={color} />
        <span style={{ color: C.text, fontSize: 13, fontWeight: 600 }}>{label}</span>
        {urgent && (
          <span style={{ marginLeft: 'auto', background: `${color}22`, color, fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, fontFamily: FONTS.mono }}>
            URGENT
          </span>
        )}
      </div>
      <div style={{ fontFamily: FONTS.mono, fontSize: 28, fontWeight: 700, color, letterSpacing: 2, marginBottom: 10 }}>
        {String(h).padStart(2,'0')}:{String(m).padStart(2,'0')}:{String(s).padStart(2,'0')}
      </div>
      <div style={{ height: 6, background: C.border, borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 1s' }} />
      </div>
      <div style={{ color: C.textMuted, fontSize: 11, marginTop: 6 }}>Time remaining to submit notification</div>
    </div>
  );
}

function RegCard({ reg }) {
  const statusColor = reg.status === 'Compliant' ? C.green : reg.status === 'Monitored' ? C.blue : C.amber;
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: '16px 18px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <div style={{ color: C.text, fontSize: 13, fontWeight: 700 }}>{reg.name}</div>
          <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2 }}>Authority: {reg.authority}</div>
        </div>
        <span style={{
          background: `${statusColor}22`, color: statusColor, fontSize: 10,
          fontWeight: 700, padding: '2px 8px', borderRadius: 4, fontFamily: FONTS.mono,
        }}>{reg.status}</span>
      </div>
      <div style={{ display: 'flex', gap: 16, marginTop: 8 }}>
        <div>
          <div style={{ color: C.textMuted, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>Deadline</div>
          <div style={{ color: C.text, fontSize: 12, fontFamily: FONTS.mono, fontWeight: 600 }}>{reg.deadline}</div>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ color: C.textMuted, fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>Threshold</div>
          <div style={{ color: C.text, fontSize: 12 }}>{reg.threshold}</div>
        </div>
      </div>
    </div>
  );
}

function IncidentReportingCard({ inc }) {
  const icoDeadline = new Date(new Date(inc.detectedAt || new Date()).getTime() + 72 * 3600000);
  const ncscDeadline = new Date(new Date(inc.detectedAt || new Date()).getTime() + 24 * 3600000);
  const now = new Date();
  const icoHoursLeft = Math.max(0, Math.round((icoDeadline - now) / 3600000));
  const ncscHoursLeft = Math.max(0, Math.round((ncscDeadline - now) / 3600000));

  return (
    <div style={{ background: C.card, border: `1px solid ${C.red}44`, borderRadius: 10, padding: '16px 18px', marginBottom: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <AlertTriangle size={14} color={C.red} />
        <span style={{ color: C.text, fontSize: 13, fontWeight: 700 }}>{inc.id} — {inc.title}</span>
        <span style={{ marginLeft: 'auto', color: C.red, fontSize: 11, fontFamily: FONTS.mono }}>{inc.severity.toUpperCase()}</span>
      </div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {inc.needsICO && (
          <div style={{ flex: 1, minWidth: 160, background: `${C.amber}11`, border: `1px solid ${C.amber}44`, borderRadius: 6, padding: '8px 10px' }}>
            <div style={{ color: C.amber, fontSize: 10, fontWeight: 700, fontFamily: FONTS.mono, marginBottom: 4 }}>ICO — UK GDPR (72h)</div>
            <div style={{ color: C.text, fontSize: 12 }}>
              {icoHoursLeft > 0 ? `${icoHoursLeft}h remaining` : 'DEADLINE PASSED'}
            </div>
            <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2 }}>
              reportabreach@ico.org.uk
            </div>
          </div>
        )}
        {inc.needsNCSC && (
          <div style={{ flex: 1, minWidth: 160, background: `${C.red}11`, border: `1px solid ${C.red}44`, borderRadius: 6, padding: '8px 10px' }}>
            <div style={{ color: C.red, fontSize: 10, fontWeight: 700, fontFamily: FONTS.mono, marginBottom: 4 }}>NCSC — CSR Bill (24h)</div>
            <div style={{ color: C.text, fontSize: 12 }}>
              {ncscHoursLeft > 0 ? `${ncscHoursLeft}h remaining` : 'DEADLINE PASSED'}
            </div>
            <div style={{ color: C.textMuted, fontSize: 11, marginTop: 2 }}>
              report@ncsc.gov.uk
            </div>
          </div>
        )}
      </div>
      <div style={{ marginTop: 10, color: C.textMuted, fontSize: 11 }}>
        Data categories: {(inc.dataCategories || []).join(', ') || 'Under assessment'}
      </div>
    </div>
  );
}

export default function Compliance({ incidents }) {
  const reportableIncidents = incidents.filter(i => i.needsICO || i.needsNCSC);
  const icoRequired = incidents.filter(i => i.needsICO);
  const ncscRequired = incidents.filter(i => i.needsNCSC);

  const earliestICO = icoRequired[0];
  const earliestNCSC = ncscRequired[0];

  return (
    <div style={{ fontFamily: FONTS.ui }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ color: C.text, fontSize: 22, fontWeight: 700, margin: 0 }}>Compliance</h1>
        <div style={{ color: C.textMuted, fontSize: 12, marginTop: 4 }}>UK regulatory obligations — ICO, NCSC, PCI DSS, NIS2</div>
      </div>

      {/* Countdown timers */}
      {(icoRequired.length > 0 || ncscRequired.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          {ncscRequired.length > 0 && (
            <Countdown hours={24} label="NCSC Notification Deadline (CSR Bill)" color={C.red} />
          )}
          {icoRequired.length > 0 && (
            <Countdown hours={72} label="ICO Notification Deadline (UK GDPR)" color={C.amber} />
          )}
        </div>
      )}

      {/* Active incidents requiring reporting */}
      {reportableIncidents.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
            Active Incidents Requiring Notification ({reportableIncidents.length})
          </div>
          {reportableIncidents.map(inc => (
            <IncidentReportingCard key={inc.id} inc={inc} />
          ))}
        </div>
      )}

      {reportableIncidents.length === 0 && (
        <div style={{ background: `${C.green}11`, border: `1px solid ${C.green}44`, borderRadius: 10, padding: '16px 20px', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
          <CheckCircle size={16} color={C.green} />
          <div>
            <div style={{ color: C.green, fontSize: 13, fontWeight: 600 }}>No Regulatory Reporting Required</div>
            <div style={{ color: C.textMuted, fontSize: 12, marginTop: 2 }}>No active incidents currently trigger ICO or NCSC notification obligations</div>
          </div>
        </div>
      )}

      {/* Regulations overview */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Regulatory Framework</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {COMPLIANCE_REGULATIONS.map(reg => <RegCard key={reg.id} reg={reg} />)}
        </div>
      </div>

      {/* Submission history */}
      <div>
        <div style={{ color: C.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Submission History</div>
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: C.surface }}>
                {['Ref', 'Date', 'Incident', 'Regulation', 'Authority', 'Status'].map(h => (
                  <th key={h} style={{ padding: '10px 16px', textAlign: 'left', color: C.textMuted, fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5, borderBottom: `1px solid ${C.border}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SUBMISSION_HISTORY.map((s, i) => {
                const color = s.status === 'Acknowledged' ? C.green : s.status === 'Submitted' ? C.blue : C.textMuted;
                return (
                  <tr key={s.id} style={{ borderBottom: i < SUBMISSION_HISTORY.length - 1 ? `1px solid ${C.border}` : 'none' }}>
                    <td style={{ padding: '10px 16px', color: C.textMuted, fontSize: 11, fontFamily: FONTS.mono }}>{s.refNo}</td>
                    <td style={{ padding: '10px 16px', color: C.textMuted, fontSize: 12, fontFamily: FONTS.mono }}>{new Date(s.date).toLocaleDateString('en-GB')}</td>
                    <td style={{ padding: '10px 16px', color: C.text, fontSize: 12, fontFamily: FONTS.mono }}>{s.incident}</td>
                    <td style={{ padding: '10px 16px', color: C.textMuted, fontSize: 12 }}>{s.regulation}</td>
                    <td style={{ padding: '10px 16px', color: C.textMuted, fontSize: 12 }}>{s.authority}</td>
                    <td style={{ padding: '10px 16px' }}>
                      <span style={{ color, fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>{s.status}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
