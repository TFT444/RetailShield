import { C, FONTS } from '../lib/tokens.js';
import {
  LayoutDashboard, AlertTriangle, FileText, Shield,
  CheckSquare, Code2, ChevronRight, Wifi
} from 'lucide-react';

const NAV = [
  { id: 'dashboard',  label: 'Dashboard',          icon: LayoutDashboard },
  { id: 'incidents',  label: 'Incidents',           icon: AlertTriangle   },
  { id: 'ai-report',  label: 'AI Incident Report',  icon: FileText        },
  { id: 'vuln',       label: 'Vulnerability Scanner', icon: Shield        },
  { id: 'compliance', label: 'Compliance',          icon: CheckSquare     },
  { id: 'rules',      label: 'Detection Rules',     icon: Code2           },
];

export default function Sidebar({ currentPage, onNavigate, incidentCount }) {
  return (
    <aside style={{
      width: 240, minHeight: '100vh', background: C.surface,
      borderRight: `1px solid ${C.border}`, display: 'flex',
      flexDirection: 'column', fontFamily: FONTS.ui, flexShrink: 0,
    }}>
      <div style={{ padding: '20px 16px 16px', borderBottom: `1px solid ${C.border}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: `linear-gradient(135deg, ${C.red} 0%, #9b1c1c 100%)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={18} color="#fff" />
          </div>
          <div>
            <div style={{ color: C.text, fontWeight: 700, fontSize: 14 }}>RetailShield</div>
            <div style={{ color: C.textMuted, fontSize: 11 }}>SOC Platform v2.0</div>
          </div>
        </div>
        <div style={{
          marginTop: 12, display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 10px', background: C.card, borderRadius: 6,
          border: `1px solid ${C.border}`,
        }}>
          <Wifi size={12} color={C.green} />
          <span style={{ color: C.green, fontSize: 11, fontFamily: FONTS.mono }}>LIVE MONITORING</span>
        </div>
      </div>

      <nav style={{ flex: 1, padding: '8px 8px' }}>
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = currentPage === id;
          const badge = id === 'incidents' && incidentCount > 0 ? incidentCount : null;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                padding: '10px 12px', marginBottom: 2, border: 'none', cursor: 'pointer',
                borderRadius: 8, textAlign: 'left', minHeight: 44, transition: 'all 150ms',
                background: active ? `${C.red}22` : 'transparent',
                borderLeft: active ? `3px solid ${C.red}` : '3px solid transparent',
              }}
            >
              <Icon size={16} color={active ? C.red : C.textMuted} />
              <span style={{
                flex: 1, fontSize: 13, fontWeight: active ? 600 : 400,
                color: active ? C.text : C.textMuted,
              }}>
                {label}
              </span>
              {badge && (
                <span style={{
                  background: C.red, color: '#fff', fontSize: 10, fontWeight: 700,
                  padding: '1px 6px', borderRadius: 10, fontFamily: FONTS.mono,
                }}>
                  {badge}
                </span>
              )}
              {active && <ChevronRight size={12} color={C.red} />}
            </button>
          );
        })}
      </nav>

      <div style={{
        padding: '12px 16px', borderTop: `1px solid ${C.border}`,
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <div style={{
          width: 30, height: 30, borderRadius: '50%',
          background: `linear-gradient(135deg, ${C.blue} 0%, ${C.purple} 100%)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, color: '#fff', flexShrink: 0,
        }}>TF</div>
        <div>
          <div style={{ color: C.text, fontSize: 12, fontWeight: 600 }}>Tanvir Farhad</div>
          <div style={{ color: C.textMuted, fontSize: 11 }}>SOC Analyst · ShieldTech</div>
        </div>
      </div>
    </aside>
  );
}
