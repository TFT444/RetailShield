import { useState } from 'react';
import { BASELINE_INCIDENTS } from './lib/data.js';
import Landing from './pages/Landing.jsx';
import Login from './pages/Login.jsx';
import Portal from './pages/Portal.jsx';
import ThreatDetection from './modules/ThreatDetection.jsx';
import VulnerabilityScanner from './modules/VulnerabilityScanner.jsx';
import ComplianceCentre from './modules/ComplianceCentre.jsx';
import DetectionRules from './modules/DetectionRules.jsx';

export default function App() {
  const [route, setRoute] = useState('landing');
  const [incidents, setIncidents] = useState([...BASELINE_INCIDENTS]);

  const nav = (page) => {
    setRoute(page);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  switch (route) {
    case 'landing':    return <Landing onDemo={() => nav('portal')} onSignIn={() => nav('login')} />;
    case 'login':      return <Login onSuccess={() => nav('portal')} onDemo={() => nav('portal')} />;
    case 'portal':     return <Portal nav={nav} incidents={incidents} onSignOut={() => nav('landing')} />;
    case 'threat':     return <ThreatDetection onBack={() => nav('portal')} incidents={incidents} setIncidents={setIncidents} />;
    case 'vuln':       return <VulnerabilityScanner onBack={() => nav('portal')} />;
    case 'compliance': return <ComplianceCentre onBack={() => nav('portal')} incidents={incidents} />;
    case 'rules':      return <DetectionRules onBack={() => nav('portal')} />;
    default:           return <Landing onDemo={() => nav('portal')} onSignIn={() => nav('login')} />;
  }
}
