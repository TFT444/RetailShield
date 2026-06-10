# RetailShield Roadmap

This roadmap reflects the honest state of the project. Only features that are fully built and tested are marked as complete.

Research paper: [DOI 10.5281/zenodo.20608262](https://doi.org/10.5281/zenodo.20608262)

---

## Phase 1 — Complete (v2.0.0, June 2026)

The foundation: a working SOC platform purpose-built for UK retail, with published research validating the detection capability.

### Detection engineering
- [x] 19 production-ready KQL detection rules covering the full MITRE ATT&CK kill chain
- [x] 8 Logic App playbooks for automated incident response
- [x] Sentinel analytics-rule JSON wrappers for one-click deployment
- [x] 221 automated pytest tests validating rule syntax and MITRE mapping

### Compliance automation
- [x] ICO 72-hour breach notification countdown with auto-generated draft reports
- [x] NCSC 24-hour reporting countdown
- [x] UK regulatory framework coverage: ICO, NCSC, PCI DSS, NIS2
- [x] Submission history tracking

### Platform
- [x] Responsive portal dashboard (Landing → Login → Portal → 4 modules)
- [x] Threat Detection module: live incident feed, MITRE heatmap, attack timeline, AI-generated incident reports
- [x] Vulnerability Scanner: SVG risk gauge, phased scan progress, OWASP Top 10 findings
- [x] Compliance Centre: live countdown timers, regulatory accordion, submission log
- [x] Detection Rules: 19-rule table with search/filter, full MITRE ATT&CK coverage matrix
- [x] Fully responsive at 375px, 768px, 1024px, and 1440px viewport widths
- [x] SIMULATE ATTACK feature populating all modules with realistic incident data

### Research
- [x] Live Microsoft Sentinel evaluation: 22.5 minute average mean time to detect (MTTD)
- [x] Peer-reviewed research paper published: [DOI 10.5281/zenodo.20608262](https://doi.org/10.5281/zenodo.20608262)

---

## Phase 2 — In Development (v2.1.0, Q3 2026)

Expanding coverage to retail-specific financial crime and supply chain risk, and connecting the platform to live Sentinel data.

### Loss Prevention module
- [ ] POS transaction anomaly detection (void abuse, refund fraud, sweethearting patterns)
- [ ] Gift card abuse tracking (bulk activation, rapid redemption sequences)
- [ ] Store risk scoring dashboard with trend analysis
- [ ] Integration with retail EPOS event logs

### ChainShield — Supply chain security module
- [ ] Third-party supplier compromise detection
- [ ] Logistics fraud indicators (diversion, cargo theft patterns)
- [ ] Supplier risk scoring and change monitoring
- [ ] Integration with procurement and logistics event sources

### Live Sentinel integration
- [ ] Real Microsoft Sentinel API connection for live dashboard data
- [ ] Replace demo data with authenticated workspace queries
- [ ] Workspace configuration UI (tenant ID, workspace ID, client credentials)

### DevOps
- [ ] GitHub Actions pipeline for automated deployment to Sentinel workspace
- [ ] Environment-specific configuration management (dev / staging / production)

---

## Phase 3 — Planned (v3.0.0, 2027)

Commercial-grade capability and broader ecosystem integration.

### Ecosystem
- [ ] Microsoft Sentinel Content Hub publication — making RetailShield installable directly from the Sentinel marketplace
- [ ] Multi-tenant MSSP support — manage multiple retail client workspaces from a single portal instance

### Compliance expansion
- [ ] PCI DSS v4.0 dedicated compliance module with control mapping
- [ ] NIS2 Directive module for operators of essential services

### Intelligence
- [ ] ML-based behavioural anomaly detection layer on top of KQL rules
- [ ] Adaptive thresholds that learn baseline patterns per store / tenant

### Commercial
- [ ] ShieldTech Ltd managed service offering for UK retailers
- [ ] SLA-backed incident response integration

---

## What is not planned

- Support for non-UK regulatory frameworks (GDPR outside the UK, SOC 2, HIPAA) — out of scope for this project
- Support for SIEM platforms other than Microsoft Sentinel
- A mobile native app — the responsive web portal covers mobile use cases

---

*Last updated: June 2026 — Tanvir Farhad, ShieldTech Ltd*
