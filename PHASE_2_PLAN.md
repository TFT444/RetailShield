# Phase 2 Structured Implementation Plan (v2.1.0 — Q3 2026)

**Status:** Draft  
**Version:** 1.0  
**Owner:** TFT444 / ShieldTech Ltd  
**Last Updated:** 2026-06-16

---

## Executive Overview

Phase 2 expands RetailShield from foundational detection to **loss prevention** and **supply chain security**. This phase also introduces **live Sentinel integration** and **automated deployment pipelines** — transforming the platform from a static content pack to a live, mission-critical SOC platform.

### Phase 2 Goals
✅ Detect retail-specific financial crimes (POS fraud, gift card abuse)  
✅ Enable supply chain risk monitoring and third-party compromise detection  
✅ Connect to live Microsoft Sentinel workspaces (no more demo data)  
✅ Automate deployment via GitHub Actions → Sentinel workspace  

### Success Criteria
- All 4 feature areas delivered and tested
- 100% of KQL rules deployed and alerting on live data
- Documentation and runbooks updated
- GitHub Actions pipeline operational for multi-environment deployment

---

## Phase 2 Components & Dependencies

```
┌─────────────────────────────────────────────────────┐
│                    PHASE 2 (v2.1.0)                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │   Loss       │  │ ChainShield  │  │ Live     │ │
│  │   Prevention │  │  (Supply     │  │ Sentinel │ │
│  │   Module     │  │   Chain)     │  │Integration
│  │              │  │              │  │          │ │
│  │ POS Fraud    │  │ Supplier     │  │ API      │ │
│  │ Gift Cards   │  │ Compromise   │  │ Config   │ │
│  │ Risk Scoring │  │ Logistics    │  │ Queries  │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
│          ▲                  ▲                ▲      │
│          └──────────────────┴────────────────┘      │
│                      ▲                              │
│                      │                              │
│         ┌────────────┴─────────────┐                │
│         │    DevOps / Deployment   │                │
│         │  (GitHub Actions + Env)  │                │
│         └──────────────────────────┘                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Dependency Graph

1. **Loss Prevention** → Standalone (depends only on KQL syntax validation)
2. **ChainShield** → Standalone (depends only on KQL syntax validation)
3. **Live Sentinel Integration** → Requires Loss Prevention & ChainShield rules to be ready
4. **DevOps Pipeline** → Last (depends on all rules, playbooks, and config being finalized)

**Critical Path:** Loss Prevention + ChainShield → Live Sentinel Integration → DevOps

---

## Component 1: Loss Prevention Module

### Overview
Real-time detection of retail-specific financial crimes: POS transaction fraud, gift card abuse, insider manipulation, and anomalous cash handling.

### Deliverables

#### 1.1 KQL Detection Rules (5 rules)

| Rule ID | Name | MITRE Technique | Severity | Estimated Days |
|---------|------|-----------------|----------|-----------------|
| RS-LP-001 | **POS Void/Refund Abuse** | T1657 (Financial Theft) | High | 3 |
| RS-LP-002 | **Gift Card Bulk Activation** | T1657 | High | 3 |
| RS-LP-003 | **Rapid Gift Card Redemption** | T1657 | High | 3 |
| RS-LP-004 | **Sweethearting Pattern Detection** | T1657 | High | 4 |
| RS-LP-005 | **After-Hours Cash Drawer Activity** | T1657 | Medium | 3 |

**Dependencies:**
- `RetailShield_Logs_CL` custom table populated with POS event data
- Watchlist: `RetailExceptionaryEmployees` (optional, for employee-specific thresholds)

**Acceptance Criteria:**
- [ ] Each rule KQL query validated by `validate_kql.py`
- [ ] Each rule includes comments: Rule ID, Title, Severity, Frequency, PlaybookTrigger, MITRE mapping
- [ ] Rule query tested against sample retail transaction logs
- [ ] Rules committed to `detection-rules/retail/` folder
- [ ] README.md updated with Loss Prevention rule table

**Estimated Effort:** 16 days (3 + 3 + 3 + 4 + 3)

#### 1.2 Logic App Playbook: Loss Prevention Response

**Name:** `loss-prevention-respond`

**Workflow:**
1. Triage incident (classify as sweethearting / refund abuse / gift card fraud / cash anomaly)
2. Enrich with store context (store code, transaction volume baseline)
3. **Action:** Suspend POS terminal (if active) / Notify store manager + SOC
4. Notify HR if employee ID present (potential insider investigation)
5. Create service ticket for loss prevention team

**Files:**
- `logic-apps/loss-prevention-respond/workflow.json` (ARM template)
- `logic-apps/loss-prevention-respond/README.md` (deployment + customization)

**Dependencies:**
- Azure Logic Apps connectors: Sentinel, ServiceNow (or alternative ticketing), Teams (notification)
- Sentinel incident trigger connector

**Acceptance Criteria:**
- [ ] Workflow JSON valid per `validate_logicapps.py`
- [ ] Tested: triggers on sample incident, enriches with store data, sends notification
- [ ] Deployment guide includes required Azure resource prerequisites
- [ ] Error handling for missing data (e.g., store code not found)

**Estimated Effort:** 5 days

#### 1.3 Frontend: Loss Prevention Dashboard Module

**Location:** `frontend/src/modules/LossPrevention.tsx` (new)

**Features:**
- **Real-time incident feed:** Latest POS fraud alerts with store location, transaction value, employee
- **Store risk matrix:** Heatmap of stores by incident frequency + incident severity
- **Trend analysis:** 7d / 30d / 90d loss trending by store, incident type
- **Quick actions:** Suspend terminal, notify HR, view transaction timeline
- **Filters:** Date range, store code, incident type, severity

**Data Structure (simulated initially, replaced by live API in Phase 2.3):**
```json
{
  "incidents": [
    {
      "id": "LP-20260616-001",
      "type": "sweethearting",
      "store_code": "LON-W12",
      "store_name": "Oxford Street",
      "employee_id": "EMP-4521",
      "employee_name": "John Smith",
      "transaction_count": 47,
      "total_value": £2340.50,
      "detected_at": "2026-06-16T14:32:15Z",
      "severity": "high",
      "status": "open"
    }
  ]
}
```

**Acceptance Criteria:**
- [ ] Module renders correctly at 375px, 768px, 1024px, 1440px (responsive)
- [ ] Real-time incident feed updates every 30 seconds (simulated data)
- [ ] Store risk matrix shows color-coded risk levels
- [ ] Trend charts render correctly (7d / 30d / 90d)
- [ ] All interactive elements functional (filters, sort, quick actions)
- [ ] Integrated into portal module navigation

**Estimated Effort:** 8 days

#### 1.4 Documentation & Testing

**Files to Create:**
- `docs/loss-prevention/threat-model.md` — Threat scenarios, assumptions, scope
- `docs/loss-prevention/deployment-guide.md` — Step-by-step KQL rule + playbook setup
- `tests/loss-prevention/test_lp_rules.py` — Unit tests for each KQL rule

**Test Coverage:**
- [ ] Unit tests for KQL rule logic (pytest)
- [ ] Integration test: sample POS logs → Sentinel → incident creation
- [ ] Playbook test: incident trigger → enrichment → notification

**Estimated Effort:** 5 days

### Loss Prevention Total Effort
**16 days (KQL) + 5 days (Playbook) + 8 days (Frontend) + 5 days (Docs/Tests) = 34 days**

---

## Component 2: ChainShield — Supply Chain Security Module

### Overview
Detect third-party supplier compromise, logistics fraud, and supply chain anomalies that could indicate nation-state or criminal infiltration of the retail ecosystem.

### Deliverables

#### 2.1 KQL Detection Rules (4 rules)

| Rule ID | Name | MITRE Technique | Severity | Estimated Days |
|---------|------|-----------------|----------|-----------------|
| RS-CS-001 | **Supplier Account Anomalous Access** | T1195 (Supply Chain Compromise) | High | 4 |
| RS-CS-002 | **Logistics Data Exfiltration Pattern** | T1048 (Exfil Over Alt Protocol) | Critical | 4 |
| RS-CS-003 | **Supplier Impossible Travel** | T1199 / T1078 | Medium | 3 |
| RS-CS-004 | **Procurement System Manipulation** | T1565 (Data Manipulation) | High | 4 |

**Dependencies:**
- Custom table: `RetailSupplierLogs_CL` (supplier access logs)
- Custom table: `RetailLogisticsEvents_CL` (shipment tracking, carrier events)
- Watchlist: `RetailSuppliers` (approved supplier list with risk tier)

**Acceptance Criteria:**
- [ ] Each rule KQL query validated
- [ ] Rules tested against sample supplier event logs
- [ ] Integration with MITRE ATT&CK framework documented
- [ ] Rules committed to `detection-rules/retail/` folder

**Estimated Effort:** 15 days (4 + 4 + 3 + 4)

#### 2.2 Logic App Playbook: Supply Chain Response

**Name:** `supply-chain-respond`

**Workflow:**
1. Triage incident (supplier compromise / logistics fraud / procurement manipulation)
2. **Enrichment:** Supplier profile (risk tier, contract value, criticality), related incidents
3. **Action:** Alert procurement team + CISO + supplier relationship manager
4. **Containment:** Suspend supplier account if high-risk (with approval gate)
5. Create incident ticket, add to Supplier Risk Dashboard

**Files:**
- `logic-apps/supply-chain-respond/workflow.json`
- `logic-apps/supply-chain-respond/README.md`

**Acceptance Criteria:**
- [ ] Workflow tested against sample incidents
- [ ] Approval gate functional (CISO review required before suspension)
- [ ] Integration with supplier management system (API connector)

**Estimated Effort:** 5 days

#### 2.3 Frontend: ChainShield Dashboard Module

**Location:** `frontend/src/modules/ChainShield.tsx` (new)

**Features:**
- **Supplier risk matrix:** Risk tier (low / medium / high / critical) vs. criticality (essential / important / optional)
- **Incident timeline:** Supply chain compromise timeline (who, when, how exposed)
- **Logistics anomalies:** Unusual shipment patterns, carrier changes, delivery route deviations
- **Third-party access audit:** List of suppliers currently accessing systems, last access, access pattern
- **Compliance tracking:** Supplier security questionnaires, audit status, contract renewal dates

**Data Structure:**
```json
{
  "suppliers": [
    {
      "id": "SUP-001",
      "name": "Global Logistics Inc",
      "risk_tier": "high",
      "criticality": "essential",
      "incidents": [
        {
          "type": "anomalous_access",
          "detected_at": "2026-06-15T10:23:00Z",
          "severity": "critical",
          "status": "investigating"
        }
      ],
      "last_access": "2026-06-16T08:15:00Z",
      "compliance_status": "compliant"
    }
  ]
}
```

**Acceptance Criteria:**
- [ ] Responsive design at all breakpoints
- [ ] Risk matrix renders with color-coded threat levels
- [ ] Incident timeline fully functional
- [ ] Integration into portal navigation

**Estimated Effort:** 8 days

#### 2.4 Documentation & Testing

**Files:**
- `docs/chainshield/threat-model.md`
- `docs/chainshield/deployment-guide.md`
- `tests/chainshield/test_cs_rules.py`

**Estimated Effort:** 5 days

### ChainShield Total Effort
**15 days (KQL) + 5 days (Playbook) + 8 days (Frontend) + 5 days (Docs/Tests) = 33 days**

---

## Component 3: Live Microsoft Sentinel Integration

### Overview
Replace demo data with **authenticated, real-time queries to the user's Microsoft Sentinel workspace**. This is the critical bridge between RetailShield (frontend) and live Sentinel data.

### Deliverables

#### 3.1 Backend API: Sentinel Query Executor

**Location:** `backend/src/sentinelApi.ts` (new)

**Functions:**
- `queryIncidents()` — Get live incidents from Sentinel workspace
- `queryAlerts()` — Get fired alerts by severity/rule
- `getWorkspaceStats()` — Dashboard KPIs (MTTD, incident volume, etc.)
- `getComplianceStatus()` — ICO/NCSC countdown timers
- `queryAnomalies()` — Loss Prevention + ChainShield incident feeds

**Tech Stack:**
- Node.js / Express backend (if not already present)
- Microsoft Graph API SDK (`@azure/identity`, `@azure/monitor-query`)
- Environment-based configuration (tenant ID, workspace ID, client credentials)

**Authentication:**
```typescript
// .env (user fills in their Azure credentials)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret (or use managed identity in production)
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_RESOURCE_GROUP=your-rg
SENTINEL_SUBSCRIPTION_ID=your-sub-id
```

**Dependencies:**
- User must have Microsoft Sentinel deployed in their Azure subscription
- User must have Query Analytics permission on the Sentinel workspace
- Azure AD app registration with appropriate permissions

**Acceptance Criteria:**
- [ ] Backend authenticates to Sentinel workspace via Azure SDK
- [ ] `queryIncidents()` successfully retrieves live incidents
- [ ] Error handling: workspace not found, auth failure, query timeout
- [ ] All queries execute within SLA (< 5 seconds for dashboard, < 30 seconds for full audit)
- [ ] Sensitive data (API keys) never exposed in frontend
- [ ] Tests: mock Sentinel API responses, verify parsing

**Estimated Effort:** 10 days

#### 3.2 Frontend Integration: Replace Demo Data

**Changes:**
1. **Dashboard pages:** Update all data fetches to call backend API instead of hardcoded demo data
   - Threat Detection module: incidents, MITRE heatmap, timeline
   - Compliance Centre: countdown timers, submission log
   - Loss Prevention: incident feed, store risk matrix
   - ChainShield: supplier incidents, logistics anomalies

2. **Configuration UI:** Add form to input/verify workspace details
   - Location: `frontend/src/pages/Settings/SentinelConfig.tsx` (new)
   - Fields: Tenant ID, Workspace ID, Client ID, Client Secret
   - Test button: "Verify Connection" → test query to Sentinel
   - Save: credentials stored securely (backend handles, frontend only stores auth token)

3. **Loading states & error handling:**
   - Show spinner while querying Sentinel
   - Display error message if query fails (with troubleshooting hint)
   - Graceful fallback to demo data for development/demo mode

**Acceptance Criteria:**
- [ ] All dashboard modules pull live data from Sentinel
- [ ] Sentinel Config page functional
- [ ] Error handling graceful (no uncaught exceptions)
- [ ] Performance acceptable (< 5s page load for dashboard)
- [ ] Works in demo mode (hardcoded demo data if API unavailable)

**Estimated Effort:** 8 days

#### 3.3 Configuration Management

**Location:** `config/environment.ts` (new) + documentation

**Environments:**
- **Development** (dev): Local Sentinel workspace or demo data
- **Staging** (staging): Shared test workspace
- **Production** (prod): Customer's live Sentinel workspace

**Config Structure:**
```typescript
// config/environment.ts
export const ENVIRONMENTS = {
  dev: {
    name: "Development",
    sentinelEnabled: false, // use demo data
    demoMode: true,
  },
  staging: {
    name: "Staging",
    sentinelEnabled: true,
    tenantId: process.env.STAGING_TENANT_ID,
    workspaceId: process.env.STAGING_WORKSPACE_ID,
  },
  prod: {
    name: "Production",
    sentinelEnabled: true,
    // credentials provided by user
  },
};
```

**Documentation:**
- `docs/integration/sentinel-setup.md` — Step-by-step workspace configuration
- `docs/integration/environment-config.md` — How to set up dev/staging/prod environments
- `docs/integration/troubleshooting.md` — Common connection issues

**Estimated Effort:** 4 days

#### 3.4 Testing & Documentation

**Tests:**
- Unit tests for Sentinel API client (mock responses)
- Integration test: end-to-end query and data transformation
- UI tests: settings form validation, connection test

**Documentation:**
- `docs/integration/getting-started.md` — For new users deploying RetailShield
- `docs/integration/api-reference.md` — For developers extending the integration

**Estimated Effort:** 5 days

### Live Sentinel Integration Total Effort
**10 days (API) + 8 days (Frontend) + 4 days (Config) + 5 days (Tests/Docs) = 27 days**

---

## Component 4: DevOps & Automated Deployment

### Overview
GitHub Actions pipeline to automate deployment of KQL rules, Logic Apps, and configuration to Sentinel workspace across dev/staging/production environments.

### Deliverables

#### 4.1 GitHub Actions Workflow: Rule Deployment

**Location:** `.github/workflows/deploy-rules.yml` (new)

**Trigger:** On push to `main` (production) or `dev` (development) branch

**Steps:**
1. **Validate:** Run `validate_kql.py` on all `.kql` files (syntax check)
2. **Test:** Run pytest on `tests/detection-rules/`
3. **Build:** (No build step; rules are already in final format)
4. **Deploy:** Use Azure CLI to create/update Sentinel Analytics Rules
   ```bash
   az sentinel alert-rule create \
     --workspace-name $SENTINEL_WORKSPACE \
     --resource-group $RESOURCE_GROUP \
     --rule-id "RS-LP-001" \
     --display-name "POS Void/Refund Abuse" \
     --query "detection-rules/retail/pos_void_refund.kql"
   ```

**Environment Variables:**
```yaml
env:
  AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
  AZURE_RESOURCE_GROUP: ${{ secrets.AZURE_RESOURCE_GROUP }}
  SENTINEL_WORKSPACE_NAME: ${{ secrets.SENTINEL_WORKSPACE_NAME }}
  DEPLOY_ENV: ${{ github.ref == 'refs/heads/main' && 'prod' || 'dev' }}
```

**Acceptance Criteria:**
- [ ] Workflow runs on push to main/dev
- [ ] Rules validate before deployment
- [ ] Tests pass before deployment
- [ ] Deployment succeeds (rules appear in Sentinel console)
- [ ] Failures trigger notifications (Slack/Email)

**Estimated Effort:** 6 days

#### 4.2 GitHub Actions Workflow: Playbook Deployment

**Location:** `.github/workflows/deploy-playbooks.yml` (new)

**Workflow:**
1. Validate Logic App JSON schemas
2. Test ARM template syntax
3. Deploy via `az deployment group create` for each playbook

**Acceptance Criteria:**
- [ ] All playbooks deploy successfully
- [ ] Playbook connectors configured (Sentinel, ServiceNow, Teams, etc.)
- [ ] Deployment includes environment-specific configuration

**Estimated Effort:** 5 days

#### 4.3 GitHub Actions Workflow: Configuration & Rollout

**Location:** `.github/workflows/deploy-config.yml` (new)

**Workflow:**
1. Deploy watchlists (CSV → Sentinel watchlist)
2. Deploy data connectors (if new data sources added)
3. Deploy workbook updates
4. Trigger post-deployment tests

**Acceptance Criteria:**
- [ ] Watchlists synced to Sentinel
- [ ] Workbook updated with latest modules
- [ ] Rollout process documented

**Estimated Effort:** 4 days

#### 4.4 Multi-Environment Support

**Workflow:**
- **Push to `dev` branch** → Deploy to development workspace (fast, loose validation)
- **Push to `main` branch** → Deploy to production workspace (strict validation, approval required)

**Implementation:**
```yaml
# .github/workflows/deploy-rules.yml
on:
  push:
    branches:
      - main
      - dev

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: ${{ github.ref == 'refs/heads/main' && 'production' || 'development' }}
    steps:
      - name: Deploy to ${{ env.DEPLOY_ENV }}
        run: |
          if [ "${{ env.DEPLOY_ENV }}" = "prod" ]; then
            # Strict validation, approval
          else
            # Faster deployment for dev
          fi
```

**Acceptance Criteria:**
- [ ] Dev deployments fast and frequent
- [ ] Prod deployments require approval (branch protection rule)
- [ ] Environment-specific secrets configured in GitHub (AZURE_SUBSCRIPTION_ID_PROD, etc.)

**Estimated Effort:** 3 days

#### 4.5 Deployment Documentation & Runbooks

**Files to Create:**
- `docs/devops/github-actions-setup.md` — How to configure GitHub Actions with Azure credentials
- `docs/devops/deployment-runbook.md` — Step-by-step for operators
- `docs/devops/rollback-procedures.md` — How to rollback a failed deployment

**Estimated Effort:** 3 days

### DevOps Total Effort
**6 days (Rules) + 5 days (Playbooks) + 4 days (Config) + 3 days (Multi-env) + 3 days (Docs) = 21 days**

---

## Phase 2 Implementation Timeline

### High-Level Schedule

```
Week 1-2 (June 24 - July 5)     Loss Prevention Rules & Playbook
Week 2-3 (July 1 - July 12)     Loss Prevention Frontend + ChainShield Rules
Week 3-4 (July 8 - July 19)     ChainShield Frontend + Sentinel Integration Backend
Week 4-5 (July 15 - July 26)    Sentinel Integration Frontend + Config UI
Week 5-6 (July 22 - Aug 2)      DevOps Pipelines + Testing
Week 6-7 (July 29 - Aug 9)      Documentation + QA
```

**Total Phase 2 Duration:** ~6-7 weeks (34 + 33 + 27 + 21 = 115 estimated days / ~5 days per week for solo developer = ~23 calendar weeks)

**Realistic Timeline with team of 2-3:** 6-7 weeks

### Week-by-Week Breakdown

#### Week 1: Loss Prevention Foundation
- **Days 1-3:** RS-LP-001 to RS-LP-003 KQL rules
- **Days 4-5:** Loss Prevention playbook skeleton
- **Deliverable:** 3 KQL rules merged to `dev` branch

#### Week 2: Loss Prevention Expansion
- **Days 1-3:** RS-LP-004, RS-LP-005 KQL rules
- **Days 4-5:** Loss Prevention playbook finalized
- **Deliverable:** All 5 KQL rules + playbook to `dev` branch

#### Week 3: Loss Prevention UI + ChainShield Rules
- **Days 1-4:** Loss Prevention dashboard module (React/Vite)
- **Days 5:** ChainShield KQL rules (1-2)
- **Deliverable:** Loss Prevention module in staging, ChainShield rules in progress

#### Week 4: ChainShield Completion
- **Days 1-2:** ChainShield KQL rules (3-4)
- **Days 3-5:** ChainShield playbook + dashboard module
- **Deliverable:** All ChainShield components in `dev` branch

#### Week 5: Sentinel Integration
- **Days 1-3:** Backend Sentinel API client
- **Days 4-5:** Frontend integration, Settings UI
- **Deliverable:** Live Sentinel data flowing to dashboard

#### Week 6: DevOps Pipelines
- **Days 1-3:** GitHub Actions workflows (rules + playbooks)
- **Days 4-5:** Multi-environment config, testing
- **Deliverable:** End-to-end deployment pipeline functional

#### Week 7: QA + Documentation
- **Days 1-3:** Testing, bug fixes, edge cases
- **Days 4-5:** Final documentation, runbooks, user guide
- **Deliverable:** Phase 2 release candidate (v2.1.0-rc1)

---

## Phase 2 Risk Register & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|-----------|
| **Sentinel API changes** (breaking changes in Microsoft updates) | High | Low | Monitor Azure SDK releases, pin dependencies, test in staging |
| **Data schema mismatch** (POS logs don't match expected format) | High | Medium | Work with data team early, create sample data, validate in dev |
| **Performance issues** (queries timeout for large datasets) | Medium | Medium | Test with realistic data volumes, optimize KQL queries, add caching |
| **Authentication failures** (user credentials invalid, permissions missing) | Medium | Medium | Clear error messages, troubleshooting guide, validate permissions early |
| **Scope creep** (feature requests mid-phase) | Medium | High | Lock scope now, create backlog for Phase 3 |

---

## Phase 2 Success Metrics

By end of Phase 2, measure:

✅ **Completeness:**
- [ ] All 9 KQL rules (5 LP + 4 ChainShield) deployed and alerting
- [ ] All 2 playbooks deployed and functional
- [ ] Loss Prevention + ChainShield modules in production
- [ ] Sentinel integration live (0% demo data in production)
- [ ] GitHub Actions pipelines running successfully

✅ **Quality:**
- [ ] 100% of KQL rules pass static validation
- [ ] 90%+ test coverage on backend API
- [ ] Zero critical bugs in production (UAT sign-off)
- [ ] Documentation complete and reviewed

✅ **Performance:**
- [ ] Dashboard page load < 5 seconds (95th percentile)
- [ ] Sentinel API queries complete within SLA
- [ ] Playbook execution < 2 minutes end-to-end

✅ **Adoption:**
- [ ] Runbook reviewed and signed off by SOC team
- [ ] Team trained on Loss Prevention & ChainShield workflows

---

## Next Steps

### Immediate Actions
1. **Validate KQL query patterns** — Review existing retail rules (RS-GCF-001, RS-SUP-001) for consistency
2. **Confirm data schema** — Work with data engineering to confirm POS, supplier, logistics log formats
3. **Prepare Azure environment** — Ensure dev/staging/prod Sentinel workspaces are ready
4. **Create GitHub project board** — Organize Phase 2 issues by component

### Pre-Phase 2 Checklist
- [ ] KQL rule pattern documented and agreed
- [ ] Data schemas finalized
- [ ] Azure credentials configured in GitHub secrets
- [ ] Team onboarded on this plan
- [ ] Budget / timeline approved

---

## Appendix: File Structure Changes

### New Directories
```
detection-rules/retail/
├── loss-prevention/
│   ├── pos_void_refund.kql          (RS-LP-001)
│   ├── gift_card_bulk_activation.kql (RS-LP-002)
│   ├── gift_card_rapid_redemption.kql (RS-LP-003)
│   ├── sweethearting_pattern.kql    (RS-LP-004)
│   └── after_hours_cash_drawer.kql  (RS-LP-005)
└── supply-chain/
    ├── supplier_account_anomaly.kql (RS-CS-001)
    ├── logistics_data_exfil.kql     (RS-CS-002)
    ├── supplier_impossible_travel.kql (RS-CS-003)
    └── procurement_manipulation.kql (RS-CS-004)

logic-apps/
├── loss-prevention-respond/
│   ├── workflow.json
│   └── README.md
└── supply-chain-respond/
    ├── workflow.json
    └── README.md

frontend/src/modules/
├── LossPrevention.tsx               (new)
├── ChainShield.tsx                  (new)
└── pages/Settings/
    └── SentinelConfig.tsx           (new)

backend/src/
├── sentinelApi.ts                   (new)
└── middleware/
    └── sentinelAuth.ts              (new)

.github/workflows/
├── deploy-rules.yml                 (new)
├── deploy-playbooks.yml             (new)
└── deploy-config.yml                (new)

docs/
├── loss-prevention/
│   ├── threat-model.md
│   └── deployment-guide.md
├── chainshield/
│   ├── threat-model.md
│   └── deployment-guide.md
├── integration/
│   ├── sentinel-setup.md
│   ├── environment-config.md
│   ├── troubleshooting.md
│   └── api-reference.md
└── devops/
    ├── github-actions-setup.md
    ├── deployment-runbook.md
    └── rollback-procedures.md
```

---

## Document Control

| Version | Date | Author | Change |
|---------|------|--------|--------|
| 1.0 | 2026-06-16 | TFT444 | Initial draft — Phase 2 plan |

---

**Ready to create GitHub Issues? Let me know! 🚀**
