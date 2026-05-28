# RetailShield Scripts

**ShieldTech Ltd | Tanvir Farhad | 2026**

Utility scripts for the RetailShield Microsoft Sentinel detection platform.

---

## Scripts

| Script | Purpose |
|---|---|
| `validate_kql.py` | Validates all KQL detection rules for metadata, syntax, and table references |
| `validate_logicapps.py` | Validates Logic App ARM templates as valid JSON with required schema keys |
| `retail_log_generator.py` | Generates synthetic retail logs and ships them to a Sentinel workspace |
| `cve_scanner.py` | Scans simulated retail infrastructure against the retail CVE database |
| `cve_database.json` | 32 retail-specific CVEs covering POS, payment terminals, stock management, and retail platforms |

---

## cve_scanner.py

Scans simulated retail infrastructure against `cve_database.json` — a database of 32 retail-specific CVEs covering POS systems, payment terminals, stock management platforms, and retail applications. Identifies vulnerable assets, CVSS scores, MITRE ATT&CK mappings, and patch status.

This addresses the gap left by generic CVE scanners that have no awareness of retail-specific software stacks.

### Prerequisites

No third-party dependencies — uses Python standard library only.

```bash
python --version   # Python 3.8+
```

### Usage

```bash
# Deep scan — all categories, text output (default)
python cve_scanner.py

# Quick scan — POS systems + payment terminals only
python cve_scanner.py --mode quick

# Deep scan with JSON report saved to file
python cve_scanner.py --mode deep --output json --out-file report.json

# Dry run — scan and print first 3 findings to console, no file written
python cve_scanner.py --dry-run
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--mode` | `quick` (POS + terminals) or `deep` (all 4 categories) | `deep` |
| `--output` | `text` (human-readable) or `json` (machine-readable) | `text` |
| `--dry-run` | Print first 3 findings to console, no file written | off |
| `--out-file` | Filename for JSON output | `cve_report.json` |

### Scan Modes

| Mode | Categories Scanned | Use Case |
|---|---|---|
| `quick` | POS systems, payment terminals | Fast daily scan of customer-facing hardware |
| `deep` | POS systems, stock management, payment terminals, retail platforms | Full weekly infrastructure review |

---

## cve_database.json

Retail-specific CVE database with 32 vulnerabilities across 4 categories. Each CVE includes:

| Field | Description |
|---|---|
| `cve_id` | CVE identifier (e.g. `CVE-2025-44123`) |
| `cvss_score` | CVSS v3.1 base score (0.0 – 10.0) |
| `severity` | `critical` / `high` / `medium` / `low` |
| `product` | Affected retail software |
| `vendor` | Software vendor |
| `category` | `pos_system` / `stock_management` / `payment_terminal` / `retail_platform` |
| `affected_versions` | List of vulnerable version strings |
| `fixed_version` | First patched version |
| `description` | Technical vulnerability description |
| `mitre_technique` | MITRE ATT&CK technique ID |
| `mitre_tactic` | MITRE ATT&CK tactic |
| `patch_available` | Whether a patch has been released |
| `exploit_available` | Whether a public exploit exists |
| `published_date` | CVE publication date |
| `cvss_vector` | Full CVSS v3.1 vector string |

### Coverage

| Category | Products Covered | CVEs |
|---|---|---|
| POS Systems | Oracle Xstore, NCR Aloha, Toshiba TCx, Verifone POS | 8 |
| Stock Management | SAP Retail, Microsoft Dynamics Retail, Oracle Retail Merchandising, JDA Supply Chain | 8 |
| Payment Terminals | Verifone VX520, Verifone P400, Ingenico iCT250, PAX S920 | 8 |
| Retail Platforms | Shopify POS, Square POS, Lightspeed Retail, Revel POS | 8 |

### Sample Output — Text Mode

```
╔══════════════════════════════════════════════════════════════════════╗
║  RetailShield CVE Vulnerability Scanner — Scan Report               ║
║  ShieldTech Ltd · Tanvir Farhad · 2026                              ║
╚══════════════════════════════════════════════════════════════════════╝

  Scan ID    : RS-SCAN-20260528-143022
  Timestamp  : 2026-05-28T14:30:22Z
  Mode       : DEEP
  Assets     : 18 scanned / 18 total
  Vulnerable : 18 assets
  CVEs found : 36

  Severity Breakdown:
    CRITICAL                           8
    HIGH                              24
    MEDIUM                             4

────────────────────────────────────────────────────────────────────────
  ASSET ID               PRODUCT                           CVEs
────────────────────────────────────────────────────────────────────────
  POS-TILL-01            Oracle Xstore POS                    2
    CVE-2025-44123       CVSS 9.8  CRITICAL  ✓ Patch available [EXPLOIT PUBLIC]
    MITRE: T1190 — Initial Access
    ...
```

### Sample Output — JSON Mode

```json
{
  "scan_id": "RS-SCAN-20260528-143022",
  "timestamp": "2026-05-28T14:30:22Z",
  "mode": "deep",
  "total_assets": 18,
  "assets_scanned": 18,
  "assets_vulnerable": 18,
  "vulnerabilities_found": 36,
  "summary": { "critical": 8, "high": 24, "medium": 4, "low": 0 },
  "findings": [
    {
      "asset_id": "POS-TILL-01",
      "product": "Oracle Xstore POS",
      "version": "8.1",
      "location": "Hounslow Branch",
      "vulnerabilities": [ ... ]
    }
  ]
}
```

---

---

## retail_log_generator.py

Generates realistic retail environment log events — POS transactions, phishing attempts, credential stuffing, ransomware staging, data exfiltration, and AI voice fraud — and sends them to a Microsoft Sentinel Log Analytics workspace via the [Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api).

Use this to populate your Sentinel workspace with test data so you can validate detection rules without waiting for real incidents.

### Prerequisites

```bash
pip install requests faker
```

### Configuration

Before connecting to a live Sentinel workspace, open `retail_log_generator.py` and replace the two placeholders at the top:

```python
WORKSPACE_ID = "YOUR_WORKSPACE_ID"   # Azure Portal → Log Analytics → Overview
SHARED_KEY   = "YOUR_SHARED_KEY"     # Log Analytics → Agents → Primary key
```

> **Tip:** Never commit real credentials. Use environment variables or Azure Key Vault in production.

### Usage

```bash
# Dry run — generates logs and prints first 3 to console, sends nothing
python retail_log_generator.py --dry-run

# Normal mode — 100 POS transactions (default count)
python retail_log_generator.py --mode normal

# Attack mode — one of each threat event (5 logs total)
python retail_log_generator.py --mode attack

# Mixed mode — 80 normal POS logs + 5 attack events, shuffled (default)
python retail_log_generator.py --mode mixed

# Custom count
python retail_log_generator.py --mode normal --count 500
python retail_log_generator.py --mode mixed  --count 250
```

### Modes

| Mode | Description | Log count |
|---|---|---|
| `normal` | POS transactions only — SALE, REFUND, VOID weighted 75/15/10 | `--count` (default 100) |
| `attack` | One of each threat event injected in sequence | Always 5 |
| `mixed` | 80% normal POS traffic + all 5 attack events, randomly shuffled | `--count` + 5 |
| `--dry-run` | Runs in mixed mode logic but prints to console instead of sending | Same as mixed |

---

## Log Types Generated

All logs are sent to the custom table `RetailShield_Logs_CL` in your Sentinel workspace.

### POS_Transaction

Simulates normal point-of-sale activity across three branches and four terminals.

| Field | Example |
|---|---|
| `EventType` | `POS_Transaction` |
| `StoreID` | `STORE-001` |
| `TerminalID` | `POS-003` |
| `OperatorName` | `Sarah Mitchell` |
| `TransactionType` | `SALE` / `REFUND` / `VOID` |
| `TotalAmount` | `290.00` |
| `PaymentMethod` | `CONTACTLESS` |
| `SuspicionScore` | `0` |
| `Severity` | `INFO` |

### Phishing_Detected — T1566.001

Simulates spearphishing email with malicious attachment targeting retail staff.

| Field | Example |
|---|---|
| `SenderAddress` | `supplier-invoices@dr4gonmail.com` |
| `Subject` | `URGENT: Invoice overdue - immediate action required` |
| `AttachmentType` | `docm` |
| `PhishingScore` | `94` |
| `MITRETechnique` | `T1566.001` |
| `Severity` | `HIGH` |

### Credential_Stuffing — T1110.004

Simulates distributed credential stuffing against the POS admin portal.

| Field | Example |
|---|---|
| `SourceIP` | `185.220.101.47` |
| `TargetSystem` | `POS_Admin` |
| `FailedAttempts` | `217` |
| `GeoLocation` | `Russia` |
| `MITRETechnique` | `T1110.004` |
| `Severity` | `HIGH` |

### Ransomware_Indicator — T1486

Simulates ransomware staging: mass file modification, shadow copy deletion, C2 beacon.

| Field | Example |
|---|---|
| `DeviceName` | `WORKSTATION-12` |
| `FilesModified` | `463` |
| `SuspiciousExtension` | `.locked` |
| `ShadowCopyDeleted` | `true` |
| `RansomwareFamily` | `LockBit` |
| `MITRETechnique` | `T1486` |
| `Severity` | `CRITICAL` |

### Data_Exfiltration — T1048

Simulates large outbound data transfer from the customer database to an external IP.

| Field | Example |
|---|---|
| `SourceUser` | `Omar Hussain` |
| `DestinationIP` | `91.234.55.12` |
| `DataTransferredMB` | `1847.3` |
| `DestinationPort` | `4444` |
| `SystemSource` | `Customer_Database` |
| `MITRETechnique` | `T1048` |
| `Severity` | `CRITICAL` |

### AI_Voice_Deepfake — T1598

Simulates an AI-generated voice fraud call impersonating management.

| Field | Example |
|---|---|
| `TargetEmployee` | `Priya Patel` |
| `AIConfidenceScore` | `0.97` |
| `ImpersonatingEntity` | `Area Manager` |
| `RequestMade` | `Delivery redirect to alternative address` |
| `MITRETechnique` | `T1598` |
| `Severity` | `CRITICAL` |

---

## Connecting to Microsoft Sentinel

1. **Get your Workspace ID and Primary Key**
   - Azure Portal → Log Analytics workspaces → your workspace → Agents management
   - Copy **Workspace ID** and **Primary key**

2. **Set the values** in `retail_log_generator.py`:
   ```python
   WORKSPACE_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   SHARED_KEY   = "base64encodedkeyhere=="
   ```

3. **Run in attack mode** to inject threat events:
   ```bash
   python retail_log_generator.py --mode attack
   # Sent 5 logs — Status: 200
   ```

4. **Query in Sentinel** (allow 5–10 minutes for ingestion):
   ```kql
   RetailShield_Logs_CL
   | where Severity_s == "CRITICAL"
   | order by TimeGenerated desc
   ```

---

## Data Sources (Simulated)

| Source | Description |
|---|---|
| **Stores** | Hounslow, Hammersmith, Ealing branches |
| **Staff** | 4 employees across BOH Manager, Sales Associate, Store Manager, BOH Associate roles |
| **Terminals** | POS-001 through POS-004 |
| **Products** | Nike Air Max 270, Nike React Miler, Adidas Ultraboost |
| **Malicious IPs** | 185.220.101.47, 172.16.0.45, 203.45.12.88, 91.234.55.12 |
| **Phishing domains** | dr4gonmail.com, hrnike-secure.net |

---

## Author

**Tanvir Farhad** — ShieldTech Ltd, London
[github.com/TFT444/RetailShield](https://github.com/TFT444/RetailShield)
