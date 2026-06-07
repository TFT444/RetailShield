#!/usr/bin/env python3
"""
RetailShield — Retail Web Vulnerability Scanner
Scans retail web applications for 13 common security vulnerabilities.

Checks 1-9, 12, 13  — PASSIVE (observation only, no payloads sent)
Checks 10-11        — ACTIVE (SQL injection and XSS detection; requires
                      explicit written permission from the system owner)

Usage:
    python retail_vuln_scanner.py --target https://shop.example.com
    python retail_vuln_scanner.py --target https://shop.example.com --active \\
        --tester "Jane Smith" --permission-from "ACME Retail Ltd" \\
        --permission-date 2026-06-07
    python retail_vuln_scanner.py --target https://shop.example.com --output json

Requires: Python 3.9+  |  pip install requests
"""

import sys
import re
import json
import time
import socket
import ssl
import argparse
import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

try:
    import requests
    from requests.exceptions import RequestException, SSLError as ReqSSLError
except ImportError:
    print("[ERROR] requests library required: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Output paths ────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR.parent / "scan-results"
AUDIT_DIR = OUTPUT_DIR / "audit-logs"

# ── ANSI colours ────────────────────────────────────────────────────────────────
C = {
    "red": "\033[91m",
    "orange": "\033[93m",
    "yellow": "\033[33m",
    "green": "\033[92m",
    "blue": "\033[94m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

SEV_COLOUR = {
    "critical": C["red"],
    "high":     C["orange"],
    "medium":   C["yellow"],
    "low":      C["green"],
    "info":     C["blue"],
}

# ── SQL error fingerprints ───────────────────────────────────────────────────────
_SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ora-\d{4,5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlite_exception",
    r"pg::syntaxerror",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array",
    r"syntax error or access violation",
    r"db2 sql error",
    r"invalid sql statement",
    r"sql command not properly ended",
]
SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)

SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "admin'--",
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"

# ── Paths to probe ───────────────────────────────────────────────────────────────
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/wp-admin",
    "/phpmyadmin", "/manager", "/cpanel", "/dashboard/admin",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/config.php", "/wp-config.php", "/web.config",
    "/server-status", "/phpinfo.php",
    "/.htpasswd", "/backup.zip", "/db.sql",
]

PAYMENT_PATHS = [
    "/checkout", "/payment", "/cart",
    "/pay", "/order", "/billing",
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS",
     "high",   "HTTPS downgrade and MITM attacks are possible"),
    ("Content-Security-Policy",   "CSP",
     "high",   "No CSP — XSS and data injection not mitigated"),
    ("X-Content-Type-Options",   "MIME sniffing protection",
     "medium", "Browsers may execute misidentified content types"),
    ("X-XSS-Protection",         "Browser XSS filter",
     "low",    "Legacy XSS filter disabled (low impact when CSP present)"),
    ("Referrer-Policy",          "Referrer leakage control",
     "low",    "Full URL may leak to third parties via Referer header"),
    ("Permissions-Policy",       "Feature policy",
     "low",    "Browser features (camera, geolocation) not restricted"),
]


# ── Scanner ─────────────────────────────────────────────────────────────────────
class Scanner:
    def __init__(self, target, active, tester, permission_from, permission_date,
                 timeout):
        self.target = target.rstrip("/")
        self.active = active
        self.tester = tester
        self.permission_from = permission_from
        self.permission_date = permission_date
        self.timeout = timeout
        self.findings = []
        self.audit_log = []
        self.start_time = datetime.datetime.now(datetime.timezone.utc)

        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "RetailShield-VulnScanner/1.0 (Authorised Security Testing)"
        )

    # ── Helpers ──────────────────────────────────────────────────────────────────
    def _log(self, check_num, check_name, target_url, payload=None):
        self.audit_log.append({
            "timestamp":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "check":          f"Check {check_num}: {check_name}",
            "target_url":     target_url,
            "payload":        payload,
            "tester":         self.tester,
            "permission_from": self.permission_from,
            "permission_date": self.permission_date,
        })

    def _finding(self, check_num, severity, title, detail,
                 parameter=None, remediation=None):
        entry = {
            "check":       check_num,
            "severity":    severity,
            "title":       title,
            "detail":      detail,
            "parameter":   parameter,
            "remediation": remediation,
        }
        self.findings.append(entry)
        col = SEV_COLOUR.get(severity, "")
        B, R = C["bold"], C["reset"]
        print(f"  {col}{B}[{severity.upper()}]{R} {title}")
        if parameter:
            print(f"  {C['dim']}  Parameter : {parameter}{R}")
        print(f"  {C['dim']}  {detail}{R}")
        if remediation:
            print(f"  {C['blue']}  Fix: {remediation}{R}")

    def _ok(self, msg):
        print(f"  {C['green']}✓{C['reset']} {msg}")

    def _get(self, path_or_url, params=None, allow_redirects=True, verify=True):
        url = (path_or_url if path_or_url.startswith("http")
               else f"{self.target}{path_or_url}")
        try:
            r = self.session.get(url, params=params, timeout=self.timeout,
                                 allow_redirects=allow_redirects, verify=verify)
            return r, None
        except ReqSSLError as e:
            return None, f"SSL error: {e}"
        except RequestException as e:
            return None, str(e)

    # ── Check 1: SSL/TLS ─────────────────────────────────────────────────────────
    def check_ssl(self):
        parsed = urlparse(self.target)
        self._log(1, "SSL/TLS Certificate", self.target)

        if parsed.scheme != "https":
            self._finding(1, "high", "Site not served over HTTPS",
                          "Target uses HTTP, not HTTPS.",
                          remediation="Configure HTTPS with a valid TLS 1.2+ certificate.")
            return

        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_ver = ssock.version()
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_left = (not_after - time.time()) / 86400

                    if days_left < 30:
                        sev = "critical" if days_left < 7 else "high"
                        self._finding(1, sev, "SSL certificate expiring soon",
                                      f"Certificate expires in {int(days_left)} days "
                                      f"({cert['notAfter']}).",
                                      remediation="Renew the TLS certificate immediately.")
                    else:
                        self._ok(f"SSL certificate valid ({int(days_left)} days remaining)")

                    if tls_ver in ("TLSv1", "TLSv1.1"):
                        self._finding(1, "high", f"Outdated TLS version: {tls_ver}",
                                      "TLS 1.0 and 1.1 are deprecated and insecure.",
                                      remediation="Disable TLS 1.0/1.1; enable TLS 1.2+ only.")
                    else:
                        self._ok(f"TLS version: {tls_ver}")
        except ssl.CertificateError as e:
            self._finding(1, "critical", "SSL certificate validation failed", str(e),
                          remediation="Install a valid, trusted TLS certificate.")
        except Exception as e:
            self._finding(1, "medium", "Could not verify SSL certificate", str(e),
                          remediation="Verify SSL configuration manually.")

    # ── Check 2: HTTPS redirect ──────────────────────────────────────────────────
    def check_https_redirect(self):
        parsed = urlparse(self.target)
        if parsed.scheme == "http":
            return  # already flagged in check 1

        http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
        self._log(2, "HTTPS Redirect", http_url)

        try:
            r = self.session.get(http_url, timeout=self.timeout,
                                 allow_redirects=False, verify=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                self._ok(f"HTTP → HTTPS redirect in place (HTTP {r.status_code})")
            else:
                self._finding(2, "high", "No HTTPS redirect on HTTP",
                              f"HTTP responds with {r.status_code}; "
                              "customers may browse over unencrypted HTTP.",
                              remediation="Configure a permanent 301 redirect from HTTP to HTTPS.")
        except RequestException:
            pass

    # ── Check 3: Security headers ────────────────────────────────────────────────
    def check_security_headers(self):
        self._log(3, "Security Headers", self.target)
        r, err = self._get("/")
        if err or not r:
            self._finding(3, "info", "Could not fetch homepage", err or "No response")
            return

        present = {k.lower() for k in r.headers}
        for header, label, severity, impact in SECURITY_HEADERS:
            if header.lower() in present:
                self._ok(f"{header} present")
            else:
                self._finding(3, severity, f"Missing security header: {header}",
                              f"{label}: {impact}.",
                              remediation=f"Add '{header}' to all HTTP responses.")

    # ── Check 4: Cookie security flags ───────────────────────────────────────────
    def check_cookie_security(self):
        self._log(4, "Cookie Security Flags", self.target)
        r, err = self._get("/")
        if err or not r:
            return

        raw_cookies = r.raw.headers.getlist("Set-Cookie")
        if not raw_cookies:
            raw_cookies = [v for k, v in r.raw.headers.items()
                           if k.lower() == "set-cookie"]
        if not raw_cookies:
            print(f"  {C['dim']}  No cookies set on homepage{C['reset']}")
            return

        for hdr in raw_cookies:
            name = hdr.split("=")[0].strip()
            flags = hdr.lower()
            if "secure" not in flags:
                self._finding(4, "high", f"Cookie missing Secure flag: {name!r}",
                              f"Cookie {name!r} can be sent over HTTP.",
                              parameter=name,
                              remediation=f"Add 'Secure' flag to the {name!r} cookie.")
            if "httponly" not in flags:
                self._finding(4, "medium", f"Cookie missing HttpOnly flag: {name!r}",
                              f"Cookie {name!r} is accessible via JavaScript "
                              "(XSS risk).",
                              parameter=name,
                              remediation=f"Add 'HttpOnly' flag to the {name!r} cookie.")
            if "samesite" not in flags:
                self._finding(4, "medium", f"Cookie missing SameSite flag: {name!r}",
                              f"Cookie {name!r} has no SameSite attribute (CSRF risk).",
                              parameter=name,
                              remediation=(f"Add 'SameSite=Strict' or 'SameSite=Lax' "
                                           f"to the {name!r} cookie."))

    # ── Check 5: Admin endpoint exposure ────────────────────────────────────────
    def check_admin_exposure(self):
        self._log(5, "Admin Endpoint Exposure", self.target)
        found_any = False
        for path in ADMIN_PATHS:
            r, err = self._get(path, allow_redirects=False)
            if err or not r:
                continue
            if r.status_code in (200, 301, 302, 403):
                found_any = True
                sev = "critical" if r.status_code == 200 else "medium"
                self._finding(5, sev, f"Admin endpoint exposed: {path}",
                              f"HTTP {r.status_code} at {self.target}{path}.",
                              parameter=path,
                              remediation=("Restrict admin access by IP allowlist or VPN. "
                                           "Do not expose admin panels to the public internet."))
        if not found_any:
            self._ok("No admin endpoints found at standard paths")

    # ── Check 6: Sensitive file exposure ─────────────────────────────────────────
    def check_sensitive_files(self):
        self._log(6, "Sensitive File Exposure", self.target)
        found_any = False
        for path in SENSITIVE_PATHS:
            r, err = self._get(path, allow_redirects=False)
            if err or not r:
                continue
            if r.status_code == 200 and len(r.text) > 10:
                found_any = True
                self._finding(6, "critical", f"Sensitive file exposed: {path}",
                              "File returns HTTP 200 with content — may expose "
                              "credentials or server configuration.",
                              parameter=path,
                              remediation=(f"Remove {path} from the web root or block "
                                           "access via web server rules."))
        if not found_any:
            self._ok("No sensitive files found at standard paths")

    # ── Check 7: Server information disclosure ───────────────────────────────────
    def check_server_disclosure(self):
        self._log(7, "Server Information Disclosure", self.target)
        r, err = self._get("/")
        if err or not r:
            return
        found = False
        for hdr in ("Server", "X-Powered-By", "X-AspNet-Version",
                    "X-Generator", "X-Runtime"):
            val = r.headers.get(hdr)
            if val:
                found = True
                self._finding(7, "low", f"Server version disclosed via {hdr} header",
                              f"'{hdr}: {val}' reveals software to attackers.",
                              remediation=(f"Remove or sanitise the {hdr!r} header "
                                           "(ServerTokens Prod / server_tokens off)."))
        if not found:
            self._ok("No server version headers detected")

    # ── Check 8: CORS misconfiguration ───────────────────────────────────────────
    def check_cors(self):
        self._log(8, "CORS Misconfiguration", self.target)
        try:
            r = self.session.get(
                self.target + "/",
                headers={"Origin": "https://evil.example.com"},
                timeout=self.timeout, verify=True,
            )
        except RequestException:
            return

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            self._finding(8, "medium",
                          "Permissive CORS: Access-Control-Allow-Origin: *",
                          "Any origin can read API responses.",
                          remediation="Restrict CORS to specific trusted origins.")
        elif acao == "https://evil.example.com":
            sev = "critical" if acac == "true" else "high"
            detail = ("Server mirrors Origin header"
                      + (", and allows credentials." if acac == "true" else "."))
            self._finding(8, sev, "CORS reflects arbitrary Origin header",
                          detail,
                          remediation=(
                              "Implement an origin allowlist; "
                              "never reflect arbitrary Origins."))
        else:
            self._ok("CORS policy does not reflect arbitrary origins")

    # ── Check 9: Directory listing ───────────────────────────────────────────────
    def check_directory_listing(self):
        self._log(9, "Directory Listing", self.target)
        found = False
        for path in ("/images/", "/static/", "/assets/", "/uploads/", "/files/"):
            r, err = self._get(path, allow_redirects=False)
            if err or not r or r.status_code != 200:
                continue
            if "index of" in r.text.lower() or "parent directory" in r.text.lower():
                found = True
                self._finding(9, "medium", f"Directory listing enabled: {path}",
                              f"Web server returns a file listing at {path}.",
                              parameter=path,
                              remediation=("Disable directory listing: 'Options -Indexes' "
                                           "(Apache) or 'autoindex off' (nginx)."))
        if not found:
            self._ok("No directory listing found at standard paths")

    # ── Check 10: SQL injection (ACTIVE) ─────────────────────────────────────────
    def check_sql_injection(self):
        """
        Detection-only. Tests URL parameters with SQL payloads and inspects
        responses for database error patterns. NEVER extracts data.
        """
        r, err = self._get("/")
        if err or not r:
            return

        # Collect URLs with query parameters from the homepage + common paths
        param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', r.text)
        common = [
            "/search?q=test", "/product?id=1", "/category?id=1",
            "/page?id=1", "/item?sku=1",
        ]
        for p in common:
            param_urls.append(f"{self.target}{p}")

        tested = set()
        for url in param_urls[:20]:
            full = url if url.startswith("http") else f"{self.target}{url}"
            parsed = urlparse(full)
            params = dict(parse_qsl(parsed.query))
            if not params:
                continue

            for param_name in params:
                key = (parsed.path, param_name)
                if key in tested:
                    continue
                tested.add(key)

                for payload in SQL_PAYLOADS:
                    test_url = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
                    test_params = dict(params)
                    test_params[param_name] = payload

                    self._log(10, "SQL Injection Detection", test_url, payload)

                    try:
                        resp = self.session.get(test_url, params=test_params,
                                                timeout=self.timeout, verify=True)
                        if SQL_ERROR_RE.search(resp.text):
                            self._finding(
                                10, "critical",
                                "SQL injection vulnerability detected",
                                f"Parameter {param_name!r} at {parsed.path} returned "
                                f"a database error for payload {payload!r}. "
                                "Unparameterised SQL query confirmed.",
                                parameter=param_name,
                                remediation=("Use parameterised queries / prepared "
                                             "statements. Never interpolate user input "
                                             "into SQL strings."))
                            return
                    except RequestException:
                        continue
                    time.sleep(0.2)

    # ── Check 11: XSS detection (ACTIVE) ─────────────────────────────────────────
    def check_xss(self):
        """
        Detection-only. Injects a non-executing payload and checks whether it
        reflects back unescaped. NEVER executes scripts in a real browser.
        """
        r, err = self._get("/")
        if err or not r:
            return

        param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', r.text)
        search_paths = [
            ("/search", "q"),
            ("/find", "q"),
            ("/products", "search"),
            ("/catalogue", "search"),
            ("/items", "q"),
        ]

        tested = set()

        # Test URL parameters found on homepage
        for url in param_urls[:10]:
            full = url if url.startswith("http") else f"{self.target}{url}"
            parsed = urlparse(full)
            params = dict(parse_qsl(parsed.query))
            for param_name in params:
                if param_name in tested:
                    continue
                tested.add(param_name)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                test_params = dict(params)
                test_params[param_name] = XSS_PAYLOAD

                self._log(11, "XSS Reflection Detection", test_url, XSS_PAYLOAD)
                try:
                    resp = self.session.get(test_url, params=test_params,
                                            timeout=self.timeout, verify=True)
                    if XSS_PAYLOAD in resp.text:
                        self._finding(
                            11, "high",
                            "Reflected XSS vulnerability detected",
                            f"Parameter {param_name!r} at {parsed.path} reflects "
                            "the XSS payload unescaped. An attacker can craft a "
                            "malicious link to steal session cookies.",
                            parameter=param_name,
                            remediation=("HTML-encode all user input before rendering. "
                                         "Implement a Content-Security-Policy header."))
                        return
                except RequestException:
                    continue
                time.sleep(0.2)

        # Test common search/query endpoints
        for path, param in search_paths:
            if param in tested:
                continue
            tested.add(param)
            self._log(11, "XSS Reflection Detection",
                      f"{self.target}{path}", XSS_PAYLOAD)
            try:
                resp = self.session.get(f"{self.target}{path}",
                                        params={param: XSS_PAYLOAD},
                                        timeout=self.timeout, verify=True)
                if resp.status_code == 200 and XSS_PAYLOAD in resp.text:
                    self._finding(
                        11, "high",
                        "Reflected XSS vulnerability detected",
                        f"Search parameter {param!r} at {path} reflects the payload "
                        "unescaped. An attacker can craft a malicious search URL.",
                        parameter=param,
                        remediation=("HTML-encode all user input before rendering. "
                                     "Implement a Content-Security-Policy header."))
                    return
            except RequestException:
                continue
            time.sleep(0.2)

    # ── Check 12: Clickjacking ───────────────────────────────────────────────────
    def check_clickjacking(self):
        self._log(12, "Clickjacking Protection", self.target)
        r, err = self._get("/")
        if err or not r:
            return

        xfo = r.headers.get("X-Frame-Options", "").upper()
        csp = r.headers.get("Content-Security-Policy", "").lower()

        has_xfo = xfo in ("DENY", "SAMEORIGIN")
        has_frame_anc = "frame-ancestors" in csp

        if not has_xfo and not has_frame_anc:
            self._finding(
                12, "high", "Clickjacking protection missing",
                "No X-Frame-Options or CSP frame-ancestors set. "
                "The site can be embedded in an attacker's iframe — "
                "retail sites without this can be overlaid to steal card details.",
                remediation=("Add 'X-Frame-Options: DENY' or "
                             "'Content-Security-Policy: frame-ancestors none'."))
        else:
            prot = xfo if has_xfo else "CSP frame-ancestors"
            self._ok(f"Clickjacking protection: {prot}")

    # ── Check 13: Payment page security ─────────────────────────────────────────
    def check_payment_pages(self):
        self._log(13, "Payment Page Security", self.target)
        found_any = False

        for path in PAYMENT_PATHS:
            r, err = self._get(path, allow_redirects=False)
            if err or not r or r.status_code not in (200, 301, 302, 307, 308):
                continue
            found_any = True

            url = f"{self.target}{path}"
            if urlparse(url).scheme != "https":
                self._finding(13, "critical",
                              f"Payment page not on HTTPS: {path}",
                              "PCI DSS Req 4 mandates TLS for cardholder data.",
                              parameter=path,
                              remediation="Force HTTPS on all payment pages.")

            # Follow redirects to get actual page content
            full_r, _ = self._get(path, allow_redirects=True)
            if not full_r or full_r.status_code != 200:
                continue

            # Mixed content
            http_srcs = re.findall(
                r'(?:src|href|action)=["\']http://[^"\']+["\']',
                full_r.text, re.IGNORECASE,
            )
            if http_srcs:
                self._finding(13, "high",
                              f"Mixed content on payment page: {path}",
                              f"{len(http_srcs)} HTTP resource(s) on an HTTPS page. "
                              "Network attackers can intercept these resources.",
                              parameter=path,
                              remediation=("Replace all HTTP URLs with HTTPS. "
                                           "Enable 'upgrade-insecure-requests' CSP directive."))

            # CSP on payment page (PCI DSS v4.0 Req 6.4.3)
            if not full_r.headers.get("Content-Security-Policy", ""):
                self._finding(13, "high",
                              f"No CSP on payment page: {path}",
                              "PCI DSS v4.0 Req 6.4.3 requires script control via CSP "
                              "on all payment pages.",
                              parameter=path,
                              remediation=("Implement a strict Content-Security-Policy "
                                           "on all payment pages per PCI DSS v4.0 Req 6.4.3."))

        if not found_any:
            print(f"  {C['dim']}  No payment pages found at standard paths{C['reset']}")

    # ── Run loop ─────────────────────────────────────────────────────────────────
    def _run_check(self, num, name, fn):
        B, R = C["bold"], C["reset"]
        print(f"\n{B}[{num:02d}] {name}{R}")
        try:
            fn()
        except Exception as e:
            print(f"  {C['dim']}  Unexpected error: {e}{C['reset']}")

    def run(self):
        passive = [
            (1,  "SSL/TLS Certificate",           self.check_ssl),
            (2,  "HTTPS Redirect",                self.check_https_redirect),
            (3,  "Security Headers",              self.check_security_headers),
            (4,  "Cookie Security Flags",         self.check_cookie_security),
            (5,  "Admin Endpoint Exposure",       self.check_admin_exposure),
            (6,  "Sensitive File Exposure",       self.check_sensitive_files),
            (7,  "Server Information Disclosure", self.check_server_disclosure),
            (8,  "CORS Misconfiguration",         self.check_cors),
            (9,  "Directory Listing",             self.check_directory_listing),
            (12, "Clickjacking Protection",       self.check_clickjacking),
            (13, "Payment Page Security",         self.check_payment_pages),
        ]
        B, R = C["bold"], C["reset"]
        print(f"\n{B}── Passive Checks (1–9, 12–13) {'─' * 28}{R}")
        for num, name, fn in passive:
            self._run_check(num, name, fn)

        if self.active:
            active = [
                (10, "SQL Injection Detection", self.check_sql_injection),
                (11, "XSS Detection",           self.check_xss),
            ]
            print(f"\n{B}── Active Checks (10–11) — Authorised Tests {'─' * 21}{R}")
            for num, name, fn in active:
                self._run_check(num, name, fn)

    # ── Reporting ────────────────────────────────────────────────────────────────
    def _permission_statement(self):
        return (
            f"Tests performed by {self.tester or '[name]'} with permission "
            f"from {self.permission_from or '[company]'} on "
            f"{self.permission_date or '[date]'}"
        )

    def print_report(self):
        B, R, D = C["bold"], C["reset"], C["dim"]
        print(f"\n{B}{'=' * 64}{R}")
        print(f"{B}  RETAILSHIELD WEB VULNERABILITY SCANNER — REPORT{R}")
        print(f"{B}{'=' * 64}{R}")
        print(f"  Target     : {self.target}")
        print(f"  Scanned    : "
              f"{self.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Mode       : "
              f"{'Passive + Active' if self.active else 'Passive only'}")
        print(f"  {self._permission_statement()}")
        print(f"{B}{'=' * 64}{R}\n")

        if not self.findings:
            print(f"  {C['green']}{B}No vulnerabilities found.{R}\n")
        else:
            counts = {}
            for f in self.findings:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1

            for f in self.findings:
                sev = f["severity"]
                col = SEV_COLOUR.get(sev, "")
                print(f"  {col}{B}[{sev.upper()}]{R} Check {f['check']}: {f['title']}")
                print(f"  {D}  {f['detail']}{R}")
                if f.get("parameter"):
                    print(f"  {D}  Parameter: {f['parameter']}{R}")
                if f.get("remediation"):
                    print(f"  {C['blue']}  Fix: {f['remediation']}{R}")
                print()

            print(f"{B}{'=' * 64}{R}")
            print(f"{B}  SUMMARY{R}")
            print(f"{'=' * 64}")
            for sev in ("critical", "high", "medium", "low", "info"):
                n = counts.get(sev, 0)
                if n:
                    col = SEV_COLOUR.get(sev, "")
                    bar = "#" * min(n, 40)
                    print(f"  {col}{sev.upper():8s}{R}  {n:3d}  {col}{bar}{R}")
            print(f"  {'TOTAL':8s}  {len(self.findings):3d}")

        print(f"{B}{'=' * 64}{R}\n")

    def build_json_report(self):
        return {
            "scan_metadata": {
                "timestamp":       self.start_time.isoformat(),
                "target":          self.target,
                "tester":          self.tester,
                "permission_from": self.permission_from,
                "permission_date": self.permission_date,
                "active_checks":   self.active,
            },
            "permission_statement": self._permission_statement(),
            "findings":             self.findings,
            "summary": {
                sev: sum(1 for f in self.findings if f["severity"] == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "audit_log": self.audit_log,
        }

    def save_audit_log(self):
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        ts = self.start_time.strftime("%Y%m%dT%H%M%SZ")
        host = urlparse(self.target).netloc.replace(":", "_")
        path = AUDIT_DIR / f"audit_{host}_{ts}.json"
        path.write_text(json.dumps(self.audit_log, indent=2), encoding="utf-8")
        print(f"  Audit log : {path}")


# ── Permission gate ──────────────────────────────────────────────────────────────
def confirm_active_tests(tester, permission_from, permission_date):
    B, R = C["bold"], C["reset"]
    print(f"\n{C['red']}{B}{'=' * 64}")
    print("  ACTIVE SECURITY TESTS — WRITTEN PERMISSION REQUIRED")
    print(f"{'=' * 64}{R}")
    print(f"""
This will perform active security tests including SQL injection and XSS
detection. These tests are safe and non-destructive but should only be
performed on systems you own or have WRITTEN permission to test.

Active checks:
  • Check 10 — SQL Injection Detection (URL parameters, login forms)
  • Check 11 — XSS Detection (URL parameters, search fields)

Tester          : {tester or '[not specified — use --tester]'}
Permission from : {permission_from or '[not specified — use --permission-from]'}
Permission date : {permission_date or '[not specified — use --permission-date]'}
""")
    a1 = input(
        "Do you confirm you have written permission to test this system? (yes/no): "
    ).strip().lower()
    if a1 != "yes":
        print("Active tests cancelled.")
        return False

    print(f"""
{C['red']}{B}SECOND CONFIRMATION REQUIRED{R}

This will perform active security tests including SQL injection and XSS
detection. These tests are safe and non-destructive but should only be
performed on systems you own or have WRITTEN permission to test.
Confirm you have written permission (yes/no):""")
    a2 = input("> ").strip().lower()
    if a2 != "yes":
        print("Active tests cancelled.")
        return False

    return True


# ── Entry point ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="RetailShield Retail Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python retail_vuln_scanner.py --target https://shop.example.com
  python retail_vuln_scanner.py --target https://shop.example.com --active \\
      --tester "Jane Smith" --permission-from "ACME Retail Ltd" \\
      --permission-date 2026-06-07
  python retail_vuln_scanner.py --target https://shop.example.com --output json
        """,
    )
    parser.add_argument("--target", required=True,
                        help="Target URL, e.g. https://shop.example.com")
    parser.add_argument("--active", action="store_true",
                        help="Enable active checks (SQL injection, XSS); "
                             "requires written permission")
    parser.add_argument("--tester", default=None,
                        help="Name of the tester (for audit trail)")
    parser.add_argument("--permission-from", default=None, dest="permission_from",
                        help="Organisation granting written permission")
    parser.add_argument("--permission-date", default=None, dest="permission_date",
                        help="Date permission was granted (YYYY-MM-DD)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print output to console only — do not write files")
    args = parser.parse_args()

    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"[ERROR] Invalid target URL: {args.target!r}", file=sys.stderr)
        print("[ERROR] Target must start with http:// or https://", file=sys.stderr)
        sys.exit(1)

    if args.active:
        if not confirm_active_tests(
            args.tester, args.permission_from, args.permission_date
        ):
            sys.exit(0)

    B, R = C["bold"], C["reset"]
    print(f"\n{B}RetailShield — Retail Web Vulnerability Scanner{R}")
    print(f"Target  : {args.target}")
    print(f"Mode    : {'Passive + Active' if args.active else 'Passive only'}")
    print(f"Started : "
          f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    scanner = Scanner(
        target=args.target,
        active=args.active,
        tester=args.tester,
        permission_from=args.permission_from,
        permission_date=args.permission_date,
        timeout=args.timeout,
    )
    scanner.run()

    if args.output == "text":
        scanner.print_report()
    else:
        report = scanner.build_json_report()
        json_str = json.dumps(report, indent=2)
        if args.dry_run:
            print(json_str)
        else:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            ts = scanner.start_time.strftime("%Y%m%dT%H%M%SZ")
            host = parsed.netloc.replace(":", "_")
            out_path = OUTPUT_DIR / f"web_scan_{host}_{ts}.json"
            out_path.write_text(json_str, encoding="utf-8")
            print(f"\nReport : {out_path}")

    if not args.dry_run:
        scanner.save_audit_log()

    critical = sum(1 for f in scanner.findings if f["severity"] == "critical")
    sys.exit(1 if critical > 0 else 0)


if __name__ == "__main__":
    main()
