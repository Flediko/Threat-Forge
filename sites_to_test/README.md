# ThreatForge Multi-Target Vulnerability Test Lab (`sites_to_test/`)

This directory contains 4 independent, lightweight, self-contained test web applications built with Python's standard library. They specifically demonstrate and validate each of ThreatForge's 9 security scanning engines:

## Vulnerability Target Matrix

| Target Name | Port | Risk Profile | Grade | Vulnerabilities Present |
| :--- | :---: | :---: | :---: | :--- |
| **Site 1: Critical Enterprise Portal** (`site1_critical.py`) | `8001` | Critical | **F** | SQL Injection, Reflected XSS, OS Command Injection, Insecure Cookies, Missing CSRF, Clickjacking, Missing Security Headers |
| **Site 2: Moderate Tech Blog** (`site2_moderate.py`) | `8002` | Moderate | **C / F** | Reflected XSS, Missing Anti-CSRF Token, Insecure Cookie Flags, Clickjacking, Missing CSP & HSTS (Protected against SQLi) |
| **Site 3: Hardened Fortress** (`site3_hardened.py`) | `8003` | Hardened | **A** | **Zero Vulnerabilities** (Strict CSP, HSTS, X-Frame-Options, secure cookies, CSRF tokens, output encoding, rate-limiting) |
| **Site 4: Open Directory Storage** (`site4_directory.py`) | `8004` | Info Leak | **C** | Apache `Index of /backups` directory traversal leak, exposed `.sql` and `.bak` dumps |

---

## Quick Start: Launching All Targets

To start all 4 test servers at once in background threads:

```bash
python sites_to_test/run_all.py
```

All 4 targets will become accessible at:
- `http://127.0.0.1:8001/`
- `http://127.0.0.1:8002/`
- `http://127.0.0.1:8003/`
- `http://127.0.0.1:8004/`

---

## Automated Live Integration Verification

To run ThreatForge's actual scanner against all 4 targets and view a terminal report:

```bash
python sites_to_test/test_scanner_live.py
```

---

## 1-Click UI Testing

1. Start ThreatForge Django server (`python manage.py runserver 8000`).
2. Log into ThreatForge at `http://127.0.0.1:8000/`.
3. Under **Quick Target Presets**, click any of the test target buttons:
   - `🚨 Site 1: SQLi / XSS / CMDi (8001)`
   - `⚠️ Site 2: Moderate CSRF/XSS (8002)`
   - `🛡️ Site 3: Hardened Fortress (8003)`
   - `📂 Site 4: Open Directory (8004)`
4. Click **Initiate Security Audit** to observe ThreatForge's automated detection, risk scoring, and report generation in real time.

