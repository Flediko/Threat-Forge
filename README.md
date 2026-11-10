# ThreatForge

ThreatForge is a Django web application for authorized web application security checks. It runs a configurable scanner, stores reports and account activity, and provides separate workspaces for regular users and administrators.

## Features

- Nine scanner modules covering SQL injection, cross-site scripting (XSS), command injection, CSRF, brute-force protection, security headers, cookie flags, clickjacking, and open directory listings.
- Low, mid, and high scan modes, plus per-module selection.
- Live scan progress, risk scoring, finding summaries, and downloadable PDF and CSV reports.
- User registration, profile and password management, password recovery, and a Terms of Use page.
- A dedicated admin portal for user management, scan monitoring, activity review, database previews, and dataset export.
- ZIP dataset export containing CSV files for users, scans, findings, activity events, and scan runs. Password hashes and salts are excluded.
- Responsive interface styled with a flat black, monospace, green-signal design.

Only scan systems that you own or have explicit permission to test. Review the target scope before starting a scan.

## Requirements

- Python 3.10 or newer
- pip
- Optional: MySQL and PyMySQL for MySQL-backed application data

Install dependencies from the project directory:

    python -m pip install -r requirements.txt

## Run locally with SQLite

On PowerShell:

    $env:USE_SQLITE = "1"
    python manage.py migrate
    python scripts/create_admin.py
    python manage.py runserver 8000

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The admin account is created interactively; the password is not stored in the README or printed by the script.

The application uses two SQLite databases in this configuration:

- db.sqlite3 stores Django-managed data such as sessions.
- data/threatforge.db stores ThreatForge users, scans, reports, and activity.

Set THREATFORGE_DB_PATH to change the second database file path. The data directory is created if needed.

## Database configuration

ThreatForge application data uses SQLite when USE_SQLITE=1, or when the configured MySQL server is unavailable. To use MySQL, install the requirements, leave USE_SQLITE unset or set it to 0, and configure:

| Variable | Default | Description |
| --- | --- | --- |
| TF_MYSQL_HOST | 127.0.0.1 | MySQL host |
| TF_MYSQL_PORT | 3306 | MySQL port |
| TF_MYSQL_USER | root | MySQL account |
| TF_MYSQL_PASSWORD | empty | MySQL password |
| TF_MYSQL_DB | threatforge | Database name |

The application creates its ThreatForge tables when it starts. Run python manage.py migrate to create the Django tables used for sessions.

## Password recovery email

During local development, password-reset emails use Django's console email backend. The reset link is printed in the terminal running runserver.

To send real email, set TF_EMAIL_BACKEND to django.core.mail.backends.smtp.EmailBackend and configure the SMTP connection:

| Variable | Description |
| --- | --- |
| TF_EMAIL_HOST | SMTP server |
| TF_EMAIL_PORT | SMTP port |
| TF_EMAIL_HOST_USER | SMTP username, if required |
| TF_EMAIL_HOST_PASSWORD | SMTP password, if required |
| TF_EMAIL_USE_TLS | Set to 1 to enable TLS |
| TF_DEFAULT_FROM_EMAIL | Sender address displayed in reset emails |

Reset links expire after one hour and become invalid after the password is changed.

## Main pages

| Page | URL | Purpose |
| --- | --- | --- |
| Home | / | Product overview |
| Scanner | /scan/ | Configure and run scans |
| History | /history/ | Review previous reports and trends |
| Profile | /profile/ | View account details and change password |
| Sign in and registration | /login/ | Access or create an account |
| Forgot password | /password/forgot/ | Request a reset link |
| Terms of Use | /terms/ | Read terms required for registration |
| Admin portal | /admin-panel/ | Manage accounts, scans, activity, and exported data |

Administrator accounts open the admin portal after signing in and cannot run scans. Create the first administrator with python scripts/create_admin.py.

## Scanner modes

| Mode | Coverage |
| --- | --- |
| Low | Security headers, cookie flags, clickjacking, and directory listing checks |
| Mid | Low-mode checks plus CSRF, SQL injection, XSS, and brute-force protection checks |
| High | Full scanner module set, including command-injection checks |

The exact module list is in scanner/scanner.py. Scans make HTTP requests to the selected target. Use a test environment and an approved target.

## Project layout

    scanner/       Scan orchestration, checks, report building, and scoring
    services/      Authentication, database access, activity logging, and PDF output
    web/           Django views and URL routes
    templates/     Django HTML templates
    static/        CSS, JavaScript, and frontend assets
    scripts/       Administrative utilities
    tests/          Offline unit-style test scripts
    sites_to_test/  Local sample targets for authorized scanner evaluation

See [sites_to_test/README.md](sites_to_test/README.md) for information about the local sample applications and how to run them.

## Run the existing checks

The repository's offline checks are standalone Python scripts:

    python tests/test_modules.py
    python tests/test_db.py
    python tests/test_scoring.py
    python tests/test_pdf.py
    python tests/test_ui_sanitization.py

The live sample-target verification is documented separately in sites_to_test/README.md.
