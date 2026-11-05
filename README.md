# 🛡️ ThreatForge — Django Web Application

Standalone Django-based implementation of ThreatForge featuring a custom, non-stretched Cyber / SOC Dark Theme frontend built with modern HTML5, CSS3, and Vanilla JavaScript.

---

## 🚀 Quick Start

1. **Navigate to this directory:**
   ```bash
   cd threatforge_django
   ```

2. **Create an Administrator Account:**
   ```bash
   python scripts/create_admin.py
   ```

3. **Start the Django Development Server:**
   ```bash
   python manage.py runserver 8000
   ```

4. **Open in Browser:**
   Navigate to [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 🎨 UI & Design Enhancements (Powered by Agent Skills)

- **Widescreen Split-Screen SOC Dashboard (`tf-container-wide`):** Eliminates unused side gutters by utilizing up to 1620px of screen real estate with a two-column desktop SOC command view.
  - **Left Side (Results & Telemetry Hub):** Displays real-time interactive 3D cyber shield telemetry, live streaming terminal with dynamic progress percentages, SVG circular risk score gauge, priority remediation cards, module coverage matrix, export actions (PDF & CSV), and interactive findings search/filtering.
  - **Right Side (Sticky Audit Configuration Hub):** Houses the target URL input with protocol validation, quick-target preset autofill buttons (`DVWA Login`, `DVWA SQLi`, `Localhost Test`, `Testphp Vulnweb`), 3 configurable scan intensity modes, interactive engine checklist matrix, authentication drawer, and one-click execution.
- **3 Scan Intensity Modes (Low / Mid / High):**
  - 🟢 **Low Mode (Passive Recon ~10s):** Audits HTTP security headers, insecure cookie flags, clickjacking defenses, and open directory listings without fuzzing input fields.
  - 🟡 **Mid Mode (Standard / Balanced ~25s):** All Low checks + anti-CSRF token verification, form parameter fuzzing, and brute-force rate-limiting inspection.
  - 🔴 **High Mode (Deep Penetration Test ~45s):** Full 9-engine suite with advanced SQL Injection vectors (error-based & blind), reflected/stored Cross-Site Scripting (XSS), and safe arithmetic Command Injection canaries.
- **Interactive 3D Cyber Security Shield Experience (`3d-web-experience`):** Real-time perspective-projected 3D wireframe cyber shield and particle constellation network that dynamically tracks pointer tilt, respects `prefers-reduced-motion`, and pauses automatically when inactive.
- **Cyber / SOC HUD Design System (`uiux-designer`):** High-contrast dark canvas (`#060911`), Matrix/Emerald green (`#00ff41`), and neon cyan accents (`#00f0ff`) with crisp vector SVG icons, visible `:focus-visible` accessibility rings, and 44px minimum touch targets.
- **Toast Notifications & Interactive Clipboard Actions (`frontend-expert`):** Transient non-blocking toast notifications, one-click copy on technical payloads and evidence snippets with instant visual feedback, and "Expand/Collapse All" finding toggles.
- **Keyboard Shortcuts:** `Ctrl + Enter` to initiate target audits directly from the form, and `Esc` to dismiss alerts.

---

## 🧪 Running Tests

Run the test suite from inside this folder:
```bash
python tests/test_modules.py
python tests/test_db.py
python tests/test_scoring.py
python tests/test_pdf.py
```

