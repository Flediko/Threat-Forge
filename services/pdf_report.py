"""
PDF Report Generator Service
============================
Builds an executive-grade, multi-page PDF vulnerability assessment report in memory
(``io.BytesIO``) from a saved or freshly generated ThreatForge scan report dictionary.

Uses ``reportlab`` (Platypus + Graphics) when installed, with a built-in
standard-library PDF 1.4 writer fallback so PDF generation and tests always
succeed even in restricted offline environments.
"""

from datetime import datetime, timezone
import io
import re
from xml.sax.saxutils import escape as xml_escape

from .scoring import FIX_SUGGESTIONS, compute_risk
from scanner.reporter import ALL_MODULES

GRADE_COLORS_HEX = {
    "A": "#10b981",  # Emerald Green
    "B": "#3b82f6",  # Indigo / Blue
    "C": "#f59e0b",  # Amber
    "D": "#f97316",  # Orange
    "F": "#ef4444",  # Red
}

SEVERITY_THEMES = {
    "High": {
        "border": "#fca5a5",
        "header_bg": "#fef2f2",
        "badge_bg": "#fee2e2",
        "badge_text": "#b91c1c",
        "tag": "HIGH SEVERITY",
    },
    "Medium": {
        "border": "#fde68a",
        "header_bg": "#fffbeb",
        "badge_bg": "#fef3c7",
        "badge_text": "#b45309",
        "tag": "MEDIUM SEVERITY",
    },
    "Low": {
        "border": "#bae6fd",
        "header_bg": "#f0f9ff",
        "badge_bg": "#e0f2fe",
        "badge_text": "#0369a1",
        "tag": "LOW SEVERITY",
    },
}

_COOKIE_SECRET_RE = re.compile(
    r"(PHPSESSID|JSESSIONID|session_id|sid|token|auth)\s*=\s*[^;\s]+",
    re.IGNORECASE,
)


def _clean_text(val: object, max_len: int | None = None) -> str:
    """
    Convert *val* to string, strip non-printable control characters, redact any
    accidental session cookie values, and optionally truncate to *max_len*.
    """
    raw = str(val if val is not None else "")
    printable = "".join(
        ch if (ord(ch) >= 32 and ord(ch) != 127) else " " for ch in raw
    )
    sanitized = _COOKIE_SECRET_RE.sub(r"\1=[REDACTED]", printable).strip()
    if max_len is not None and len(sanitized) > max_len:
        return sanitized[: max_len - 3] + "..."
    return sanitized


def _safe_xml(val: object, max_len: int | None = None) -> str:
    """Clean and XML-escape dynamic text before passing into ReportLab Paragraph."""
    return xml_escape(_clean_text(val, max_len=max_len))


def _ensure_report_fields(report: dict) -> dict:
    """Ensure risk_score, grade, label, and top_fixes exist on older reports."""
    enriched = dict(report)
    findings = enriched.get("findings", [])
    if "risk_score" not in enriched or "grade" not in enriched:
        risk = compute_risk(findings)
        enriched.setdefault("risk_score", risk["risk_score"])
        enriched.setdefault("grade", risk["grade"])
        enriched.setdefault("label", risk["label"])
        enriched.setdefault("breakdown", risk["breakdown"])
        enriched.setdefault("top_fixes", risk["top_fixes"])
    return enriched


def _build_pdf_with_reportlab(report: dict, generated_for: str) -> bytes:
    """Build an executive-styled multi-page PDF using ReportLab Platypus & Graphics."""
    from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    class NumberedCanvas(canvas.Canvas):
        """Custom canvas that renders a top accent stripe, header, and 'Page X of Y' footer."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_header_footer(num_pages)
                super().showPage()
            super().save()

        def _draw_header_footer(self, page_count: int):
            self.saveState()
            width, height = A4

            # Top indigo accent stripe
            self.setFillColor(colors.HexColor("#4f46e5"))
            self.rect(0, height - 3.5 * mm, width, 3.5 * mm, fill=1, stroke=0)

            # Header running title
            self.setFont("Helvetica-Bold", 8.5)
            self.setFillColor(colors.HexColor("#4f46e5"))
            self.drawString(18 * mm, height - 12 * mm, "THREATFORGE")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(42 * mm, height - 12 * mm, "· Automated SOC Vulnerability Assessment")

            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#94a3b8"))
            self.drawRightString(
                width - 18 * mm,
                height - 12 * mm,
                "CONFIDENTIAL AUDIT REPORT",
            )
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.6)
            self.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)

            # Footer
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.6)
            self.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)

            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(
                18 * mm,
                10 * mm,
                "ThreatForge Security Audit Platform · For authorized security testing only.",
            )
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#334155"))
            self.drawRightString(
                width - 18 * mm,
                10 * mm,
                f"Page {self._pageNumber} of {page_count}",
            )
            self.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title="ThreatForge Vulnerability Report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TFTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=23,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=3,
    )
    subtitle_style = ParagraphStyle(
        "TFSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#4f46e5"),
        spaceAfter=10,
    )
    h2_style = ParagraphStyle(
        "TFH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "TFBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    label_style = ParagraphStyle(
        "TFLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#475569"),
    )
    mono_style = ParagraphStyle(
        "TFMono",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#0f172a"),
        wordWrap="CJK",
    )
    code_box_style = ParagraphStyle(
        "TFCodeBox",
        parent=styles["BodyText"],
        fontName="Courier-Bold",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#b91c1c"),
        wordWrap="CJK",
    )
    card_title_style = ParagraphStyle(
        "TFCardTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    badge_style = ParagraphStyle(
        "TFBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=TA_RIGHT,
    )

    story = []

    # ── PAGE 1: Cover & Executive Briefing ────────────────────────────────────
    story.append(Paragraph("ThreatForge Security Assessment", title_style))
    story.append(
        Paragraph(
            "COMPREHENSIVE AUTOMATED VULNERABILITY AUDIT &amp; DEFENSE VERIFICATION",
            subtitle_style,
        )
    )

    target_str = _safe_xml(report.get("target", "Unknown"), 300)
    scan_time_str = _safe_xml(
        report.get(
            "scan_time",
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        ),
        80,
    )
    user_str = _safe_xml(generated_for or "Certified Security Operator", 80)
    auth_mode = (
        "Authenticated Audit (Session Cookie Applied)"
        if report.get("authenticated_scan")
        else "Black-Box Scan (Unauthenticated Endpoint Testing)"
    )

    # Executive Briefing Metadata Card with Indigo Accent Border
    meta_data = [
        [Paragraph("Target Endpoint:", label_style), Paragraph(f"<b>{target_str}</b>", body_style)],
        [Paragraph("Audit Timestamp:", label_style), Paragraph(scan_time_str, body_style)],
        [Paragraph("Operator Identity:", label_style), Paragraph(user_str, body_style)],
        [Paragraph("Execution Profile:", label_style), Paragraph(_safe_xml(auth_mode), body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[38 * mm, 136 * mm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
                ("LINELEFT", (0, 0), (0, -1), 3.0, colors.HexColor("#4f46e5")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Risk Score Gauge Drawing
    score = int(report.get("risk_score", 0))
    grade = _clean_text(report.get("grade", "A"), 2) or "A"
    label = _clean_text(report.get("label", "Excellent"), 40)
    grade_color = colors.HexColor(GRADE_COLORS_HEX.get(grade, "#4f46e5"))

    gauge = Drawing(174 * mm, 52 * mm)
    # Background panel
    gauge.add(
        Rect(
            0,
            0,
            174 * mm,
            52 * mm,
            rx=4,
            ry=4,
            fillColor=colors.HexColor("#f8fafc"),
            strokeColor=colors.HexColor("#e2e8f0"),
            strokeWidth=0.6,
        )
    )

    cx, cy, r = 36 * mm, 26 * mm, 19 * mm
    # Gauge outer ring
    gauge.add(
        Circle(
            cx,
            cy,
            r,
            strokeColor=colors.HexColor("#e2e8f0"),
            strokeWidth=6,
            fillColor=colors.HexColor("#ffffff"),
        )
    )
    # Colored arc wedge proportional to score (0..100)
    if score > 0:
        extent = max(8, min(360, int(360 * (score / 100.0))))
        gauge.add(
            Wedge(
                cx,
                cy,
                r,
                90 - extent,
                90,
                strokeColor=grade_color,
                fillColor=grade_color,
            )
        )
        gauge.add(
            Circle(
                cx,
                cy,
                r - 4.5 * mm,
                strokeColor=colors.white,
                fillColor=colors.white,
            )
        )

    gauge.add(
        String(
            cx,
            cy + 2,
            f"{score}/100",
            fontName="Helvetica-Bold",
            fontSize=13,
            fillColor=colors.HexColor("#0f172a"),
            textAnchor="middle",
        )
    )
    gauge.add(
        String(
            cx,
            cy - 9,
            f"GRADE {grade}",
            fontName="Helvetica-Bold",
            fontSize=8.5,
            fillColor=grade_color,
            textAnchor="middle",
        )
    )

    gauge.add(
        String(
            68 * mm,
            cy + 10,
            f"Security Posture: Grade {grade} ({label})",
            fontName="Helvetica-Bold",
            fontSize=13,
            fillColor=grade_color,
        )
    )
    gauge.add(
        String(
            68 * mm,
            cy - 3,
            f"Cumulative Risk Score: {score} of 100 max exposure points",
            fontName="Helvetica-Bold",
            fontSize=9.5,
            fillColor=colors.HexColor("#334155"),
        )
    )

    posture_desc = (
        "Hardened perimeter — zero active vulnerability indicators observed."
        if score == 0
        else (
            "Elevated resilience — minor defensive hardening opportunities detected."
            if score <= 35
            else (
                "Moderate exposure — active misconfigurations require structured remediation."
                if score <= 70
                else "Critical exposure — high-severity flaws require immediate intervention."
            )
        )
    )
    gauge.add(
        String(
            68 * mm,
            cy - 14,
            posture_desc,
            fontName="Helvetica",
            fontSize=8.5,
            fillColor=colors.HexColor("#64748b"),
        )
    )

    story.append(gauge)
    story.append(Spacer(1, 10))

    # Executive Severity Metrics Board (4-Column Modern Cards)
    sev_counts = report.get("severity_counts", {"High": 0, "Medium": 0, "Low": 0})
    h_count = int(sev_counts.get("High", 0))
    m_count = int(sev_counts.get("Medium", 0))
    l_count = int(sev_counts.get("Low", 0))
    t_count = int(report.get("total_findings", h_count + m_count + l_count))

    sev_metric_data = [
        [
            Paragraph("<font color='#b91c1c'><b>CRITICAL / HIGH</b></font>", label_style),
            Paragraph("<font color='#b45309'><b>MEDIUM SEVERITY</b></font>", label_style),
            Paragraph("<font color='#0369a1'><b>LOW SEVERITY</b></font>", label_style),
            Paragraph("<font color='#334155'><b>TOTAL FINDINGS</b></font>", label_style),
        ],
        [
            Paragraph(f"<font color='#dc2626'><b>{h_count}</b></font>", ParagraphStyle("C1", parent=title_style, fontSize=18, leading=20)),
            Paragraph(f"<font color='#d97706'><b>{m_count}</b></font>", ParagraphStyle("C2", parent=title_style, fontSize=18, leading=20)),
            Paragraph(f"<font color='#0284c7'><b>{l_count}</b></font>", ParagraphStyle("C3", parent=title_style, fontSize=18, leading=20)),
            Paragraph(f"<font color='#0f172a'><b>{t_count}</b></font>", ParagraphStyle("C4", parent=title_style, fontSize=18, leading=20)),
        ],
        [
            Paragraph("<font color='#991b1b'>Immediate Action</font>", body_style),
            Paragraph("<font color='#92400e'>Priority Remediation</font>", body_style),
            Paragraph("<font color='#075985'>Hardening Advice</font>", body_style),
            Paragraph("<font color='#475569'>Tested Vector Total</font>", body_style),
        ],
    ]
    sev_metric_table = Table(sev_metric_data, colWidths=[43.5 * mm, 43.5 * mm, 43.5 * mm, 43.5 * mm])
    sev_metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fef2f2")),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#fffbeb")),
                ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f0f9ff")),
                ("BACKGROUND", (3, 0), (3, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (0, -1), 0.6, colors.HexColor("#fca5a5")),
                ("BOX", (1, 0), (1, -1), 0.6, colors.HexColor("#fde68a")),
                ("BOX", (2, 0), (2, -1), 0.6, colors.HexColor("#bae6fd")),
                ("BOX", (3, 0), (3, -1), 0.6, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(sev_metric_table)
    story.append(Spacer(1, 10))

    # Priority Action Roadmap (Top Fixes)
    story.append(Paragraph("Priority Action Roadmap", h2_style))
    top_fixes = report.get("top_fixes") or []
    if top_fixes:
        fix_rows = [
            [
                Paragraph("<b>Vulnerability Class</b>", label_style),
                Paragraph("<b>Risk Penalty</b>", label_style),
                Paragraph("<b>Prescribed Remediation Action</b>", label_style),
            ]
        ]
        for item in top_fixes[:3]:
            fix_rows.append(
                [
                    Paragraph(f"<b>{_safe_xml(item.get('type', ''), 80)}</b>", body_style),
                    Paragraph(f"<font color='#dc2626'><b>+{int(item.get('points', 0))} pts</b></font>", body_style),
                    Paragraph(_safe_xml(item.get("fix", ""), 300), body_style),
                ]
            )
        fix_table = Table(fix_rows, colWidths=[48 * mm, 24 * mm, 102 * mm])
        fix_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#c7d2fe")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e7ff")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(fix_table)
    else:
        story.append(
            Paragraph(
                "No vulnerabilities detected — all active perimeter checks passed successfully.",
                body_style,
            )
        )

    # ── PAGE 2: Engine Coverage Matrix & Detailed Findings ───────────────────
    story.append(PageBreak())
    story.append(Paragraph("SOC Audit Engine Coverage Matrix (9 Engines)", h2_style))

    summary_map = report.get("summary", {})
    cov_rows = [
        [
            Paragraph("<font color='#ffffff'><b>Audit Engine Category</b></font>", label_style),
            Paragraph("<font color='#ffffff'><b>Observed Status &amp; Telemetry</b></font>", label_style),
        ]
    ]
    for mod in ALL_MODULES:
        if mod == "CSRF Protection":
            cnt = int(summary_map.get("Missing CSRF Token", 0)) + int(
                summary_map.get("Weak or Empty CSRF Token", 0)
            )
        elif mod == "Brute-Force Protection":
            cnt = int(summary_map.get("No Brute-Force Protection", 0))
        else:
            cnt = int(summary_map.get(mod, 0))

        status_txt = (
            "<font color='#16a34a'><b>&#10004; PASS &middot; Clean Defense</b></font>"
            if cnt == 0
            else f"<font color='#dc2626'><b>&#9888; DEFICIENT &middot; {cnt} Finding(s) Detected</b></font>"
        )
        cov_rows.append(
            [
                Paragraph(_safe_xml(mod, 80), body_style),
                Paragraph(status_txt, body_style),
            ]
        )

    cov_table = Table(cov_rows, colWidths=[108 * mm, 66 * mm])
    cov_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(cov_table)
    story.append(Spacer(1, 12))

    # Detailed Findings grouped by severity (High -> Medium -> Low)
    story.append(Paragraph("Detailed Vulnerability Findings", h2_style))
    findings = report.get("findings") or []

    if not findings:
        story.append(
            Paragraph(
                "<b>No vulnerabilities detected.</b> The tested endpoint did not expose any signature, reflection, or header weaknesses across the 9 audit engines.",
                body_style,
            )
        )
    else:
        for sev_level in ("High", "Medium", "Low"):
            group = [f for f in findings if f.get("severity") == sev_level]
            if not group:
                continue

            theme = SEVERITY_THEMES.get(sev_level, SEVERITY_THEMES["Low"])
            sev_header_text = (
                f"<font color='{theme['badge_text']}'><b>{sev_level} Severity Findings ({len(group)})</b></font>"
            )
            story.append(Paragraph(sev_header_text, h2_style))

            for idx, f in enumerate(group, start=1):
                ftype = _safe_xml(f.get("type", "Finding"), 120)
                ffield = _safe_xml(f.get("field", "N/A"), 300)
                raw_payload = str(f.get("payload") or "").strip()
                has_payload = bool(raw_payload and raw_payload.upper() not in ("N/A", "NONE", ""))
                fpayload = _safe_xml(raw_payload, 300)
                fevidence = _safe_xml(f.get("evidence", "N/A"), 300)
                fdetail = _safe_xml(f.get("detail", ""), 500)

                # Card Header with pill tag
                f_rows = [
                    [
                        Paragraph(f"<b>#{idx} &middot; {ftype}</b>", card_title_style),
                        Paragraph(
                            f"<font color='{theme['badge_text']}'><b>{theme['tag']}</b></font>",
                            badge_style,
                        ),
                    ],
                    [
                        Paragraph("Target / Field:", label_style),
                        Paragraph(ffield, mono_style),
                    ],
                ]

                # Only include Payload row when an actual payload was used
                if has_payload:
                    f_rows.append(
                        [
                            Paragraph("Injected Vector:", label_style),
                            Paragraph(fpayload, code_box_style),
                        ]
                    )

                f_rows.append(
                    [
                        Paragraph("Observed Evidence:", label_style),
                        Paragraph(fevidence, mono_style),
                    ]
                )
                f_rows.append(
                    [
                        Paragraph("Analysis &amp; Impact:", label_style),
                        Paragraph(fdetail, body_style),
                    ]
                )

                f_table = Table(f_rows, colWidths=[38 * mm, 136 * mm])
                card_style = [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(theme["header_bg"])),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor(theme["border"])),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor(theme["border"])),
                    ("INNERGRID", (0, 1), (-1, -1), 0.25, colors.HexColor("#f1f5f9")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, 0), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]
                f_table.setStyle(TableStyle(card_style))
                story.append(f_table)
                story.append(Spacer(1, 8))

    # Recommendations Section
    story.append(Spacer(1, 8))
    story.append(Paragraph("Remediation Recommendations", h2_style))
    distinct_types = sorted({f.get("type", "") for f in findings if f.get("type")})
    if distinct_types:
        for vtype in distinct_types:
            rem = FIX_SUGGESTIONS.get(
                vtype,
                "Follow OWASP input validation and output encoding best practices.",
            )
            story.append(
                Paragraph(
                    f"&bull; <b>{_safe_xml(vtype, 80)}:</b> {_safe_xml(rem, 300)}",
                    body_style,
                )
            )
            story.append(Spacer(1, 3))
    else:
        story.append(
            Paragraph(
                "Maintain security headers, strict cookie flags, and regular automated scans to ensure persistent defense.",
                body_style,
            )
        )

    # ── LAST PAGE: Methodology, Limitations & Authorized-Use Disclaimer ─────
    story.append(PageBreak())
    story.append(Paragraph("Audit Methodology &amp; Scanner Limitations", h2_style))

    limitations = [
        "<b>Single Target Scope:</b> ThreatForge tests the single URL provided and the forms extracted from that page; it does not crawl entire web hierarchies.",
        "<b>Authentication Context:</b> Scans are executed unauthenticated unless a valid session cookie was explicitly supplied in the scan configuration.",
        "<b>Detection Mechanics:</b> Checks leverage database error signatures, unescaped reflection markers, HTTP response header heuristics, and non-destructive arithmetic vectors.",
    ]
    for lim in limitations:
        story.append(Paragraph(f"&bull; {lim}", body_style))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Authorized-Use &amp; Educational Disclaimer", h2_style))

    disclaimer_box = [
        [
            Paragraph(
                "ThreatForge is an academic B.Tech cybersecurity project developed strictly for authorized security assessments and educational evaluation on environments you own or have explicit written permission to test (such as local WAMP/DVWA or OWASP Juice Shop instances). Unauthorized scanning of third-party systems is strictly prohibited.",
                body_style,
            )
        ]
    ]
    disclaimer_table = Table(disclaimer_box, colWidths=[174 * mm])
    disclaimer_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
                ("LINELEFT", (0, 0), (0, -1), 3.0, colors.HexColor("#0f172a")),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(disclaimer_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


def _pdf_escape(text: str) -> str:
    """Escape parentheses and backslashes for raw PDF content streams."""
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _build_pdf_stdlib_fallback(report: dict, generated_for: str) -> bytes:
    """
    Pure-Python standard-library PDF 1.4 generator fallback used only when
    ``reportlab`` is not installed in the current Python environment.
    """
    lines: list[str] = []
    lines.append("ThreatForge Vulnerability Report")
    lines.append(f"Target URL: {_clean_text(report.get('target', 'Unknown'), 200)}")
    lines.append(f"Scan Date (UTC): {_clean_text(report.get('scan_time', ''), 60)}")
    lines.append(f"Generated For: {_clean_text(generated_for or 'User', 60)}")
    mode = (
        "Authenticated scan"
        if report.get("authenticated_scan")
        else "Unauthenticated scan"
    )
    lines.append(f"Scan Mode: {mode}")
    lines.append(
        f"Risk Score: {report.get('risk_score', 0)}/100 | Grade: {report.get('grade', 'A')} ({report.get('label', 'Excellent')})"
    )
    sev = report.get("severity_counts", {"High": 0, "Medium": 0, "Low": 0})
    lines.append(
        f"Severity Counts: High={sev.get('High', 0)}, Medium={sev.get('Medium', 0)}, Low={sev.get('Low', 0)} (Total={report.get('total_findings', 0)})"
    )
    lines.append("-" * 72)

    findings = report.get("findings") or []
    if not findings:
        lines.append("No vulnerabilities detected.")
    else:
        for idx, f in enumerate(findings, start=1):
            lines.append(
                f"#{idx} [{_clean_text(f.get('severity', 'Low'), 10)}] {_clean_text(f.get('type', ''), 80)}"
            )
            lines.append(f"  Field: {_clean_text(f.get('field', 'N/A'), 120)}")
            raw_payload = str(f.get("payload") or "").strip()
            if raw_payload and raw_payload.upper() not in ("N/A", "NONE", ""):
                lines.append(f"  Payload: {_clean_text(raw_payload, 120)}")
            lines.append(f"  Evidence: {_clean_text(f.get('evidence', 'N/A'), 120)}")
            lines.append(f"  Detail: {_clean_text(f.get('detail', ''), 160)}")

    lines.append("-" * 72)
    lines.append(
        "Limitations: Single URL only, unauthenticated unless session cookie supplied, signature-based."
    )
    lines.append("For educational and authorized testing only.")

    per_page = 42
    pages_lines = [
        lines[i : i + per_page] for i in range(0, max(1, len(lines)), per_page)
    ]
    total_pages = len(pages_lines)

    objects: list[bytes] = []
    page_obj_ids = []
    content_obj_ids = []
    next_id = 4
    for _ in pages_lines:
        page_obj_ids.append(next_id)
        content_obj_ids.append(next_id + 1)
        next_id += 2

    kids_ref = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(
        f"2 0 obj\n<< /Type /Pages /Kids [{kids_ref}] /Count {total_pages} >>\nendobj\n".encode(
            "ascii"
        )
    )
    objects.append(
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    )

    for page_idx, p_lines in enumerate(pages_lines, start=1):
        pid = page_obj_ids[page_idx - 1]
        cid = content_obj_ids[page_idx - 1]

        stream_cmds = ["BT", "/F1 9 Tf", "50 790 Td", "14 TL"]
        stream_cmds.append(
            f"(ThreatForge - Page {page_idx} of {total_pages}) Tj T*"
        )
        for ln in p_lines:
            safe_ln = _pdf_escape(ln[:105])
            stream_cmds.append(f"({safe_ln}) Tj T*")
        stream_cmds.append("ET")
        stream_bytes = "\n".join(stream_cmds).encode("latin-1", errors="replace")

        page_dict = (
            f"{pid} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>\n"
            f"endobj\n"
        ).encode("ascii")
        content_dict = (
            f"{cid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )
        objects.append(page_dict)
        objects.append(content_dict)

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for obj in objects:
        offsets.append(out.tell())
        out.write(obj)

    xref_pos = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode("ascii"))

    out.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return out.getvalue()


def build_pdf(report: dict, generated_for: str = "Authorized User") -> bytes:
    """
    Build a complete PDF vulnerability report in memory and return its bytes.
    """
    enriched = _ensure_report_fields(report or {})
    try:
        return _build_pdf_with_reportlab(enriched, generated_for)
    except ImportError:
        return _build_pdf_stdlib_fallback(enriched, generated_for)


def make_pdf_filename(target_url: str, scan_time: str | None = None) -> str:
    """
    Generate a sanitized PDF filename of the form
    ``threatforge_<host>_<YYYYMMDD_HHMM>.pdf`` containing only letters,
    digits, dots, dashes, and underscores.
    """
    from urllib.parse import urlparse

    parsed = urlparse(target_url or "")
    raw_host = parsed.netloc or parsed.path or "target"
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", raw_host).strip("._-") or "target"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return f"threatforge_{safe_host}_{ts}.pdf"
