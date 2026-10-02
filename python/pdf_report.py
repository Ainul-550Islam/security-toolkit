#!/usr/bin/env python3
# ============================================================================
#  ReportForge — Pure-stdlib PDF report generator (no external dependencies)
#  ---------------------------------------------------------------------------
#  Generates a clean, client-ready security report PDF from a JSON findings
#  file (SecuAudit / SecuAudit-API compatible). Handles: title page, summary,
#  severity list, findings with evidence + remediation, wrapped text, page
#  numbers, and proper PDF escaping.
#
#  Usage: python3 pdf_report.py --json results_example.json \
#           --out report.pdf --title "Security Audit — example.com"
# ============================================================================

import argparse
import json
import time

# ---------------------------------------------------------------------------
# Minimal PDF writer helpers (PDF 1.4, Helvetica core fonts)
# ---------------------------------------------------------------------------

# Unicode -> ASCII replacements for the WinAnsi-encoded core fonts
_UNICODE_MAP = {
    "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ",
    "\u20ac": "EUR", "\u2022": "-",
}


def pdf_escape(s: str) -> str:
    out = []
    for ch in str(s):
        if ch == "\\":
            out.append("\\\\")
        elif ch == "(":
            out.append("\\(")
        elif ch == ")":
            out.append("\\)")
        elif ch in _UNICODE_MAP:
            out.append(_UNICODE_MAP[ch])
        elif ord(ch) < 32 or ord(ch) > 126:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


class PdfBuilder:
    """Tiny single-page-stream PDF builder with manual layout."""

    def __init__(self, title="Security Report"):
        self.title = title
        self.objects = []           # list of bytes objects
        self.current = bytearray()  # content stream being built
        self.page_width = 595.0     # A4 points
        self.page_height = 842.0
        self.margin = 48.0
        self.y = self.page_height - self.margin
        self.page_number = 1
        self.font_size = 10

    # ---- low-level content ops -------------------------------------------
    def _here(self):
        return f"1 0 0 1 0 {self.y:.1f} Tm".encode()

    def new_page(self):
        self.current.extend(b"0 0 0 RG\n")
        self.objects.append(bytes(self.current))
        self.current = bytearray()
        self.page_number += 1
        self.y = self.page_height - self.margin

    def ensure_space(self, needed=20.0):
        if self.y - needed < self.margin:
            self.new_page()

    def text(self, s, size=10, bold=False, color=(0.0, 0.0, 0.0)):
        r, g, b = color
        self.ensure_space(size + 4)
        self.current.extend(f"{r:.3f} {g:.3f} {b:.3f} rg\n".encode())
        self.current.extend(b"/" + (b"F2" if bold else b"F1") + b" " +
                            f"{size:.1f}".encode() + b" Tf\n")
        self.current.extend(self._here())
        self.current.extend(b"(" + pdf_escape(s).encode() + b") Tj\n")
        self.y -= size + 6

    def wrap(self, s, size=10, width=480.0, indent=0.0, color=(0.0, 0.0, 0.0)):
        words = str(s).split()
        line = ""
        for w in words:
            trial = (line + " " + w).strip()
            if len(trial) * (size * 0.50) > width:  # rough char-width estimate
                self.text((" " * int(indent)) + line, size=size, color=color)
                line = w
            else:
                line = trial
        if line:
            self.text((" " * int(indent)) + line, size=size, color=color)

    def rule(self):
        self.ensure_space(10)
        self.current.extend(b"0.75 w\n0.60 0.65 0.72 RG\n")
        x0, x1 = self.margin, self.page_width - self.margin
        self.current.extend(f"{x0:.1f} {self.y:.1f} m {x1:.1f} {self.y:.1f} l S\n".encode())
        self.y -= 10

    def spacer(self, h=8):
        self.y -= h

    # ---- build --------------------------------------------------------------
    def build(self) -> bytes:
        # close current content stream
        self.current.extend(b"0 0 0 RG\n")
        self.objects.append(bytes(self.current))

        contents = self.objects
        n = len(contents)

        # Object layout:
        #   1 Catalog, 2 Pages, 3 F1 (regular), 4 F2 (bold),
        #   5..(4+n)  content streams,
        #   (5+n)..(4+2n) page objects
        obj_defs = []  # list of (num, body_bytes_or_None, is_stream)

        obj_defs.append((1, b"<< /Type /Catalog /Pages 2 0 R >>", False))
        kids = " ".join(str(5 + n + k) for k in range(n))
        obj_defs.append((2, f"<< /Type /Pages /Kids [{kids}] /Count {n} >>".encode(), False))
        obj_defs.append((3,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>", False))
        obj_defs.append((4,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>", False))
        for k, c in enumerate(contents):
            obj_defs.append((5 + k, c, True))
        for k in range(n):
            page = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {self.page_width:.0f} {self.page_height:.0f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                f"/Contents {5 + k} 0 R >>"
            ).encode()
            obj_defs.append((5 + n + k, page, False))

        out = bytearray()
        out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for num, body, is_stream in obj_defs:
            offsets.append(len(out))
            out.extend(f"{num} 0 obj\n".encode())
            if is_stream:
                out.extend(f"<< /Length {len(body)} >>\nstream\n".encode())
                out.extend(body)
                out.extend(b"\nendstream")
            else:
                out.extend(body)
            out.extend(b"\nendobj\n")

        xref_pos = len(out)
        count = len(obj_defs) + 1
        out.extend(f"xref\n0 {count}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for off in offsets:
            out.extend(f"{off:010d} 00000 n \n".encode())
        out.extend(
            f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
        )
        return bytes(out)


# ---------------------------------------------------------------------------
# Report layout
# ---------------------------------------------------------------------------
SEVERITY_COLOR = {
    "Critical": (0.72, 0.11, 0.11), "High": (0.86, 0.15, 0.15),
    "Medium": (0.85, 0.47, 0.02), "Low": (0.15, 0.39, 0.92), "Info": (0.42, 0.45, 0.52),
}


def build_report(data: dict, out_path: str, title: str):
    pdf = PdfBuilder(title)
    # Title
    pdf.text("SECURITY AUDIT REPORT", size=22, bold=True, color=(0.08, 0.10, 0.16))
    pdf.spacer(6)
    pdf.text(title, size=13, bold=True, color=(0.13, 0.17, 0.28))
    pdf.rule()
    pdf.spacer(4)

    # Metadata card
    pdf.text(f"Target       : {data.get('target', '-')}", size=10)
    pdf.text(f"Scan date    : {data.get('scan_date', '-')[:19]}", size=10)
    pdf.text(f"Tool         : {data.get('tool', 'SecuAudit')}", size=10)
    pdf.text(f"Score        : {data.get('score', '-')}/100   Grade: {data.get('grade', '-')}",
             size=11, bold=True)
    pdf.spacer(10)

    # Summary
    summary = data.get("summary", {})
    counts = summary if isinstance(summary, dict) else {}
    if counts:
        pdf.text("Severity Summary", size=13, bold=True)
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            n = counts.get(sev, 0)
            if n:
                pdf.text(f"   {sev:<9} : {n}", size=10, color=SEVERITY_COLOR.get(sev, (0, 0, 0)))
        pdf.spacer(8)

    # Findings
    pdf.text("Findings", size=13, bold=True)
    findings = data.get("findings", [])
    if not findings:
        pdf.wrap("No findings recorded.", size=10)
    for idx, f in enumerate(findings, 1):
        pdf.rule()
        sev = f.get("severity", "Info")
        pdf.text(f"{idx}. [{sev}] {f.get('title', 'Finding')}",
                 size=11, bold=True, color=SEVERITY_COLOR.get(sev, (0, 0, 0)))
        pdf.wrap(f"Evidence    : {f.get('evidence', '-')}", size=9, indent=2,
                 color=(0.35, 0.38, 0.45))
        pdf.wrap(f"Remediation : {f.get('remediation', '-')}", size=9, indent=2)

    pdf.rule()
    pdf.spacer(4)
    pdf.wrap(f"Disclaimer: {data.get('disclaimer', 'Authorized testing only.')}",
             size=8, color=(0.45, 0.48, 0.55))
    pdf.text(f"Generated by {data.get('tool', 'SecuAudit')} — "
             f"{time.strftime('%Y-%m-%d %H:%M')}", size=8, color=(0.45, 0.48, 0.55))

    with open(out_path, "wb") as fh:
        fh.write(pdf.build())
    print(f"[✓] PDF saved to {out_path}")


# ---------------------------------------------------------------------------
# Phase-6 deterministic renders (no clock access during render).
# `generated_at` comes from the snapshot metadata; identical input data
# always produces byte-identical output.
# ---------------------------------------------------------------------------
_GREY = (0.42, 0.45, 0.52)
_NAVY = (0.08, 0.10, 0.16)


def _wrap(pdf, s, size=9, width=470.0, indent=0, color=_GREY):
    pdf.wrap(s, size=size, width=width, indent=indent, color=color)


def render_report_pdf(snap: dict) -> bytes:
    """Render a Phase-6 snapshot to PDF bytes (deterministic)."""
    meta = snap.get("metadata", {})
    pdf = PdfBuilder(str(meta.get("title", "Security Report"))[:64])
    pdf.text("SECURITY REPORT", size=20, bold=True, color=_NAVY)
    pdf.spacer(6)
    pdf.text(str(meta.get("title", "-"))[:80], size=12, bold=True,
             color=(0.13, 0.17, 0.28))
    pdf.rule()
    pdf.spacer(4)
    pdf.text(f"Organization : {str(meta.get('org_name', '-'))[:60]}", size=9)
    pdf.text(f"Project      : {str(meta.get('project_name', '-'))[:60]} "
             f"({str(meta.get('project_id', ''))[:8]})", size=9)
    pdf.text(f"Type         : {str(meta.get('report_type', '-'))}", size=9)
    pdf.text(f"Generated    : {str(meta.get('generated_at', '-'))[:19]}  by "
             f"{str(meta.get('generated_by', '-'))[:40]}", size=9)
    pdf.text(f"Data cutoff  : {str(meta.get('data_cutoff', '-'))[:19]}",
             size=9)
    pdf.text(f"Risk engine  : {str(meta.get('risk_calculation_version', '-'))}"
             f"  schema: {str(meta.get('report_version', '-'))}", size=9)
    pdf.text(f"Report hash  : {str(meta.get('report_hash', '-'))[:24]}...",
             size=8, color=_GREY)
    pdf.spacer(8)

    posture = snap.get("posture") or {}
    risk = snap.get("risk") or {}
    if posture or risk:
        pdf.text("EXECUTIVE SUMMARY", size=12, bold=True)
        if posture:
            pdf.text(f"Posture score: {posture.get('score', '-')}/100 "
                     f"({posture.get('level', '-')})  [posture-v1]", size=10,
                     bold=True)
            for f in posture.get("factors", []):
                pdf.text(f"   {str(f.get('factor',''))[:38]:<38} "
                         f"w={float(f.get('weight',0)):.2f} "
                         f"v={float(f.get('value',0)):.3f} "
                         f"pts={float(f.get('points',0)):.2f}", size=8,
                         color=_GREY)
        if risk:
            pdf.text(f"Open findings : {int(risk.get('count', 0))}  "
                     f"total risk {float(risk.get('total_risk', 0))}",
                     size=10)
            for sev in ("Critical", "High", "Medium", "Low", "Info"):
                n = int((risk.get("by_severity") or {}).get(sev, 0))
                if n:
                    pdf.text(f"   {sev:<9}: {n}", size=9,
                             color=SEVERITY_COLOR.get(sev, (0, 0, 0)))
        pdf.spacer(6)

    assets = snap.get("assets", [])
    if assets:
        pdf.text(f"ASSETS ({len(assets)})", size=12, bold=True)
        for a in assets[:60]:
            pdf.text(f"  {str(a.get('value',''))[:44]:<44}  "
                     f"{str(a.get('exposure','-'))[:14]:<14}  "
                     f"crit={str(a.get('criticality','-'))[:9]}", size=8,
                     color=_GREY)
        pdf.spacer(4)

    findings = snap.get("findings", [])
    if findings:
        pdf.text(f"FINDINGS ({len(findings)})", size=12, bold=True)
        for idx, f in enumerate(findings, 1):
            sev = str(f.get("severity", "Info"))
            pdf.rule()
            pdf.text(f"{idx}. [{sev}] {str(f.get('title','-'))[:70]}  "
                     f"risk={round(float(f.get('risk_score') or 0),1)} "
                     f"({str(f.get('risk_level','-'))})", size=10, bold=True,
                     color=SEVERITY_COLOR.get(sev, (0, 0, 0)))
            _wrap(pdf, f"Asset: {str(f.get('asset_value','-'))[:60]}  "
                       f"exposure={str(f.get('exposure','-'))}  "
                       f"status={str(f.get('lifecycle','-'))}", size=8)
            rem = str(f.get("remediation", ""))[:180]
            if rem:
                _wrap(pdf, f"Remediation: {rem}", size=8)
            for e in f.get("evidence", [])[:4]:
                snip = " ".join(x for x in (
                    str(e.get("response_snippet", "") or ""),
                    str(e.get("request_snippet", "") or "")) if x)
                _wrap(pdf, f"Evidence: {str(e.get('type','-'))} "
                          f"{str(e.get('url','-'))[:60]}  "
                          f"{str(e.get('detection_reason',''))[:80]}"
                          f"{(' ' + snip[:120]) if snip else ''}", size=8)
            if idx >= 60:
                pdf.text("   ... more findings omitted (bounded render)",
                         size=8, color=_GREY)
                break

    rem = snap.get("remediation") or {}
    if rem:
        pdf.spacer(6)
        pdf.text("REMEDIATION", size=12, bold=True)
        pdf.text(f"  tickets={int(rem.get('total',0))}  "
                 f"overdue={int(rem.get('overdue_count',0))}  "
                 f"avg_age_days={rem.get('avg_remediation_age_days',0)}",
                 size=9)

    evidence = snap.get("evidence", [])
    if evidence:
        pdf.spacer(6)
        pdf.text("COMPLIANCE EVIDENCE (generic controls)", size=12,
                 bold=True)
        for e in evidence[:80]:
            pdf.text(f"  [{e.get('status','-')}] "
                     f"{str(e.get('control_category','-'))[:32]:<32} "
                     f"{str(e.get('source_type','-'))[:24]:<24} "
                     f"{str(e.get('evidence_hash','-'))[:16]}", size=8,
                     color=_GREY)

    trunc = ((snap.get("truncation") or {}).get("sections") or {})
    if any(t.get("truncated") for t in trunc.values()):
        pdf.spacer(6)
        pdf.text("BOUNDED SECTIONS (nothing dropped silently)", size=11,
                 bold=True)
        for sec, info in trunc.items():
            if info.get("truncated"):
                pdf.text(f"  {sec}: original={int(info.get('original_count',0))}"
                         f" included={int(info.get('included_count',0))} "
                         f"reason={info.get('reason','')}", size=8,
                         color=_GREY)

    pdf.rule()
    pdf.spacer(4)
    _wrap(pdf, "Disclaimer: authorized assessment data only. Reported "
               "findings and evidence are snapshots; this report makes no "
               "compliance or certification claim of any kind.", size=8)
    pdf.text(f"Generated by SecuPulse reporting — "
             f"{str(meta.get('generated_at', '-'))[:19]}  "
             f"hash {str(meta.get('report_hash', '-'))[:24]}...", size=8,
             color=_GREY)
    return pdf.build()


def render_evidence_pdf(payload: dict) -> bytes:
    """Render the evidence registry export (deterministic)."""
    pdf = PdfBuilder("Compliance evidence registry")
    pdf.text("COMPLIANCE EVIDENCE REGISTRY", size=18, bold=True, color=_NAVY)
    pdf.rule()
    pdf.spacer(4)
    pdf.text(f"Project   : {str(payload.get('project_id', '-'))[:48]}",
             size=9)
    pdf.text(f"Generated : {str(payload.get('generated_at', '-'))[:19]}",
             size=9)
    pdf.text(f"Schema    : {str(payload.get('schema_version', '-'))}",
             size=9)
    _wrap(pdf, str(payload.get("note", "")), size=8)
    pdf.spacer(6)
    items = payload.get("items", []) or []
    for e in items[:120]:
        pdf.text(f"  [{e.get('status','-')}] "
                 f"{str(e.get('control_category','-'))[:32]:<32} "
                 f"{str(e.get('source_type','-'))[:22]:<22} "
                 f"{str(e.get('evidence_hash','-'))[:16]}", size=8,
                 color=_GREY)
        _wrap(pdf, f"     {str(e.get('description',''))[:140]}", size=8)
    if len(items) > 120:
        pdf.text(f"   ... {len(items) - 120} more item(s) omitted "
                 "(bounded render)", size=8, color=_GREY)
    pdf.rule()
    pdf.spacer(4)
    pdf.text(f"Generated by SecuPulse reporting — "
             f"{str(payload.get('generated_at', '-'))[:19]}", size=8,
             color=_GREY)
    return pdf.build()


def main():
    ap = argparse.ArgumentParser(description="ReportForge — PDF report generator")
    ap.add_argument("--json", required=True, help="Findings JSON (SecuAudit compatible)")
    ap.add_argument("--out", default="report.pdf", help="Output PDF path")
    ap.add_argument("--title", default="Security Assessment", help="Report title line")
    args = ap.parse_args()

    with open(args.json, encoding="utf-8") as f:
        data = json.load(f)
    build_report(data, args.out, args.title)


if __name__ == "__main__":
    main()
