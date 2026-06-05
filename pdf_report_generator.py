"""
pdf_report_generator.py — PDF Report Generator
=================================================

Generates PDF reports from the JSON reports produced by report_generator.py.

Uses reportlab for PDF generation with all 7 sections:
- §1 Header / Metadata
- §2 Executive Summary
- §3 Vulnerability Details (full with taint path)
- §4 Safe Paths Confirmed
- §5 Sanitizations Detected
- §6 CFG / DFG Statistics
- §7 Footer

Dependencies:
    pip install reportlab
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import (
    getSampleStyleSheet, ParagraphStyle, TA_CENTER, TA_LEFT, TA_JUSTIFY
)
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    Image, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY


PDF_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output", "pdf")


@dataclass
class PDFPathStep:
    step: int
    role: str
    line: int
    col: int
    expression: str


@dataclass
class PDFVulnerability:
    id: str
    severity: str
    cwe: str
    sink: str
    sink_line: int
    sink_col: int
    sink_expr: str
    arg: str
    source_var: str
    source_type: str
    mechanism: str
    taint_path: List[PDFPathStep]
    remediation: str
    remediation_code: str


@dataclass
class PDFSafeSink:
    sink: str
    line: int
    sanitizer: str
    variable: str


@dataclass
class PDFSanitization:
    function: str
    variable: str
    line: int


@dataclass
class PDFReport:
    filename: str
    filepath: str
    timestamp: str
    loc: int
    verdict: str
    vuln_count: int
    critical_count: int
    warning_count: int
    info_count: int
    vulnerabilities: List[PDFVulnerability]
    safe_sinks: List[PDFSafeSink]
    sanitizations: List[PDFSanitization]
    cfg_stats: Dict[str, int]
    dfg_stats: Dict[str, Any]
    analysis_time_ms: float
    engine_version: str


def load_json_report(filepath: str) -> PDFReport:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns = []
    for v in data.get("vulnerabilities", []):
        path_steps = []
        for tp in v.get("taint_path", []):
            path_steps.append(PDFPathStep(
                step=tp["step"],
                role=tp["role"],
                line=tp["line"],
                col=tp["col"],
                expression=tp["expr"],
            ))
        vulns.append(PDFVulnerability(
            id=v["id"],
            severity=v["severity"],
            cwe=v.get("cwe", "CWE-89"),
            sink=v["sink"],
            sink_line=v["sink_line"],
            sink_col=v.get("sink_col", 0),
            sink_expr=v.get("sink_expr", ""),
            arg=v.get("arg", ""),
            source_var=v["source_var"],
            source_type=v["source_type"],
            mechanism=v["mechanism"],
            taint_path=path_steps,
            remediation=v.get("remediation", ""),
            remediation_code=v.get("remediation_code", ""),
        ))

    safe_sinks = []
    for ss in data.get("safe_sinks", []):
        safe_sinks.append(PDFSafeSink(
            sink=ss["sink"],
            line=ss["line"],
            sanitizer=ss.get("sanitizer", ""),
            variable=ss.get("variable", ""),
        ))

    sanitizations = []
    for san in data.get("sanitizations", []):
        sanitizations.append(PDFSanitization(
            function=san.get("function", ""),
            variable=san.get("variable", ""),
            line=san.get("line", 0),
        ))

    stats = data.get("statistics", {})
    cfg = stats.get("cfg", {})
    dfg = stats.get("dfg", {})

    return PDFReport(
        filename=data["file"],
        filepath=data.get("filepath", ""),
        timestamp=data["timestamp"],
        loc=data["loc"],
        verdict=data["verdict"],
        vuln_count=data["summary"]["total"],
        critical_count=data["summary"]["critical"],
        warning_count=data["summary"]["warning"],
        info_count=data["summary"]["info"],
        vulnerabilities=vulns,
        safe_sinks=safe_sinks,
        sanitizations=sanitizations,
        cfg_stats=cfg,
        dfg_stats=dfg,
        analysis_time_ms=stats.get("analysis_time_ms", 0),
        engine_version=data.get("engine", "1.0.0"),
    )


def get_severity_color(severity: str) -> colors.Color:
    if severity == "CRITICAL":
        return colors.Color(0.85, 0.2, 0.2)
    elif severity == "WARNING":
        return colors.Color(0.9, 0.7, 0.2)
    return colors.Color(0.3, 0.5, 0.85)


def get_verdict_color(verdict: str) -> colors.Color:
    if "VULNERABLE" in verdict:
        return colors.Color(0.85, 0.2, 0.2)
    return colors.Color(0.2, 0.6, 0.3)


def build_pdf(report: PDFReport, output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=LETTER,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=30,
        alignment=TA_CENTER,
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.white,
        spaceBefore=20,
        spaceAfter=10,
        backgroundColor=colors.HexColor("#2c3e50"),
        leftPadding=8,
    )

    subsection_style = ParagraphStyle(
        "SubsectionHeading",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#34495e"),
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
    )

    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Code"],
        fontSize=8,
        fontName="Courier",
        leftIndent=15,
        rightIndent=15,
        spaceBefore=4,
        spaceAfter=4,
        backgroundColor=colors.HexColor("#f8f9fa"),
        borderColor=colors.HexColor("#dee2e6"),
        borderWidth=1,
        borderPadding=5,
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.gray,
    )

    story.append(Paragraph("Security Linter Report", title_style))
    story.append(Spacer(1, 5))

    verdict_color = get_verdict_color(report.verdict)

    meta_data = [
        ["Filename", report.filename],
        ["Timestamp", report.timestamp],
        ["Lines of Code (LOC)", str(report.loc)],
        ["Verdict", report.verdict],
    ]
    meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (1, 3), (1, 3), verdict_color),
        ("FONTNAME", (1, 3), (1, 3), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 15))
    story.append(Paragraph("§2  Executive Summary", section_style))

    if report.vuln_count > 0:
        summary_data = [["ID", "Severity", "Sink", "Source Variable", "Source Type", "Line"]]
        for v in report.vulnerabilities:
            summary_data.append([
                v.id,
                v.severity,
                v.sink[:20] + "..." if len(v.sink) > 20 else v.sink,
                v.source_var[:15] + "..." if len(v.source_var) > 15 else v.source_var,
                v.source_type,
                str(v.sink_line),
            ])

        summary_table = Table(summary_data, colWidths=[0.8*inch, 0.9*inch, 1.5*inch, 1.2*inch, 1*inch, 0.4*inch])

        row_colors = []
        for i, row in enumerate(summary_data):
            if i == 0:
                row_colors.append(colors.HexColor("#2c3e50"))
            else:
                sev = row[1]
                if sev == "CRITICAL":
                    row_colors.append(colors.HexColor("#fdedec"))
                elif sev == "WARNING":
                    row_colors.append(colors.HexColor("#fef9e7"))
                else:
                    row_colors.append(colors.white)

        summary_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        story.append(summary_table)

        vuln_summary = Table([
            ["CRITICAL", str(report.critical_count)],
            ["WARNING", str(report.warning_count)],
            ["INFO", str(report.info_count)],
            ["TOTAL", str(report.vuln_count)],
        ], colWidths=[1*inch, 0.6*inch])
        vuln_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(Spacer(1, 10))
        story.append(vuln_summary)
    else:
        story.append(Paragraph("No vulnerabilities found.", body_style))

    if report.vulnerabilities:
        story.append(PageBreak())
        story.append(Paragraph("§3  Vulnerability Details", section_style))

        for vuln in report.vulnerabilities:
            sev_color = get_severity_color(vuln.severity)

            story.append(Spacer(1, 12))

            header_data = [[f"{vuln.id} — {vuln.sink}", vuln.severity]]
            header_table = Table(header_data, colWidths=[4.5*inch, 1.5*inch])
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#2c3e50")),
                ("BACKGROUND", (1, 0), (1, 0), sev_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("ALIGN", (0, 0), (0, 0), "LEFT"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(header_table)

            story.append(Spacer(1, 6))

            details_data = [
                ["CWE", vuln.cwe],
                ["Sink", vuln.sink],
                ["Sink Line", str(vuln.sink_line)],
                ["Sink Column", str(vuln.sink_col)],
                ["Sink Expression", vuln.sink_expr],
                ["Argument", vuln.arg],
                ["Source Variable", vuln.source_var],
                ["Source Type", vuln.source_type],
                ["Propagation Mechanism", vuln.mechanism],
            ]
            details_table = Table(details_data, colWidths=[1.6*inch, 4.4*inch])
            details_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(details_table)

            story.append(Spacer(1, 10))
            story.append(Paragraph("Taint Path Trace:", subsection_style))

            path_data = [["Step", "Role", "Line", "Expression"]]
            for step in vuln.taint_path:
                role_style = "bold red" if step.role in ("SOURCE", "SINK") else "yellow"
                path_data.append([
                    str(step.step),
                    step.role,
                    str(step.line),
                    step.expression[:60] + "..." if len(step.expression) > 60 else step.expression,
                ])

            path_table = Table(path_data, colWidths=[0.4*inch, 0.8*inch, 0.4*inch, 4.4*inch])
            path_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ]))
            story.append(path_table)

            story.append(Spacer(1, 10))
            story.append(Paragraph("Remediation:", subsection_style))

            story.append(Paragraph(vuln.remediation, body_style))
            story.append(Spacer(1, 5))

            code_lines = vuln.remediation_code.split("\n")
            code_block = "<br/>".join(line for line in code_lines)
            story.append(
                Paragraph(
                    f"<font face='Courier' size='8' color='#2c3e50'>{code_block}</font>",
                    code_style
                )
            )

            story.append(Spacer(1, 8))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))

    story.append(PageBreak())
    story.append(Paragraph("§4  Safe Paths Confirmed", section_style))

    if report.safe_sinks:
        sink_data = [["Sink", "Line", "Sanitizer", "Protected Variable"]]
        for ss in report.safe_sinks:
            sink_data.append([
                ss.sink,
                str(ss.line),
                ss.sanitizer,
                ss.variable,
            ])
        sink_table = Table(sink_data, colWidths=[1.8*inch, 0.5*inch, 1*inch, 1.5*inch])
        sink_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#27ae60")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f9f0")]),
        ]))
        story.append(sink_table)
    elif report.sanitizations and not report.vulnerabilities:
        story.append(Paragraph(
            "Sanitizers intercepted the taint chain before reaching any SQL sink.",
            body_style
        ))
    elif not report.vulnerabilities:
        story.append(Paragraph("All reachable sinks confirmed safe.", body_style))
    else:
        story.append(Paragraph("No safe sink paths confirmed.", body_style))

    story.append(Spacer(1, 15))
    story.append(Paragraph("§5  Sanitizations Detected", section_style))

    if report.sanitizations:
        san_data = [["Function", "Variable", "Line"]]
        for san in report.sanitizations:
            san_data.append([
                f"{san.function}()",
                san.variable,
                str(san.line) if san.line > 0 else "N/A",
            ])
        san_table = Table(san_data, colWidths=[1.5*inch, 1.5*inch, 0.8*inch])
        san_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f8ff")]),
        ]))
        story.append(san_table)
    else:
        story.append(Paragraph("No sanitization functions detected.", body_style))

    story.append(PageBreak())
    story.append(Paragraph("§6  CFG / DFG Statistics", section_style))

    if report.cfg_stats or report.dfg_stats:
        stats_data = []
        if report.cfg_stats:
            stats_data.extend([
                ["CFG — Total Nodes", str(report.cfg_stats.get("total_nodes", 0))],
                ["CFG — Condition/Loop Nodes", str(report.cfg_stats.get("conditions", 0))],
                ["CFG — Assignment Nodes", str(report.cfg_stats.get("assignments", 0))],
                ["CFG — Call Nodes", str(report.cfg_stats.get("calls", 0))],
                ["CFG — Merge Nodes", str(report.cfg_stats.get("merges", 0))],
            ])
        stats_data.append(["─" * 20, "─" * 8])
        if report.dfg_stats:
            stats_data.extend([
                ["DFG — Total Nodes", str(report.dfg_stats.get("total_nodes", 0))],
                ["DFG — Total Edges", str(report.dfg_stats.get("total_edges", 0))],
                ["DFG — Source Nodes", str(report.dfg_stats.get("sources", 0))],
                ["DFG — Sink Nodes", str(report.dfg_stats.get("sinks", 0))],
                ["DFG — Operator Nodes", str(report.dfg_stats.get("operators", 0))],
                ["DFG — Constant Nodes", str(report.dfg_stats.get("constants", 0))],
                ["DFG — Variable Nodes", str(report.dfg_stats.get("variables", 0))],
                ["Taint Propagation Hops", str(report.dfg_stats.get("taint_hops", 0))],
            ])
        stats_data.append(["─" * 20, "─" * 8])
        stats_data.append(["Analysis Time (ms)", f"{report.analysis_time_ms:.1f}"])

        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
        ]))
        story.append(stats_table)
    else:
        story.append(Paragraph("No statistics available.", body_style))

    story.append(PageBreak())
    story.append(Paragraph("§7  Footer", section_style))

    footer_data = [
        ["Vulnerabilities", f"{report.critical_count} CRITICAL | {report.warning_count} WARNING | {report.info_count} INFO"],
        ["Safe Sinks", str(len(report.safe_sinks))],
        ["Analysis Time", f"{report.analysis_time_ms:.1f} ms"],
        ["Engine Version", report.engine_version],
        ["Final Verdict", report.verdict],
    ]
    footer_table = Table(footer_data, colWidths=[1.8*inch, 4.2*inch])
    footer_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (1, 4), (1, 4), verdict_color),
        ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(footer_table)

    doc.build(story)


def generate_metrics_pdf(output_dir: str = None, console=None) -> bool:
    """
    Generate a standalone PDF report for accuracy metrics.
    Reads output/metrics.json and produces output/pdf/metrics_report.pdf.
    """
    if output_dir is None:
        output_dir = PDF_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    metrics_path = os.path.join(os.path.dirname(__file__), "output", "metrics.json")
    if not os.path.isfile(metrics_path):
        if console:
            console.print("[yellow]⚠ No metrics.json found — skipping metrics PDF[/yellow]")
        return False

    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        if console:
            console.print(f"[red]✗ Could not read metrics.json: {e}[/red]")
        return False

    agg = data.get("aggregate_metrics", {})
    cases = data.get("cases", [])
    timestamp = data.get("timestamp", "")

    pdf_path = os.path.join(output_dir, "metrics_report.pdf")
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=LETTER,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=30,
        alignment=TA_CENTER,
    )

    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.white,
        spaceBefore=20,
        spaceAfter=10,
        backgroundColor=colors.HexColor("#2c3e50"),
        leftPadding=8,
    )

    subsection_style = ParagraphStyle(
        "SubsectionHeading",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=12,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        spaceAfter=6,
    )

    # ── Cover page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("Accuracy Metrics Report", title_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Security Linter — False Positive / False Negative Analysis",
        ParagraphStyle("Subtitle", parent=title_style, fontSize=14,
                       textColor=colors.HexColor("#555555"), spaceAfter=40),
    ))
    story.append(Spacer(1, 20))

    meta_data = [
        ["Generated", timestamp],
        ["Total Cases", str(agg.get("total_cases", 0))],
        ["True Positives", str(agg.get("true_positives", 0))],
        ["True Negatives", str(agg.get("true_negatives", 0))],
        ["False Positives", str(agg.get("false_positives", 0))],
        ["False Negatives", str(agg.get("false_negatives", 0))],
    ]
    meta_table = Table(meta_data, colWidths=[1.8*inch, 4.2*inch])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)

    # ── §1 Confusion Matrix ───────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("§1  Confusion Matrix", section_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Comparison of linter output against ground truth defined in "
        "<code>samples/ground_truth.json</code>.",
        body_style,
    ))
    story.append(Spacer(1, 12))

    tp = agg.get("true_positives", 0)
    tn = agg.get("true_negatives", 0)
    fp = agg.get("false_positives", 0)
    fn = agg.get("false_negatives", 0)

    confusion_data = [
        ["", "Actually Vulnerable", "Actually Safe"],
        ["Reported VULNERABLE", f"True Positive: {tp}", f"False Positive: {fp}"],
        ["Reported SAFE", f"False Negative: {fn}", f"True Negative: {tn}"],
    ]
    confusion_table = Table(confusion_data, colWidths=[1.5*inch, 2.2*inch, 2.2*inch])
    confusion_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(confusion_table)

    # ── §2 Aggregate Metrics ──────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(Paragraph("§2  Aggregate Metrics", section_style))
    story.append(Spacer(1, 10))

    prec = agg.get("precision", 0)
    rec = agg.get("recall", 0)
    f1 = agg.get("f1_score", 0)
    fpr = agg.get("false_positive_rate", 0)
    fnr = agg.get("false_negative_rate", 0)
    acc = agg.get("accuracy", 0)

    metrics_data = [
        ["Metric", "Value"],
        ["Precision", f"{prec:.1%}"],
        ["Recall", f"{rec:.1%}"],
        ["F1 Score", f"{f1:.1%}"],
        ["False Positive Rate", f"{fpr:.1%}"],
        ["False Negative Rate", f"{fnr:.1%}"],
        ["Accuracy", f"{acc:.1%}"],
    ]
    metrics_table = Table(metrics_data, colWidths=[2.5*inch, 3.5*inch])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#ecf0f1")),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(metrics_table)

    # ── §3 Per-Case Results ───────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("§3  Per-Case Results", section_style))
    story.append(Spacer(1, 10))

    case_data = [["Case", "Expected", "Actual", "TP", "FP", "FN", "Result"]]
    for cr in cases:
        case_name = cr.get("case", "").replace(".py", "").replace("case", "C")
        exp = "VULN" if "VULNERABLE" in cr.get("expected_verdict", "") else "SAFE"
        act = "VULN" if "VULNERABLE" in cr.get("actual_verdict", "") else "SAFE"
        cls = cr.get("classification", "")
        case_data.append([
            case_name, exp, act,
            str(cr.get("true_positives", 0)),
            str(cr.get("false_positives", 0)),
            str(cr.get("false_negatives", 0)),
            cls,
        ])

    case_table = Table(case_data, colWidths=[1.8*inch, 0.7*inch, 0.7*inch, 0.5*inch, 0.5*inch, 0.5*inch, 0.8*inch])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 1), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    for i, cr in enumerate(cases):
        row_idx = i + 1
        cls = cr.get("classification", "")
        if cls in ("TP", "TN"):
            case_table.setStyle(TableStyle([
                ("TEXTCOLOR", (6, row_idx), (6, row_idx), colors.Color(0.2, 0.6, 0.3)),
                ("FONTNAME", (6, row_idx), (6, row_idx), "Helvetica-Bold"),
            ]))
        else:
            case_table.setStyle(TableStyle([
                ("TEXTCOLOR", (6, row_idx), (6, row_idx), colors.Color(0.85, 0.2, 0.2)),
                ("FONTNAME", (6, row_idx), (6, row_idx), "Helvetica-Bold"),
            ]))
    story.append(case_table)

    # ── §4 False Positive / Negative Details ──────────────────────────────────
    has_details = False
    for cr in cases:
        if cr.get("fp_details") or cr.get("fn_details"):
            has_details = True
            break

    if has_details:
        story.append(Spacer(1, 20))
        story.append(Paragraph("§4  Error Details", section_style))
        story.append(Spacer(1, 10))

        for cr in cases:
            fp_d = cr.get("fp_details", [])
            fn_d = cr.get("fn_details", [])
            if not fp_d and not fn_d:
                continue

            case_name = cr.get("case", "").replace(".py", "")
            story.append(Paragraph(f"<b>{case_name}</b>", subsection_style))

            for detail in fp_d:
                story.append(Paragraph(
                    f'<font color="red">[FP]</font> {detail}',
                    ParagraphStyle("Detail", parent=body_style, fontSize=9),
                ))
            for detail in fn_d:
                story.append(Paragraph(
                    f'<font color="red">[FN]</font> {detail}',
                    ParagraphStyle("Detail", parent=body_style, fontSize=9),
                ))
            story.append(Spacer(1, 4))

    doc.build(story)

    if console:
        console.print(f"  [green]✓[/green] metrics_report.pdf")
    return True


def generate_all_pdfs(
    reports_dir: str = None,
    output_dir: str = None,
    console=None,
) -> int:
    if reports_dir is None:
        reports_dir = os.path.join(os.path.dirname(__file__), "output", "reports")
    if output_dir is None:
        output_dir = PDF_OUTPUT_DIR

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.isdir(reports_dir):
        if console:
            console.print(f"[red]Reports directory not found: {reports_dir}[/red]")
        return 0

    json_files = [f for f in os.listdir(reports_dir) if f.endswith(".json")]

    if not json_files:
        if console:
            console.print(f"[yellow]No JSON reports found in {reports_dir}[/yellow]")
        return 0

    count = 0
    for json_file in json_files:
        json_path = os.path.join(reports_dir, json_file)
        try:
            report = load_json_report(json_path)
            pdf_name = json_file.replace(".json", ".pdf")
            pdf_path = os.path.join(output_dir, pdf_name)
            build_pdf(report, pdf_path)
            count += 1
            if console:
                console.print(f"  [green]✓[/green] {pdf_name}")
        except Exception as e:
            if console:
                console.print(f"  [red]✗[/red] {json_file}: {e}")

    return count


if __name__ == "__main__":
    import sys

    print("Generating PDF reports...")
    count = generate_all_pdfs()
    print(f"\nGenerated {count} PDF reports in {PDF_OUTPUT_DIR}/")