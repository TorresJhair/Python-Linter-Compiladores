"""
report_generator.py — Security Linter Report Generator
=======================================================

Genera dos artefactos por archivo analizado:
  output/reports/<slug>.json — reporte machine-readable para CI/CD
  Terminal rich              — reporte legible con las 7 secciones

Secciones del reporte
---------------------
  §1  Header / metadata        — filename, timestamp, LOC, verdict
  §2  Executive summary        — tabla compacta de vulnerabilidades
  §3  Vulnerability details    — bloque completo por cada hallazgo
  §4  Safe paths confirmed     — sinks analizados y confirmados seguros
  §5  Sanitizations detected   — sanitizadores encontrados y variables protegidas
  §6  CFG / DFG statistics     — métricas de los grafos y del análisis
  §7  Footer                   — totales, tiempo, versión del motor

Severidad
---------
  CRITICAL — al menos un camino sin sanitización llega al sink
  WARNING  — el CFG tiene ramas condicionales; la vulnerabilidad solo
             existe en algunos caminos
  INFO     — variable tainted detectada pero ningún sink SQL alcanzado
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime    import datetime, timezone
from typing      import List, Optional

from rich          import box as rbox
from rich.columns  import Columns
from rich.console  import Console
from rich.panel    import Panel
from rich.rule     import Rule
from rich.table    import Table
from rich.text     import Text

from cfg_builder   import CFG, CFGNodeType
from dfg_builder   import DFG, DFGNodeType
from symbol_table  import SymbolTable
from taint_engine  import (
    TaintPropagationResult, Vulnerability, TaintRecord, TaintSource,
)

ENGINE_VERSION = "1.0.0"


# ──────────────────────────────────────────────────────────────────────────────
# Modelo de datos del reporte
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PathStep:
    step:       int
    role:       str    # SOURCE | ASSIGN | OPERATOR | SINK
    line:       int
    col:        int
    expression: str


@dataclass
class VulnDetail:
    id:               str   # CVE-SL-NNN
    severity:         str   # CRITICAL | WARNING | INFO
    sink:             str
    sink_line:        int
    sink_col:         int
    sink_expr:        str
    arg_name:         str
    source_var:       str
    source_type:      str   # HTTP_FORM | HTTP_ARGS | STDIN | …
    prop_mechanism:   str
    taint_path:       List[PathStep]
    remediation:      str
    remediation_code: str


@dataclass
class SafeSink:
    sink:      str
    line:      int
    sanitizer: str
    variable:  str


@dataclass
class SanitizationRecord:
    function: str
    variable: str
    line:     int


@dataclass
class CFGStats:
    total_nodes: int
    conditions:  int
    assignments: int
    calls:       int
    merges:      int


@dataclass
class DFGStats:
    total_nodes: int
    total_edges: int
    sources:     int
    sinks:       int
    operators:   int
    constants:   int
    variables:   int
    taint_hops:  int


@dataclass
class ReportData:
    # §1 Header
    filename:         str
    filepath:         str
    timestamp:        str
    loc:              int
    verdict:          str   # VULNERABLE | SAFE | SAFE (no SQL sink)
    # §2 Summary counts
    vuln_count:       int
    critical_count:   int
    warning_count:    int
    info_count:       int
    # §3 Vulnerabilities
    vulnerabilities:  List[VulnDetail]          = field(default_factory=list)
    # §4 Safe paths
    safe_sinks:       List[SafeSink]            = field(default_factory=list)
    # §5 Sanitizations
    sanitizations:    List[SanitizationRecord]  = field(default_factory=list)
    # §6 Stats
    cfg_stats:        Optional[CFGStats]        = None
    dfg_stats:        Optional[DFGStats]        = None
    analysis_time_ms: float                     = 0.0
    # §7 Footer
    engine_version:   str                       = ENGINE_VERSION


# ──────────────────────────────────────────────────────────────────────────────
# Tablas de conversión
# ──────────────────────────────────────────────────────────────────────────────

_SOURCE_LABELS: dict[str, str] = {
    "INPUT":        "STDIN",
    "STDIN":        "STDIN",
    "REQUEST_ARGS": "HTTP_ARGS",
    "REQUEST_FORM": "HTTP_FORM",
    "REQUEST_JSON": "HTTP_JSON",
    "COOKIES":      "HTTP_COOKIE",
    "SESSION":      "HTTP_SESSION",
    "ENV":          "ENV_VAR",
    "PARAM":        "FUNCTION_PARAM",
    "UNKNOWN":      "EXTERNAL",
}

# Sugerencias de remediación indexadas por tipo de fuente
_REMEDIATIONS: dict[str, tuple[str, str]] = {
    "STDIN": (
        "Use a parameterized query and validate the input type. "
        "If the value must be an integer, cast it with int():",
        'user_id = int(input("ID: "))\n'
        'query = "SELECT * FROM users WHERE id = ?"\n'
        'cursor.execute(query, (user_id,))',
    ),
    "HTTP_ARGS": (
        "Use a parameterized query. Never interpolate HTTP parameters directly into SQL:",
        'name = request.args.get("name")\n'
        'query = "SELECT * FROM users WHERE name = %s"\n'
        'cursor.execute(query, (name,))',
    ),
    "HTTP_FORM": (
        "Use a parameterized query. The database driver escapes the value automatically:",
        'username = request.form.get("user")\n'
        'sql = "SELECT id FROM accounts WHERE login = %s"\n'
        'db.execute(sql, (username,))',
    ),
    "HTTP_JSON": (
        "Validate and use parameterized queries for any JSON-sourced data:",
        'value = request.json.get("field")\n'
        'cursor.execute("SELECT * FROM t WHERE col = %s", (value,))',
    ),
    "FUNCTION_PARAM": (
        "Validate the parameter type at the function entry point before using it in SQL:",
        'def fetch_product(product_id):\n'
        '    safe_id = int(product_id)  # raises ValueError on bad input\n'
        '    cursor.execute("SELECT * FROM products WHERE id = ?", (safe_id,))',
    ),
    "EXTERNAL": (
        "Identify the data source and use a parameterized query. "
        "Never concatenate external data into SQL strings:",
        '# Replace string building with a parameterized query:\n'
        'cursor.execute("SELECT * FROM t WHERE col = %s", (external_value,))',
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
# Assembler
# ──────────────────────────────────────────────────────────────────────────────

def _severity(cfg: CFG) -> str:
    """CRITICAL si no hay ramas condicionales; WARNING si el CFG tiene condiciones."""
    has_conditions = any(
        n.type in (CFGNodeType.CONDITION, CFGNodeType.LOOP_HEAD)
        for n in cfg.nodes.values()
    )
    return "WARNING" if has_conditions else "CRITICAL"


def _detect_mechanism(source_label: str, source_str: str) -> str:
    src = source_str.lower()
    if "fstring" in src or "f-string" in src:  return "f-string interpolation"
    if "pctfmt"  in src or "percent"  in src:  return "printf-style format (%)"
    if "augop"   in src or "augment"  in src:  return "augmented assignment (+=)"
    if "binop"   in src or "binary"   in src:  return "string concatenation (+)"
    if "propagation" in src:                    return "taint propagation (augmented assignment)"
    if "input"   in src:                        return "direct assignment from stdin"
    if "request" in src:                        return "direct assignment from HTTP request"
    if "param"   in src:                        return "function parameter (interprocedural)"
    return "data flow propagation"


def _build_path(
    vuln:         Vulnerability,
    result:       TaintPropagationResult,
    source_lines: List[str],
) -> List[PathStep]:
    steps: List[PathStep] = []
    step = 1

    # Buscar el registro de fuente más relevante
    src_record = next(
        (r for r in result.sources
         if r.variable == vuln.arg_name or r.variable in vuln.taint_path),
        next(iter(result.sources), None),
    )

    def _line_text(line_no: int) -> str:
        if line_no and 1 <= line_no <= len(source_lines):
            return source_lines[line_no - 1].strip()
        return ""

    if src_record:
        steps.append(PathStep(
            step=step, role="SOURCE",
            line=src_record.line, col=src_record.col,
            expression=_line_text(src_record.line) or src_record.source,
        ))
        step += 1

    # Primer paso de propagación intermedia
    for prop in result.propagations:
        if prop.variable in (vuln.arg_name, *vuln.taint_path):
            steps.append(PathStep(
                step=step, role="ASSIGN",
                line=prop.line, col=prop.col,
                expression=_line_text(prop.line) or prop.variable,
            ))
            step += 1
            break

    # Sink
    sink_expr = (
        _line_text(vuln.line)
        or f"{vuln.sink}({vuln.arg_name})"
    )
    steps.append(PathStep(
        step=step, role="SINK",
        line=vuln.line, col=vuln.col,
        expression=sink_expr,
    ))
    return steps


def assemble_report(
    filepath:   str,
    source:     str,
    result:     TaintPropagationResult,
    cfg:        CFG,
    dfg:        DFG,
    st:         SymbolTable,
    elapsed_ms: float,
) -> ReportData:
    filename     = os.path.basename(filepath)
    source_lines = source.splitlines()
    loc          = sum(
        1 for l in source_lines
        if l.strip() and not l.strip().startswith("#")
    )

    # ── Vulnerability details ─────────────────────────────────────────────────
    vuln_details: List[VulnDetail] = []
    for i, v in enumerate(result.vulnerabilities, 2):
        severity = _severity(cfg)

        src_record = next(
            (r for r in result.sources
             if r.variable == v.arg_name or r.variable in v.taint_path),
            next(iter(result.sources), None),
        )
        source_type_key = (src_record.source_type.name
                           if src_record else "UNKNOWN")
        source_label    = _SOURCE_LABELS.get(source_type_key, "EXTERNAL")
        source_var      = src_record.variable if src_record else v.arg_name
        src_str         = src_record.source   if src_record else ""

        mechanism        = _detect_mechanism(source_label, src_str)
        rem_text, rem_code = _REMEDIATIONS.get(source_label,
                                               _REMEDIATIONS["EXTERNAL"])

        sink_expr = (
            source_lines[v.line - 1].strip()
            if v.line and 1 <= v.line <= len(source_lines)
            else f"{v.sink}({v.arg_name})"
        )

        vuln_details.append(VulnDetail(
            id               = f"CVE-SL-{i:03d}",
            severity         = severity,
            sink             = v.sink,
            sink_line        = v.line,
            sink_col         = v.col,
            sink_expr        = sink_expr,
            arg_name         = v.arg_name,
            source_var       = source_var,
            source_type      = source_label,
            prop_mechanism   = mechanism,
            taint_path       = _build_path(v, result, source_lines),
            remediation      = rem_text,
            remediation_code = rem_code,
        ))

    # ── Safe sinks ────────────────────────────────────────────────────────────
    safe_sinks: List[SafeSink] = []
    seen_sinks: set[tuple] = set()
    if result.sanitizations:
        for sym in st.get_all_symbols():
            if sym.sanitizer:
                for line_no, line in enumerate(source_lines, 1):
                    stripped = line.strip()
                    base = stripped.split("(")[0].strip().rsplit(".", 1)[-1]
                    if st.is_sink(base):
                        key = (stripped.split("(")[0].strip(), line_no,
                               sym.sanitizer, sym.name)
                        if key not in seen_sinks:
                            seen_sinks.add(key)
                            safe_sinks.append(SafeSink(
                                sink=key[0], line=key[1],
                                sanitizer=key[2], variable=key[3],
                            ))
                        break

    # ── Sanitization records ──────────────────────────────────────────────────
    san_records: List[SanitizationRecord] = []
    seen_san: set[tuple] = set()
    for san in result.sanitizations:
        for sym in st.get_all_symbols():
            if sym.sanitizer == san:
                key = (san, sym.name)
                if key not in seen_san:
                    seen_san.add(key)
                    san_records.append(SanitizationRecord(
                        function=san, variable=sym.name, line=sym.line,
                    ))

    # ── CFG stats ─────────────────────────────────────────────────────────────
    cfg_stats = CFGStats(
        total_nodes = len(cfg.nodes),
        conditions  = sum(
            1 for n in cfg.nodes.values()
            if n.type in (CFGNodeType.CONDITION, CFGNodeType.LOOP_HEAD)
        ),
        assignments = sum(
            1 for n in cfg.nodes.values()
            if n.type == CFGNodeType.ASSIGN
        ),
        calls       = sum(
            1 for n in cfg.nodes.values()
            if n.type == CFGNodeType.CALL
        ),
        merges      = sum(
            1 for n in cfg.nodes.values()
            if n.type == CFGNodeType.MERGE
        ),
    )

    # ── DFG stats ─────────────────────────────────────────────────────────────
    dfg_stats = DFGStats(
        total_nodes = len(dfg.nodes),
        total_edges = len(dfg.edges),
        sources     = sum(1 for n in dfg.nodes.values()
                          if n.type == DFGNodeType.SOURCE),
        sinks       = sum(1 for n in dfg.nodes.values()
                          if n.type == DFGNodeType.SINK),
        operators   = sum(1 for n in dfg.nodes.values()
                          if n.type == DFGNodeType.OPERATOR),
        constants   = sum(1 for n in dfg.nodes.values()
                          if n.type == DFGNodeType.CONSTANT),
        variables   = sum(1 for n in dfg.nodes.values()
                          if n.type == DFGNodeType.VARIABLE),
        taint_hops  = len(result.propagations) + len(result.sources),
    )

    # ── Verdict ───────────────────────────────────────────────────────────────
    if result.vulnerabilities:
        verdict = "VULNERABLE"
    elif dfg_stats.sinks == 0:
        verdict = "SAFE (no SQL sink)"
    else:
        verdict = "SAFE"

    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for vd in vuln_details:
        counts[vd.severity] = counts.get(vd.severity, 0) + 1

    return ReportData(
        filename         = filename,
        filepath         = filepath,
        timestamp        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        loc              = loc,
        verdict          = verdict,
        vuln_count       = len(vuln_details),
        critical_count   = counts["CRITICAL"],
        warning_count    = counts["WARNING"],
        info_count       = counts["INFO"],
        vulnerabilities  = vuln_details,
        safe_sinks       = safe_sinks,
        sanitizations    = san_records,
        cfg_stats        = cfg_stats,
        dfg_stats        = dfg_stats,
        analysis_time_ms = elapsed_ms,
        engine_version   = ENGINE_VERSION,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Rich terminal renderer
# ──────────────────────────────────────────────────────────────────────────────

_SEV_STYLE  = {"CRITICAL": "bold red", "WARNING": "bold yellow", "INFO": "bold blue"}
_SEV_ICON   = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}
_VRD_STYLE  = {
    "VULNERABLE":         "bold red",
    "SAFE":               "bold green",
    "SAFE (no SQL sink)": "bold green",
}


def render_terminal(report: ReportData, con: Console):
    """Imprime el reporte completo de 7 secciones en la consola rich."""

    vs = _VRD_STYLE.get(report.verdict, "white")

    # ── §1 Header ─────────────────────────────────────────────────────────────
    con.print()
    con.print(Panel(
        f"[bold white]{report.filename}[/bold white]\n"
        f"[dim white]Timestamp :[/dim white]  {report.timestamp}\n"
        f"[dim white]Lines (LOC):[/dim white]  {report.loc}\n"
        f"[dim white]Verdict   :[/dim white]  [{vs}]{report.verdict}[/{vs}]",
        title="[bold cyan]§1  Header / Metadata[/bold cyan]",
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    ))

    # ── §2 Executive summary ──────────────────────────────────────────────────
    con.print(Rule("[bold cyan]§2  Executive Summary[/bold cyan]",
                   style="dim cyan"))
    if not report.vulnerabilities:
        con.print("  [green]No vulnerabilities found.[/green]\n")
    else:
        tbl = Table(
            show_header=True, header_style="bold white",
            border_style="dim white", box=rbox.SIMPLE_HEAVY, expand=False,
        )
        tbl.add_column("ID",          style="dim white",  width=10)
        tbl.add_column("Severity",    style="bold",       width=12)
        tbl.add_column("Sink",        style="cyan",       width=24)
        tbl.add_column("Source var",  style="yellow",     width=20)
        tbl.add_column("Source type", style="white",      width=16)
        tbl.add_column("Line",        style="dim white",  width=6, justify="right")
        for vd in report.vulnerabilities:
            ss = _SEV_STYLE.get(vd.severity, "white")
            tbl.add_row(
                vd.id,
                f"[{ss}]{_SEV_ICON.get(vd.severity,'')} {vd.severity}[/{ss}]",
                vd.sink,
                vd.source_var,
                vd.source_type,
                str(vd.sink_line),
            )
        con.print(tbl)
        con.print()

    # ── §3 Vulnerability details ──────────────────────────────────────────────
    if report.vulnerabilities:
        con.print(Rule("[bold cyan]§3  Vulnerability Details[/bold cyan]",
                       style="dim cyan"))

    for vd in report.vulnerabilities:
        ss = _SEV_STYLE.get(vd.severity, "white")
        border_color = vd.severity.lower().replace("critical", "red").replace("warning", "yellow")

        con.print(Panel(
            f"[{ss}]{_SEV_ICON.get(vd.severity,'')} {vd.severity}[/{ss}]"
            f"   [dim white]{vd.id}  ·  CWE-89  ·  SQL Injection[/dim white]",
            title=f"[bold white]{vd.id} — {vd.sink}[/bold white]",
            border_style=border_color,
            expand=False,
            padding=(0, 2),
        ))

        # Sink location
        con.print(
            f"  [dim white]Sink       :[/dim white]  [cyan]{vd.sink}[/cyan]"
            f"  line [bold]{vd.sink_line}[/bold], col {vd.sink_col}"
        )
        con.print(
            f"  [dim white]Expression :[/dim white]  [white]{vd.sink_expr}[/white]"
        )
        con.print()

        # Taint path trace
        con.print("  [dim white]Taint path trace:[/dim white]")
        role_styles = {"SOURCE": "bold red", "ASSIGN": "yellow", "SINK": "bold red"}
        for step in vd.taint_path:
            rs = role_styles.get(step.role, "white")
            con.print(
                f"    [{rs}][{step.step}] {step.role:<8}[/{rs}]"
                f"  [dim white]line {step.line:>3}[/dim white]"
                f"  [white]{step.expression}[/white]"
            )
        con.print()

        # Metadata
        con.print(
            f"  [dim white]Source classification :[/dim white]  "
            f"[yellow]{vd.source_type}[/yellow]"
        )
        con.print(
            f"  [dim white]Propagation mechanism :[/dim white]  "
            f"[white]{vd.prop_mechanism}[/white]"
        )
        con.print()

        # Remediation
        con.print(f"  [dim white]Remediation:[/dim white]  {vd.remediation}")
        con.print()
        con.print("  [dim white]Suggested fix:[/dim white]")
        for ln in vd.remediation_code.splitlines():
            con.print(f"    [green]{ln}[/green]")
        con.print()

    # ── §4 Safe paths ─────────────────────────────────────────────────────────
    con.print(Rule("[bold cyan]§4  Safe Paths Confirmed[/bold cyan]",
                   style="dim cyan"))
    if report.safe_sinks:
        for ss in report.safe_sinks:
            con.print(
                f"  [green]✓[/green]  [cyan]{ss.sink}[/cyan]"
                f"  line {ss.line}"
                f"  protected by [bold green]{ss.sanitizer}[/bold green]"
                f"  (variable: [yellow]{ss.variable}[/yellow])"
            )
    elif report.sanitizations:
        con.print(
            "  [green]✓[/green]  Sanitizers intercepted the taint chain "
            "before reaching any SQL sink."
        )
    elif not report.vulnerabilities:
        con.print(
            f"  [{vs}]All reachable sinks confirmed safe.[/{vs}]"
        )
    else:
        con.print("  [dim white]No safe sink paths confirmed.[/dim white]")
    con.print()

    # ── §5 Sanitizations ──────────────────────────────────────────────────────
    con.print(Rule("[bold cyan]§5  Sanitizations Detected[/bold cyan]",
                   style="dim cyan"))
    if not report.sanitizations:
        con.print("  [dim white]No sanitization functions detected.[/dim white]\n")
    else:
        for sr in report.sanitizations:
            con.print(
                f"  [green]✓[/green]  "
                f"[bold green]{sr.function}()[/bold green]"
                f"  →  variable [yellow]{sr.variable}[/yellow]"
                f"  (line {sr.line})"
            )
        con.print()

    # ── §6 Statistics ─────────────────────────────────────────────────────────
    con.print(Rule("[bold cyan]§6  CFG / DFG Statistics[/bold cyan]",
                   style="dim cyan"))
    if report.cfg_stats and report.dfg_stats:
        cs, ds = report.cfg_stats, report.dfg_stats
        tbl = Table(
            show_header=True, header_style="bold dim white",
            border_style="dim white", box=rbox.SIMPLE, expand=False,
        )
        tbl.add_column("Metric",  style="dim white",  width=34)
        tbl.add_column("Value",   style="bold white", width=10, justify="right")
        tbl.add_row("CFG — total nodes",          str(cs.total_nodes))
        tbl.add_row("CFG — condition / loop nodes", str(cs.conditions))
        tbl.add_row("CFG — assignment nodes",     str(cs.assignments))
        tbl.add_row("CFG — call nodes",           str(cs.calls))
        tbl.add_row("CFG — merge nodes",          str(cs.merges))
        tbl.add_row("─" * 32,                     "─" * 8)
        tbl.add_row("DFG — total nodes",          str(ds.total_nodes))
        tbl.add_row("DFG — total edges",          str(ds.total_edges))
        tbl.add_row("DFG — source nodes",         str(ds.sources))
        tbl.add_row("DFG — sink nodes",           str(ds.sinks))
        tbl.add_row("DFG — operator nodes",       str(ds.operators))
        tbl.add_row("DFG — variable nodes",       str(ds.variables))
        tbl.add_row("DFG — constant nodes",       str(ds.constants))
        tbl.add_row("─" * 32,                     "─" * 8)
        tbl.add_row("Taint propagation hops",     str(ds.taint_hops))
        tbl.add_row("Analysis time (ms)",
                    f"{report.analysis_time_ms:.1f}")
        con.print(tbl)
    con.print()

    # ── §7 Footer ─────────────────────────────────────────────────────────────
    con.print(Rule("[bold cyan]§7  Footer[/bold cyan]", style="dim cyan"))
    con.print(Panel(
        f"[dim white]Vulnerabilities :[/dim white]  "
        f"[bold red]{report.critical_count} CRITICAL[/bold red]  "
        f"[bold yellow]{report.warning_count} WARNING[/bold yellow]  "
        f"[bold blue]{report.info_count} INFO[/bold blue]\n"
        f"[dim white]Safe sinks      :[/dim white]  "
        f"[green]{len(report.safe_sinks)}[/green]\n"
        f"[dim white]Analysis time   :[/dim white]  "
        f"{report.analysis_time_ms:.1f} ms\n"
        f"[dim white]Engine version  :[/dim white]  "
        f"{report.engine_version}\n"
        f"[dim white]Final verdict   :[/dim white]  "
        f"[{vs}]{report.verdict}[/{vs}]",
        title="[bold cyan]Analysis Complete[/bold cyan]",
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    ))
    con.print()


# ──────────────────────────────────────────────────────────────────────────────
# JSON renderer
# ──────────────────────────────────────────────────────────────────────────────

def render_json(report: ReportData, output_path: str):
    """Serializa el reporte como JSON estructurado para CI/CD."""
    data = {
        "schema_version": "1.0",
        "engine":         report.engine_version,
        "file":           report.filename,
        "filepath":       report.filepath,
        "timestamp":      report.timestamp,
        "loc":            report.loc,
        "verdict":        report.verdict,
        "summary": {
            "total":    report.vuln_count,
            "critical": report.critical_count,
            "warning":  report.warning_count,
            "info":     report.info_count,
        },
        "vulnerabilities": [
            {
                "id":               vd.id,
                "severity":         vd.severity,
                "cwe":              "CWE-89",
                "sink":             vd.sink,
                "sink_line":        vd.sink_line,
                "sink_col":         vd.sink_col,
                "sink_expr":        vd.sink_expr,
                "arg":              vd.arg_name,
                "source_var":       vd.source_var,
                "source_type":      vd.source_type,
                "mechanism":        vd.prop_mechanism,
                "taint_path": [
                    {
                        "step": s.step,
                        "role": s.role,
                        "line": s.line,
                        "col":  s.col,
                        "expr": s.expression,
                    }
                    for s in vd.taint_path
                ],
                "remediation":      vd.remediation,
                "remediation_code": vd.remediation_code,
            }
            for vd in report.vulnerabilities
        ],
        "safe_sinks": [
            {
                "sink":      ss.sink,
                "line":      ss.line,
                "sanitizer": ss.sanitizer,
                "variable":  ss.variable,
            }
            for ss in report.safe_sinks
        ],
        "sanitizations": [
            {
                "function": sr.function,
                "variable": sr.variable,
                "line":     sr.line,
            }
            for sr in report.sanitizations
        ],
        "statistics": {
            "cfg": asdict(report.cfg_stats)  if report.cfg_stats  else {},
            "dfg": asdict(report.dfg_stats)  if report.dfg_stats  else {},
            "analysis_time_ms": report.analysis_time_ms,
        },
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────────────────────────────────────
# Punto de entrada
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(
    filepath:   str,
    source:     str,
    result:     TaintPropagationResult,
    cfg:        CFG,
    dfg:        DFG,
    st:         SymbolTable,
    elapsed_ms: float,
    output_dir: str,
    con:        Console,
) -> ReportData:
    """
    Ensambla el reporte, lo imprime en terminal y lo guarda como JSON.

    Parámetros
    ----------
    filepath   : ruta absoluta del archivo analizado
    source     : contenido del archivo como string
    result     : resultado del TaintPropagationEngine
    cfg        : Control Flow Graph construido
    dfg        : Data Flow Graph construido
    st         : SymbolTable tras el análisis
    elapsed_ms : tiempo de análisis en milisegundos
    output_dir : carpeta destino del JSON (output/reports)
    con        : consola rich

    Retorna el ReportData ensamblado.
    """
    os.makedirs(output_dir, exist_ok=True)
    slug = os.path.splitext(os.path.basename(filepath))[0]

    report = assemble_report(filepath, source, result, cfg, dfg, st, elapsed_ms)
    render_terminal(report, con)

    json_path = os.path.join(output_dir, f"{slug}.json")
    render_json(report, json_path)
    con.print(
        f"  [dim white]JSON report →[/dim white] "
        f"[bold cyan]{os.path.relpath(json_path)}[/bold cyan]\n"
    )
    return report
