"""
main.py — Security Linter — Phase 1 + Phase 2
==============================================

Phase 1: "No reimplementa el lexer ni el parser; consume directamente el AST
producido por el compilador huésped."

Phase 2: Extended semantic analysis (linter core)
- CFG Builder models all possible execution paths
- DFG Builder tracks how values flow between variables
- Taint Propagation Engine marks variables from user-controlled sources
- Report Generator creates terminal + JSON reports

Directory structure
------------------
  samples/          ← input source code (one .py per case)
  output/
  │   ├── ast/          ← AST PNG
  │   ├── cfg/          ← CFG PNG
  │   ├── dfg/          ← DFG PNG
  │   ├── legend/       ← legends
  │   └── reports/      ← JSON reports (NEW)

Pipeline per file in samples/
------------------------------
  1. Read .py from samples/
  2. AST Consumer → AST (Module)
  3. CFG Builder → CFG → output/cfg/
  4. DFG Builder → DFG → output/dfg/
  5. Symbol Table + Taint Engine
  6. Report Generator → terminal + JSON
  7. Export AST, CFG, DFG as PNG
"""

import os
import sys
import time

from rich.console import Console
from rich.panel   import Panel
from rich.rule    import Rule

from ast_consumer    import ASTConsumer
from ast_printer     import print_ast_tree
from ast_visualizer  import ASTVisualizer
from cfg_builder     import CFGBuilder
from cfg_visualizer  import CFGVisualizer
from dfg_builder     import DFGBuilder
from dfg_visualizer  import DFGVisualizer
from symbol_table    import SymbolTable
from taint_engine    import TaintPropagationEngine
from report_generator import generate_report
from pdf_report_generator import generate_all_pdfs, generate_metrics_pdf
from test_metrics import run_all_cases, render_terminal_report, render_json_report

con = Console()

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
AST_DIR     = os.path.join(BASE_DIR, "output", "ast")
CFG_DIR     = os.path.join(BASE_DIR, "output", "cfg")
DFG_DIR     = os.path.join(BASE_DIR, "output", "dfg")
REPORTS_DIR = os.path.join(BASE_DIR, "output", "reports")
LEGEND_DIR  = os.path.join(BASE_DIR, "output", "legend")

CASE_META: dict[str, str] = {
    "case1_simple_assignment.py":    "Figure 1. Simple Assignment (Safe)",
    "case2_sqli_concatenation.py":   "Figure 2. SQLi via String Concatenation",
    "case3_sqli_fstring.py":         "Figure 3. SQLi via f-string (Flask)",
    "case4_sqli_printf.py":         "Figure 4. SQLi via printf-style",
    "case5_safe_sanitizer.py":       "Figure 5. Safe Path with int() Sanitizer",
    "case6_augassign_conditional.py": "Figure 6. Conditional SQLi via AugAssign",
    "case7_orm_injection.py":        "Figure 7. ORM with Raw SQL Injection",
    "case8_safe_orm.py":             "Figure 8. Safe ORM with Parameterized Queries",
    "case9_complex_propagation.py":  "Figure 9. Complex Taint Propagation",
    "case10_dynamic_columns.py":     "Figure 10. Dynamic Table/Column Names (SQLi)",
    "case11_enterprise_app.py":     "Figure 11. Enterprise App (Safe with Validation)",
}


def run_case(
    sample_path: str,
    caption: str,
    ast_viz: ASTVisualizer,
    cfg_viz: CFGVisualizer,
    dfg_viz: DFGVisualizer,
    consumer: ASTConsumer,
) -> bool:
    filename = os.path.basename(sample_path)
    slug     = os.path.splitext(filename)[0]

    con.print()
    con.print(Rule(f"[bold white]{caption}[/bold white]", style="dim white"))

    try:
        with open(sample_path, encoding="utf-8") as f:
            source = f.read()
    except OSError as exc:
        con.print(f"  [bold red]✗ Could not read {sample_path}:[/bold red] {exc}")
        return False

    start_time = time.perf_counter()

    con.print(Rule("[dim cyan]📄  Source — " + filename + "[/dim cyan]", style="dim white"))
    for i, line in enumerate(source.splitlines(), 1):
        con.print(f"  {i:>3} │ {line}")

    try:
        tree = consumer.consume(source)
    except Exception as exc:
        con.print(f"  [bold red]✗ AST Consumer error:[/bold red] {exc}")
        return False

    con.print(Rule("[dim cyan]🌳  AST[/dim cyan]", style="dim white"))
    print_ast_tree(tree, con=con)

    cfg = None
    con.print(Rule("[dim cyan]🔗  CFG Build[/dim cyan]", style="dim white"))
    cfg_builder = CFGBuilder()
    try:
        cfg = cfg_builder.build(tree)
        con.print(f"  [green]✓[/green] CFG built — {len(cfg.nodes)} nodes")
    except Exception as exc:
        con.print(f"  [bold red]✗ CFG error:[/bold red] {exc}")

    dfg = None
    con.print(Rule("[dim cyan]🔗  DFG Build[/dim cyan]", style="dim white"))
    dfg_builder = DFGBuilder()
    try:
        dfg = dfg_builder.build(tree)
        con.print(f"  [green]✓[/green] DFG built — {len(dfg.nodes)} nodes, {len(dfg.edges)} edges")
    except Exception as exc:
        con.print(f"  [bold red]✗ DFG error:[/bold red] {exc}")

    symbol_table = SymbolTable()
    taint_engine = TaintPropagationEngine()
    result = None
    elapsed_ms = 0.0

    con.print(Rule("[dim cyan]🔍  Taint Analysis[/dim cyan]", style="dim white"))
    try:
        if dfg:
            result = taint_engine.analyze(tree, dfg, symbol_table)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if result.sources:
                con.print(f"  [yellow]⚠[/yellow] Taint sources:")
                for rec in result.sources:
                    con.print(f"    • {rec.variable} @ line {rec.line} (source: {rec.source})")
            elif result.propagations:
                con.print(f"  [yellow]↪[/yellow] Propagations: {len(result.propagations)}")
            else:
                con.print(f"  [green]✓[/green] No taint detected")
        else:
            con.print(f"  [dim]Skipped (no DFG)[/dim]")
    except Exception as exc:
        con.print(f"  [bold red]✗ Taint error:[/bold red] {exc}")

    if result and cfg and dfg:
        con.print(Rule("[dim cyan]📊  Report Generation[/dim cyan]", style="dim white"))
        report = generate_report(
            filepath=sample_path,
            source=source,
            result=result,
            cfg=cfg,
            dfg=dfg,
            st=symbol_table,
            elapsed_ms=elapsed_ms,
            output_dir=REPORTS_DIR,
            con=con,
        )
    else:
        con.print(f"  [dim]Skipped (incomplete analysis)[/dim]")

    outputs = []

    try:
        png = ast_viz.render(tree, filename=slug, caption=caption)
        outputs.append(("AST", os.path.relpath(png, BASE_DIR)))
    except Exception as exc:
        con.print(f"  [red]✗ AST PNG: {exc}[/red]")

    try:
        if cfg:
            png = cfg_viz.render(cfg, filename=slug, caption=caption)
            outputs.append(("CFG", os.path.relpath(png, BASE_DIR)))
    except Exception as exc:
        con.print(f"  [red]✗ CFG PNG: {exc}[/red]")

    try:
        if dfg:
            png = dfg_viz.render(dfg, filename=slug, caption=caption)
            outputs.append(("DFG", os.path.relpath(png, BASE_DIR)))
    except Exception as exc:
        con.print(f"  [red]✗ DFG PNG: {exc}[/red]")

    for label, path in outputs:
        con.print(f"  [green]✓[/green] {label} → [cyan]{path}[/cyan]")

    return bool(outputs)


def main():
    con.print()
    con.print(
        Panel(
            "[bold cyan]SECURITY LINTER — PHASE 1+2[/bold cyan]\n"
            "[dim white]CFG + DFG + Taint + Visualization + Reports[/dim white]\n\n"
            f"[dim white]samples/ → output/ast/ | cfg/ | dfg/ | reports/[/dim white]",
            border_style="cyan",
            expand=False,
            padding=(1, 4),
        )
    )

    os.makedirs(CFG_DIR, exist_ok=True)
    os.makedirs(DFG_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if not os.path.isdir(SAMPLES_DIR):
        con.print(f"[bold red]✗ samples/ not found[/bold red]")
        sys.exit(1)

    ast_viz = ASTVisualizer(output_dir=AST_DIR, dpi=200, rankdir="TB")
    cfg_viz = CFGVisualizer(output_dir=CFG_DIR, dpi=200, rankdir="TB")
    dfg_viz = DFGVisualizer(output_dir=DFG_DIR, dpi=200, rankdir="LR")
    consumer = ASTConsumer()

    results = []
    for filename, caption in CASE_META.items():
        path = os.path.join(SAMPLES_DIR, filename)
        if not os.path.isfile(path):
            con.print(f"  [yellow]⚠ Skipping: {filename}[/yellow]")
            results.append((caption, False))
            continue
        ok = run_case(path, caption, ast_viz, cfg_viz, dfg_viz, consumer)
        results.append((caption, ok))

    con.print()
    con.print(Rule("[bold white]Summary[/bold white]", style="dim white"))
    ok_count = sum(1 for _, ok in results if ok)
    for caption, ok in results:
        icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
        label = caption.split(". ", 1)[-1]
        con.print(f"  {icon}  {label}")

    con.print()
    con.print(f"  [bold]{ok_count}/{len(results)}[/bold] cases")
    con.print(f"  AST     → [cyan]{os.path.relpath(AST_DIR, BASE_DIR)}/[/cyan]")
    con.print(f"  CFG     → [cyan]{os.path.relpath(CFG_DIR, BASE_DIR)}/[/cyan]")
    con.print(f"  DFG     → [cyan]{os.path.relpath(DFG_DIR, BASE_DIR)}/[/cyan]")
    con.print(f"  JSON    → [cyan]{os.path.relpath(REPORTS_DIR, BASE_DIR)}/[/cyan]")
    con.print()

    con.print(Rule("[bold white]PDF Report Generation[/bold white]", style="dim white"))
    pdf_count = generate_all_pdfs(console=con)
    con.print(f"  [green]✓[/green] Generated {pdf_count} PDF reports")
    con.print(f"  PDF     → [cyan]{os.path.relpath(os.path.join(BASE_DIR, 'output', 'pdf'), BASE_DIR)}/[/cyan]")
    con.print()

    # ── §8 Accuracy Metrics ───────────────────────────────────────────────────
    gt_path = os.path.join(SAMPLES_DIR, "ground_truth.json")
    if os.path.isfile(gt_path):
        con.print(Rule("[bold white]§8  Accuracy Metrics[/bold white]", style="dim white"))
        con.print()
        aggregate = run_all_cases()
        if aggregate.case_results:
            render_terminal_report(aggregate)
            render_json_report(aggregate)

            # Generate standalone metrics PDF
            generate_metrics_pdf(console=con)

            con.print()
            if aggregate.false_positives == 0 and aggregate.false_negatives == 0:
                con.print("  [green]✓ All cases passed — no false positives or false negatives.[/green]\n")
            else:
                con.print(
                    f"  [bold red]✗ {aggregate.false_positives} FP, "
                    f"{aggregate.false_negatives} FN detected.[/bold red]\n"
                )
        else:
            con.print("  [dim]No cases analyzed for metrics.[/dim]\n")
    else:
        con.print("  [dim]Skipping metrics (ground_truth.json not found).[/dim]\n")

    con.print("  [dim]Phase 2 complete with all reports.[/dim]")
    con.print()

    sys.exit(0 if ok_count == len(results) else 1)


if __name__ == "__main__":
    main()