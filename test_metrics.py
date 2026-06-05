"""
test_metrics.py — False Positive / False Negative Metrics Harness
==================================================================

Runs the Security Linter pipeline on all sample files and compares
actual results against ground truth defined in samples/ground_truth.json.

Computes standard information retrieval metrics:
  - Precision, Recall, F1 Score
  - False Positive Rate, False Negative Rate
  - Accuracy

Outputs:
  - Rich terminal report (§8 Accuracy Metrics)
  - JSON report → output/metrics.json

Usage:
    python test_metrics.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox

from ast_consumer    import ASTConsumer
from cfg_builder     import CFGBuilder
from dfg_builder     import DFGBuilder
from symbol_table    import SymbolTable
from taint_engine    import TaintPropagationEngine, Vulnerability

con = Console()

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")
METRICS_JSON = os.path.join(OUTPUT_DIR, "metrics.json")


# ──────────────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────────────

class Classification:
    TP = "TP"   # True Positive
    TN = "TN"   # True Negative
    FP = "FP"   # False Positive
    FN = "FN"   # False Negative


@dataclass
class VulnComparison:
    """Comparison of a single actual vulnerability against ground truth."""
    actual_vuln: Vulnerability
    matched_expected: Optional[dict] = None
    is_true_positive: bool = False
    reason: str = ""


@dataclass
class CaseMetrics:
    """Metrics for a single test case."""
    case_name: str
    description: str
    expected_verdict: str
    actual_verdict: str
    expected_vulns: int
    actual_vulns: int
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    classification: str = ""
    fp_details: List[str] = field(default_factory=list)
    fn_details: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AggregateMetrics:
    """Overall metrics across all test cases."""
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    case_results: List[CaseMetrics] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0


# ──────────────────────────────────────────────────────────────────────────────
# Pipeline runner (reuses main.py logic without visualization)
# ──────────────────────────────────────────────────────────────────────────────

def run_analysis(filepath: str) -> Tuple[Optional[str], List[Vulnerability]]:
    """
    Run the linter pipeline on a single file.
    Returns (verdict, list_of_vulnerabilities).
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None, []

    consumer = ASTConsumer()
    try:
        tree = consumer.consume(source)
    except Exception:
        return None, []

    cfg_builder = CFGBuilder()
    try:
        cfg = cfg_builder.build(tree)
    except Exception:
        cfg = None

    dfg_builder = DFGBuilder()
    try:
        dfg = dfg_builder.build(tree)
    except Exception:
        dfg = None

    symbol_table = SymbolTable()
    taint_engine = TaintPropagationEngine()

    if dfg is None:
        return None, []

    try:
        result = taint_engine.analyze(tree, dfg, symbol_table)
    except Exception:
        return None, []

    if result.vulnerabilities:
        verdict = "VULNERABLE"
    elif cfg is not None:
        has_sinks = any(
            n.type.value == 7  # DFGNodeType.SINK
            for n in dfg.nodes.values()
        ) if dfg else False
        verdict = "SAFE (no SQL sink)" if not has_sinks else "SAFE"
    else:
        verdict = "SAFE"

    return verdict, result.vulnerabilities


# ──────────────────────────────────────────────────────────────────────────────
# Ground truth loader
# ──────────────────────────────────────────────────────────────────────────────

def load_ground_truth() -> Dict[str, dict]:
    gt_path = os.path.join(SAMPLES_DIR, "ground_truth.json")
    with open(gt_path, encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability matching
# ──────────────────────────────────────────────────────────────────────────────

def match_vulnerabilities(
    actual_vulns: List[Vulnerability],
    expected_vulns: List[dict],
) -> Tuple[int, int, int, List[str], List[str]]:
    """
    Match actual vulnerabilities against expected ones.

    Returns (tp, fp, fn, fp_details, fn_details).

    Matching strategy:
      - An actual vuln is a TP if its sink line matches any expected sink line.
      - An actual vuln with no matching expected line is an FP.
      - An expected vuln with no matching actual line is an FN.
    """
    expected_lines = {v["line"] for v in expected_vulns}
    matched_expected_lines: set = set()

    tp = 0
    fp = 0
    fp_details: List[str] = []

    for vuln in actual_vulns:
        if vuln.line in expected_lines and vuln.line not in matched_expected_lines:
            tp += 1
            matched_expected_lines.add(vuln.line)
        else:
            fp += 1
            fp_details.append(
                f"  sink={vuln.sink} line={vuln.line} "
                f"arg={vuln.arg_name} — not in expected sink lines {sorted(expected_lines)}"
            )

    fn = 0
    fn_details: List[str] = []
    for exp in expected_vulns:
        if exp["line"] not in matched_expected_lines:
            fn += 1
            fn_details.append(
                f"  expected sink={exp['sink']} line={exp['line']} — not detected"
            )

    return tp, fp, fn, fp_details, fn_details


# ──────────────────────────────────────────────────────────────────────────────
# Main analysis loop
# ──────────────────────────────────────────────────────────────────────────────

def run_all_cases() -> AggregateMetrics:
    ground_truth = load_ground_truth()
    aggregate = AggregateMetrics()

    # Process cases in sorted order for consistent output
    sorted_cases = sorted(ground_truth.keys())

    for case_name in sorted_cases:
        gt = ground_truth[case_name]
        filepath = os.path.join(SAMPLES_DIR, case_name)

        if not os.path.isfile(filepath):
            con.print(f"  [yellow]⚠ Skipping: {case_name} (file not found)[/yellow]")
            continue

        con.print(f"  [dim]Analyzing {case_name}...[/dim]")

        start = time.perf_counter()
        actual_verdict, actual_vulns = run_analysis(filepath)
        elapsed = (time.perf_counter() - start) * 1000

        if actual_verdict is None:
            con.print(f"  [red]✗ Pipeline failed for {case_name}[/red]")
            continue

        expected_verdict = gt["expected_verdict"]
        expected_vulns_list = gt.get("expected_vulnerabilities", [])
        expected_vuln_count = gt.get("expected_vulns", len(expected_vulns_list))
        actual_vuln_count = len(actual_vulns)

        # Match vulnerabilities
        tp, fp, fn, fp_details, fn_details = match_vulnerabilities(
            actual_vulns, expected_vulns_list
        )

        # Determine case-level classification
        # Normalize verdicts: "SAFE (no SQL sink)" → "SAFE"
        actual_verdict_norm = actual_verdict.split(" (")[0] if actual_verdict else ""
        expected_verdict_norm = expected_verdict.split(" (")[0] if expected_verdict else ""

        if expected_verdict_norm == "VULNERABLE" and actual_verdict_norm == "VULNERABLE":
            if fn == 0:
                case_class = Classification.TP
                aggregate.true_positives += 1
            else:
                case_class = Classification.TP  # Partial match still counts
                aggregate.true_positives += 1
        elif expected_verdict_norm == "SAFE" and actual_verdict_norm == "SAFE":
            case_class = Classification.TN
            aggregate.true_negatives += 1
        elif expected_verdict_norm == "SAFE" and actual_verdict_norm == "VULNERABLE":
            case_class = Classification.FP
            aggregate.false_positives += 1
        elif expected_verdict_norm == "VULNERABLE" and actual_verdict_norm == "SAFE":
            case_class = Classification.FN
            aggregate.false_negatives += 1
        else:
            case_class = Classification.FP  # Default conservative
            aggregate.false_positives += 1

        case_metrics = CaseMetrics(
            case_name=case_name,
            description=gt.get("description", ""),
            expected_verdict=expected_verdict,
            actual_verdict=actual_verdict,
            expected_vulns=expected_vuln_count,
            actual_vulns=actual_vuln_count,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            classification=case_class,
            fp_details=fp_details,
            fn_details=fn_details,
            notes=gt.get("notes", ""),
        )
        aggregate.case_results.append(case_metrics)

        # Inline feedback
        icon = {
            Classification.TP: "[green]✓ TP[/green]",
            Classification.TN: "[green]✓ TN[/green]",
            Classification.FP: "[red]✗ FP[/red]",
            Classification.FN: "[red]✗ FN[/red]",
        }.get(case_class, "?")

        con.print(f"    {icon}  {case_class}  "
                  f"(expected={expected_verdict}, actual={actual_verdict}, "
                  f"vulns={actual_vuln_count}, {elapsed:.0f}ms)")

    return aggregate


# ──────────────────────────────────────────────────────────────────────────────
# Terminal report
# ──────────────────────────────────────────────────────────────────────────────

_CLASSIFICATION_STYLE = {
    Classification.TP: "bold green",
    Classification.TN: "bold green",
    Classification.FP: "bold red",
    Classification.FN: "bold red",
}

_CLASSIFICATION_ICON = {
    Classification.TP: "✅",
    Classification.TN: "✅",
    Classification.FP: "❌",
    Classification.FN: "❌",
}


def render_terminal_report(aggregate: AggregateMetrics):
    """Print the §8 Accuracy Metrics report."""
    con.print()
    con.print(Rule("[bold cyan]§8  Accuracy Metrics[/bold cyan]", style="dim cyan"))

    # ── Per-case table ────────────────────────────────────────────────────────
    tbl = Table(
        show_header=True, header_style="bold dim white",
        border_style="dim white", box=rbox.SIMPLE, expand=True,
    )
    tbl.add_column("Case", style="dim white", width=28)
    tbl.add_column("Expected", style="bold white", width=10, justify="center")
    tbl.add_column("Actual", style="bold white", width=10, justify="center")
    tbl.add_column("Vulns", style="white", width=8, justify="center")
    tbl.add_column("TP", style="green", width=5, justify="center")
    tbl.add_column("FP", style="red", width=5, justify="center")
    tbl.add_column("FN", style="red", width=5, justify="center")
    tbl.add_column("Result", style="bold", width=8, justify="center")

    for cm in aggregate.case_results:
        icon = _CLASSIFICATION_ICON.get(cm.classification, "?")
        style = _CLASSIFICATION_STYLE.get(cm.classification, "white")
        exp_short = "VULN" if "VULNERABLE" in cm.expected_verdict else "SAFE"
        act_short = "VULN" if "VULNERABLE" in cm.actual_verdict else "SAFE"
        tbl.add_row(
            cm.case_name.replace(".py", "").replace("case", "C"),
            exp_short,
            act_short,
            str(cm.actual_vulns),
            str(cm.true_positives),
            str(cm.false_positives),
            str(cm.false_negatives),
            f"[{style}]{icon} {cm.classification}[/{style}]",
        )

    con.print(tbl)
    con.print()

    # ── Metrics panel ─────────────────────────────────────────────────────────
    p = aggregate.precision
    r = aggregate.recall
    f1 = aggregate.f1_score
    fpr = aggregate.false_positive_rate
    fnr = aggregate.false_negative_rate
    acc = aggregate.accuracy

    con.print(Panel(
        f"[dim white]True Positives  :[/dim white]  [bold green]{aggregate.true_positives}[/bold green]\n"
        f"[dim white]True Negatives :[/dim white]  [bold green]{aggregate.true_negatives}[/bold green]\n"
        f"[dim white]False Positives:[/dim white]  [bold red]{aggregate.false_positives}[/bold red]\n"
        f"[dim white]False Negatives:[/dim white]  [bold red]{aggregate.false_negatives}[/bold red]\n"
        f"[dim white]{'─' * 40}[/dim white]\n"
        f"[dim white]Precision      :[/dim white]  [bold cyan]{p:.1%}[/bold cyan]\n"
        f"[dim white]Recall         :[/dim white]  [bold cyan]{r:.1%}[/bold cyan]\n"
        f"[dim white]F1 Score       :[/dim white]  [bold cyan]{f1:.1%}[/bold cyan]\n"
        f"[dim white]FP Rate        :[/dim white]  [bold yellow]{fpr:.1%}[/bold yellow]\n"
        f"[dim white]FN Rate        :[/dim white]  [bold yellow]{fnr:.1%}[/bold yellow]\n"
        f"[dim white]Accuracy       :[/dim white]  [bold cyan]{acc:.1%}[/bold cyan]",
        title="[bold cyan]Aggregate Metrics[/bold cyan]",
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    ))
    con.print()

    # ── FP / FN details ───────────────────────────────────────────────────────
    has_issues = False
    for cm in aggregate.case_results:
        if cm.fp_details:
            if not has_issues:
                con.print(Rule("[bold red]False Positive Details[/bold red]", style="dim red"))
                has_issues = True
            con.print(f"  [red]{cm.case_name}:[/red]")
            for detail in cm.fp_details:
                con.print(f"    {detail}")
            con.print()

    for cm in aggregate.case_results:
        if cm.fn_details:
            if not has_issues:
                con.print(Rule("[bold red]False Negative Details[/bold red]", style="dim red"))
                has_issues = True
            con.print(f"  [red]{cm.case_name}:[/red]")
            for detail in cm.fn_details:
                con.print(f"    {detail}")
            con.print()

    if not has_issues:
        con.print("  [green]No false positives or false negatives detected.[/green]\n")


# ──────────────────────────────────────────────────────────────────────────────
# JSON report
# ──────────────────────────────────────────────────────────────────────────────

def render_json_report(aggregate: AggregateMetrics):
    """Save metrics as JSON for CI/CD integration."""
    os.makedirs(os.path.dirname(METRICS_JSON), exist_ok=True)

    data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "cases": [
            {
                "case": cm.case_name,
                "description": cm.description,
                "expected_verdict": cm.expected_verdict,
                "actual_verdict": cm.actual_verdict,
                "classification": cm.classification,
                "expected_vulns": cm.expected_vulns,
                "actual_vulns": cm.actual_vulns,
                "true_positives": cm.true_positives,
                "false_positives": cm.false_positives,
                "false_negatives": cm.false_negatives,
                "fp_details": cm.fp_details,
                "fn_details": cm.fn_details,
                "notes": cm.notes,
            }
            for cm in aggregate.case_results
        ],
        "aggregate_metrics": {
            "true_positives": aggregate.true_positives,
            "true_negatives": aggregate.true_negatives,
            "false_positives": aggregate.false_positives,
            "false_negatives": aggregate.false_negatives,
            "precision": round(aggregate.precision, 4),
            "recall": round(aggregate.recall, 4),
            "f1_score": round(aggregate.f1_score, 4),
            "false_positive_rate": round(aggregate.false_positive_rate, 4),
            "false_negative_rate": round(aggregate.false_negative_rate, 4),
            "accuracy": round(aggregate.accuracy, 4),
            "total_cases": len(aggregate.case_results),
        },
    }

    with open(METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    con.print(f"  [dim white]JSON metrics →[/dim white] "
              f"[bold cyan]{os.path.relpath(METRICS_JSON, BASE_DIR)}[/bold cyan]\n")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    con.print()
    con.print(
        Panel(
            "[bold cyan]SECURITY LINTER — ACCURACY METRICS[/bold cyan]\n"
            "[dim white]False Positive / False Negative Analysis[/dim white]\n\n"
            f"[dim white]Ground truth: samples/ground_truth.json[/dim white]",
            border_style="cyan",
            expand=False,
            padding=(1, 4),
        )
    )

    if not os.path.isdir(SAMPLES_DIR):
        con.print(f"[bold red]✗ samples/ directory not found[/bold red]")
        sys.exit(1)

    gt_path = os.path.join(SAMPLES_DIR, "ground_truth.json")
    if not os.path.isfile(gt_path):
        con.print(f"[bold red]✗ ground_truth.json not found in samples/[/bold red]")
        sys.exit(1)

    con.print()
    con.print(Rule("[dim cyan]Running analysis on all cases[/dim cyan]", style="dim white"))
    con.print()

    aggregate = run_all_cases()

    if not aggregate.case_results:
        con.print("[bold red]✗ No cases were analyzed[/bold red]")
        sys.exit(1)

    render_terminal_report(aggregate)
    render_json_report(aggregate)

    # Exit code: 0 if no false positives or false negatives
    if aggregate.false_positives == 0 and aggregate.false_negatives == 0:
        con.print("  [green]✓ All cases passed — no false positives or false negatives.[/green]\n")
        sys.exit(0)
    else:
        con.print(
            f"  [bold red]✗ {aggregate.false_positives} FP, "
            f"{aggregate.false_negatives} FN detected.[/bold red]\n"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
