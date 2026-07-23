"""
run_benchmark.py — Benchmark comparison: Linter vs Bandit vs Semgrep
"""
import json
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
GT_PATH = os.path.join(SAMPLES_DIR, "ground_truth.json")
LINTER_OUT = os.path.join(BASE_DIR, "output", "metrics.json")


SEMGREP_RULE = """
rules:
  - id: sqli-param-taint
    mode: taint
    pattern-sources:
      - pattern: |
          def $F(...):
            ...
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: cursor.execute(...)
              - pattern: db.execute(...)
              - pattern: connection.execute(...)
              - pattern: conn.execute(...)
              - pattern: cur.execute(...)
    message: "SQLi via function parameter"
    languages: [python]
    severity: ERROR
"""


def load_ground_truth():
    with open(GT_PATH) as f:
        return json.load(f)


def run_linter():
    subprocess.run(
        [sys.executable, "test_metrics.py"],
        cwd=BASE_DIR,
        capture_output=True,
        timeout=120,
    )
    if os.path.exists(LINTER_OUT):
        with open(LINTER_OUT) as f:
            return json.load(f)
    return None


def run_bandit():
    out = "/tmp/bandit_results.json"
    subprocess.run(
        ["/tmp/venv/bin/bandit", "-r", SAMPLES_DIR, "-f", "json", "-o", out],
        capture_output=True, timeout=120,
    )
    if os.path.exists(out):
        with open(out) as f:
            data = json.load(f)
        findings = {}
        for r in data.get("results", []):
            fname = os.path.basename(r["filename"])
            findings.setdefault(fname, []).append(r)
        return findings
    return {}


def run_semgrep():
    rule_path = "/tmp/semgrep_bench_rule.yaml"
    out = "/tmp/semgrep_results.json"
    with open(rule_path, "w") as f:
        f.write(SEMGREP_RULE)
    subprocess.run(
        ["/tmp/venv/bin/semgrep", "--config", rule_path, SAMPLES_DIR,
         "--json", "-o", out],
        capture_output=True, timeout=120,
    )
    if os.path.exists(out):
        with open(out) as f:
            data = json.load(f)
        findings = {}
        for r in data.get("results", []):
            fname = os.path.basename(r["path"])
            findings.setdefault(fname, []).append(r)
        return findings
    return {}


def evaluate_tool(gt, findings_by_file, tool_name):
    tp = tn = fp = fn = 0
    for fname, gt_entry in sorted(gt.items()):
        exp_verdict = gt_entry["expected_verdict"]
        has_finding = len(findings_by_file.get(fname, [])) > 0
        if exp_verdict == "VULNERABLE":
            if has_finding:
                tp += 1
            else:
                fn += 1
        elif exp_verdict == "SAFE":
            if has_finding:
                fp += 1
            else:
                tn += 1
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return {"tool": tool_name, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1}


def evaluate_linter(gt, metrics_json):
    if not metrics_json:
        return None
    cases = metrics_json.get("cases", [])
    agg = metrics_json.get("aggregate_metrics", {})
    tp = sum(1 for c in cases if c.get("classification") == "TP")
    tn = sum(1 for c in cases if c.get("classification") == "TN")
    fp = sum(1 for c in cases if c.get("classification") == "FP")
    fn = sum(1 for c in cases if c.get("classification") == "FN")
    return {"tool": "Linter", "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": agg.get("precision", 0),
            "recall": agg.get("recall", 0),
            "f1": agg.get("f1_score", 0)}


def print_table(results):
    print()
    print("=" * 85)
    print(f"{'Tool':<25} {'TP':>5} {'TN':>5} {'FP':>5} {'FN':>5}  "
          f"{'Precision':>8} {'Recall':>8} {'F1':>8}")
    print("-" * 85)
    for r in results:
        if r is None:
            continue
        print(f"{r['tool']:<25} {r['tp']:>5} {r['tn']:>5} {r['fp']:>5} {r['fn']:>5}  "
              f"{r['precision']:>8.1%} {r['recall']:>8.1%} {r['f1']:>8.1%}")
    print("=" * 85)
    print()


def main():
    gt = load_ground_truth()
    print(f"Ground truth: {len(gt)} entries "
          f"({sum(1 for v in gt.values() if v.get('expected_verdict')=='VULNERABLE')} VULN, "
          f"{sum(1 for v in gt.values() if v.get('expected_verdict')=='SAFE')} SAFE)")

    print("\n[1/3] Running linter...")
    linter_result = evaluate_linter(gt, run_linter())
    print(f"  TP={linter_result['tp']} TN={linter_result['tn']} "
          f"FP={linter_result['fp']} FN={linter_result['fn']}")

    print("\n[2/3] Running Bandit...")
    bandit_f = run_bandit()
    print(f"  {sum(len(v) for v in bandit_f.values())} findings in {len(bandit_f)} files")
    bandit_result = evaluate_tool(gt, bandit_f, "Bandit")
    print(f"  TP={bandit_result['tp']} TN={bandit_result['tn']} "
          f"FP={bandit_result['fp']} FN={bandit_result['fn']}")

    print("\n[3/3] Running Semgrep (taint mode)...")
    semgrep_f = run_semgrep()
    print(f"  {sum(len(v) for v in semgrep_f.values())} findings in {len(semgrep_f)} files")
    semgrep_result = evaluate_tool(gt, semgrep_f, "Semgrep (taint)")
    print(f"  TP={semgrep_result['tp']} TN={semgrep_result['tn']} "
          f"FP={semgrep_result['fp']} FN={semgrep_result['fn']}")

    print_table([linter_result, bandit_result, semgrep_result])

    # Save to JSON
    out = [linter_result, bandit_result, semgrep_result]
    with open(os.path.join(BASE_DIR, "output", "benchmark_results.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("Results saved to output/benchmark_results.json")


if __name__ == "__main__":
    main()
