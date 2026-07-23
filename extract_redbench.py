"""Extract ALL RedBench SQLi samples as standalone .py files + update ground truth."""
import json
import os
import sys

sys.path.insert(0, "/tmp/redbench")
from redbench.loader import BenchmarkLoader

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
GT_PATH = os.path.join(SAMPLES_DIR, "ground_truth.json")

sources_to_try = ["samples.jsonl", "samples_real.jsonl", "samples_generated_v2.jsonl"]

seen_ids = set()
all_sqli = []
for sf in sources_to_try:
    loader = BenchmarkLoader(source_files=[sf])
    try:
        samples = loader.load_class("sqli", validate=False)
        for s in samples:
            if s.id not in seen_ids:
                seen_ids.add(s.id)
                all_sqli.append(s)
        print(f"  {sf}: {len(samples)} samples ({len([s for s in samples if s.id not in seen_ids])} new)")
    except FileNotFoundError:
        print(f"  {sf}: not found")

print(f"\nTotal unique sqli samples: {len(all_sqli)}")

with open(GT_PATH) as f:
    gt = json.load(f)

written = 0
for s in all_sqli:
    safe_id = s.id.replace("-", "_")

    vuln_name = f"rb_{safe_id}_vuln.py"
    vuln_path = os.path.join(SAMPLES_DIR, vuln_name)
    with open(vuln_path, "w") as f:
        f.write(s.code)
    lines = len(s.code.splitlines())
    print(f"  Wrote {vuln_name} ({lines} lines)")

    desc = s.description

    gt[vuln_name] = {
        "description": desc[:80],
        "expected_verdict": "VULNERABLE",
        "expected_vulns": 1,
        "expected_vulnerabilities": [
            {
                "sink": "execute",
                "line": 0,
                "source_type": "PARAM",
                "source_var": "parameter",
                "notes": desc[:120],
            }
        ],
        "notes": f"RedBench {s.id}: {desc[:150]}",
    }
    written += 1

    fix_code = s.fix.strip() if s.fix else ""
    if fix_code and len(fix_code.splitlines()) > 1:
        safe_name = f"rb_{safe_id}_safe.py"
        safe_path = os.path.join(SAMPLES_DIR, safe_name)
        with open(safe_path, "w") as f:
            f.write(fix_code)
        print(f"  Wrote {safe_name} ({len(fix_code.splitlines())} lines)")

        gt[safe_name] = {
            "description": f"FIX: {desc[:60]}",
            "expected_verdict": "SAFE",
            "expected_vulns": 0,
            "expected_vulnerabilities": [],
            "notes": f"RedBench {s.id} fix: parameterized query or input validation",
        }
        written += 1

with open(GT_PATH, "w") as f:
    json.dump(gt, f, indent=2, ensure_ascii=False)

print(f"\nTotal written: {written} files")
print(f"Ground truth now has {len(gt)} entries")
