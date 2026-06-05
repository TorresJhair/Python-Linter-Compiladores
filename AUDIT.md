# Security Linter — Project Audit Report

**Date:** 2026-05-04
**Scope:** Full codebase review of `/home/alexowo/UNSA/Compiladores/Proyecto`
**Files analyzed:** 11 source modules, 11 sample files, requirements.txt, Dockerfile, docker-compose.yml

---

## Project Overview

This is a **static analysis tool for detecting SQL Injection vulnerabilities** in Python code. It uses Python's built-in `ast` module as the compiler host (no custom lexer/parser), builds Control Flow Graphs (CFG) and Data Flow Graphs (DFG), and runs a taint propagation engine to find user-controlled data flowing into SQL sinks.

### Architecture

```
samples/   →   AST Consumer   →   CFG Builder   →   DFG Builder   →   Taint Engine   →   Reports
(.py files)    (ast_consumer)    (cfg_builder)     (dfg_builder)     (taint_engine)      JSON + PDF
                                                                                        + PNG graphs
```

| Module | Role |
|--------|------|
| `ast_consumer.py` | Translates Python's standard AST → custom AST (`ast_nodes.py`) |
| `ast_nodes.py` | Custom AST node classes targeting SQLi patterns |
| `cfg_builder.py` | Builds Control Flow Graph — all execution paths |
| `dfg_builder.py` | Builds Data Flow Graph — value propagation between variables |
| `symbol_table.py` | Tracks variable state: safe, tainted, sanitized, param |
| `taint_engine.py` | Core engine — sources → BFS propagation → sink detection |
| `report_generator.py` | 7-section terminal + JSON reports with remediation |
| `pdf_report_generator.py` | PDF report generation from JSON reports |

---

## Critical Issues (bugs that produce wrong results)

### 1. `for` loop body parsed as expressions
- **File:** `ast_consumer.py:94`
- **Bug:** `_convert_expr(s)` is called instead of `_convert_stmt(s)`
- **Impact:** Any `for` loop containing assignments, `if`, or function calls produces a corrupted AST. All sample files happen to avoid this path, but real code would break silently.

### 2. `elif` branches silently dropped
- **File:** `ast_consumer.py:71-84`
- **Bug:** Python represents `elif` as nested `If` in `orelse`. The code ignores this pattern.
- **Impact:** `elif` chains lose their control flow entirely — the else body gets the wrong content and elif conditions are never analyzed.

### 3. `return` connects to module EXIT
- **File:** `cfg_builder.py:208`
- **Bug:** A `return` inside a function connects to the module-level `EXIT` node instead of the function's own exit.
- **Impact:** The CFG shows the program terminating when a function returns. Path analysis across function boundaries is wrong.

### 4. Function taint state lost
- **File:** `taint_engine.py:339-368`
- **Bug:** Taint is tracked in a child `SymbolTable` that gets discarded after analyzing the function body.
- **Impact:** Sinks inside functions may not see tainted parameters → **false negatives** for interprocedural SQLi.

### 5. Duplicate `_convert_BinOp` method
- **File:** `ast_consumer.py:157 & 208`
- **Bug:** The first definition (lines 157-161) is completely shadowed by the second (lines 208-214).
- **Impact:** Dead code that signals confusion. If someone edits the first one thinking it's active, they introduce a bug.

---

## High Priority (design flaws, missing infrastructure)

### 6. Zero test coverage
- **Impact:** No way to verify detection accuracy or prevent regressions. For a security analysis tool, this is a major risk.
- **Recommendation:** Add `pytest` with test cases for each vulnerability pattern and safe pattern.

### 7. No `.gitignore`
- **Impact:** `__pycache__/`, `venv/`, and `output/` (generated PNGs, PDFs, JSON) are tracked in git → repo bloat and merge conflicts.

### 8. No README
- **Impact:** No documentation on how to install, run, add new samples, or interpret results.

### 9. `_severity()` always returns WARNING for code with conditionals
- **File:** `report_generator.py:209-215`
- **Bug:** If the CFG has *any* condition node, all vulnerabilities are marked WARNING instead of CRITICAL.
- **Impact:** Wrong severity classification. A file with `if True: pass` followed by an unconditional SQLi gets WARNING instead of CRITICAL.

### 10. `_PYTHON_BUILTINS` recreated on every BFS iteration
- **File:** `taint_engine.py:424`
- **Bug:** A 40-element set is recreated on every BFS iteration (~100+ times per file).
- **Impact:** Pure waste. Should be a module-level constant.

---

## Medium Priority (correctness & cleanliness)

### 11. Vulnerability IDs start at 002
- **File:** `report_generator.py:301`
- **Bug:** `enumerate(..., 2)` → first vuln is `CVE-SL-002`.
- **Impact:** Off-by-one error in report IDs.

### 12. Duplicate imports in `pdf_report_generator.py`
- **File:** `pdf_report_generator.py:29 & 36`
- **Bug:** `TA_CENTER`, `TA_LEFT`, `TA_JUSTIFY` imported twice from different modules.
- **Impact:** Confusing and fragile.

### 13. Timing measurement is incomplete
- **File:** `main.py:101, 143`
- **Bug:** `elapsed_ms` only covers taint analysis. CFG build, DFG build, and report generation are excluded.
- **Impact:** The "Analysis time" field in reports is misleading.

### 14. HTML not escaped in PDF
- **File:** `pdf_report_generator.py`
- **Bug:** User-controlled strings (`sink_expr`, `remediation_code`, `step.expression`) are inserted into reportlab Paragraph markup without escaping.
- **Impact:** `<` or `&` in source code breaks PDF generation or produces corrupted output.

### 15. Dead code: `_convert_Num`, `_convert_Str`
- **File:** `ast_consumer.py:147-152`
- **Bug:** These node types were deprecated in Python 3.8 and removed in Python 3.12. Never called.

### 16. Dead code: `update_var`
- **File:** `dfg_builder.py:148-161`
- **Bug:** Method defined but never called anywhere.

### 17. Import label shows empty string
- **File:** `cfg_builder.py:212`
- **Bug:** `import X` labels show `import ` (blank) because `stmt.module` is `""` for plain imports.
- **Impact:** CFG visualization shows incomplete labels.

### 18. Unnecessary dependencies
- **File:** `requirements.txt`
- **Bug:** `ipython`, `astpretty`, `astviz` are not imported anywhere in the project.
- **Impact:** Larger install surface, slower setup.

---

## Low Priority (cosmetic)

| # | Issue | File |
|---|-------|------|
| 19 | Exit code depends on PNG generation, not security verdict | `main.py:262` |
| 20 | `_generic_convert_expr` uses `repr(node)` as name → `<ast.Constant object at 0x...>` | `ast_consumer.py:133` |
| 21 | `define_function` silently overwrites existing functions | `symbol_table.py:197` |
| 22 | Safe sink detection is heuristic (regex on source lines) | `report_generator.py:342` |
| 23 | `_mark_dfg_node_tainted` not consistently called | `taint_engine.py:736` |
| 24 | `docker-compose.yml` uses deprecated `version` key | `docker-compose.yml:1` |
| 25 | No CI/CD configuration, no linting, no pre-commit hooks | Entire project |
| 26 | Many public methods lack return type annotations | Multiple files |
| 27 | `_convert_param` ignores default values | `ast_consumer.py:120` |
| 28 | `pdf_report_generator.py` type hints say `str` but default is `None` | `pdf_report_generator.py:577` |

---

## Summary

| Priority | Count | Action |
|----------|-------|--------|
| Critical | 5 | Fix immediately — incorrect behavior |
| High | 5 | Fix soon — design flaws, missing infrastructure |
| Medium | 8 | Fix when convenient — correctness & cleanliness |
| Low | 12 | Nice to have — cosmetic, maintainability |

**Total issues found: 30**
