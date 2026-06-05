# Security Linter — Documentation

## Overview

This project is a **static analysis tool** that detects **SQL Injection (SQLi) vulnerabilities** in Python source code. It implements a multi-phase compiler pipeline that consumes Python code, builds semantic graphs, and propagates taint from user-controlled inputs to dangerous SQL sinks.

Unlike a traditional compiler, this project does **not** reimplement a lexer or parser. Instead, it uses Python's built-in `ast` module as the compiler host (Phase 1 requirement) and focuses on semantic analysis, graph construction, and security auditing (Phase 2).

---

## Pipeline

```
samples/*.py
    │
    ▼
┌─────────────┐     ┌────────────┐     ┌────────────┐     ┌──────────────┐
│ AST Consumer│ ──▶ │ CFG Builder│ ──▶ │ DFG Builder│ ──▶ │ Taint Engine │
│ (Phase 1)   │     │ (Phase 2a) │     │ (Phase 2b) │     │ (Phase 2c)   │
└─────────────┘     └────────────┘     └────────────┘     └──────────────┘
    │                   │                   │                    │
    ▼                   ▼                   ▼                    ▼
┌─────────────┐     ┌────────────┐     ┌────────────┐     ┌──────────────┐
│ AST Visual. │     │ CFG Visual.│     │ DFG Visual.│     │ Report Gen.  │
│ (PNG)       │     │ (PNG)      │     │ (PNG)      │     │ JSON + PDF   │
└─────────────┘     └────────────┘     └────────────┘     └──────────────┘
```

### Data Flow Between Stages

| Stage | Input | Output | Consumed By |
|-------|-------|--------|-------------|
| AST Consumer | Raw Python source (`str`) | `Module` (custom AST tree) | CFG Builder, DFG Builder, Taint Engine (Phase A), AST Visualizer |
| CFG Builder | `Module` | `CFG` (control flow graph) | Taint Engine (severity classification), Report Generator (§6 stats), CFG Visualizer |
| DFG Builder | `Module` | `DFG` (data flow graph) | Taint Engine (Phase B BFS propagation), Report Generator (§6 stats), DFG Visualizer |
| Symbol Table | — (created fresh) | `SymbolTable` (variable state) | Taint Engine (Phase A + B + C), Report Generator (§4 safe sinks, §5 sanitizations) |
| Taint Engine | `Module` + `DFG` + `SymbolTable` | `TaintPropagationResult` | Report Generator (§2 summary, §3 vuln details) |
| Report Generator | All of the above | `ReportData` + JSON + PDF | Terminal output, CI/CD integration |

---

## Phase 1 — AST (Abstract Syntax Tree)

### What is the AST?

The AST is a tree representation of the syntactic structure of source code. Each node represents a construct in the code (statements, expressions, operators, etc.). It is the **foundation** upon which all subsequent analysis is built.

### How it works internally

The AST Consumer operates in two stages:

#### Stage 1: Python's `ast.parse()`

```python
# ast_consumer.py:42
std_ast = ast.parse(source)
```

This single call internally performs:
1. **Lexical analysis**: The source text is tokenized into a stream of tokens (keywords, operators, literals, identifiers, punctuation). Python's tokenizer handles string literals, numeric literals, indentation-based block structure, and comment stripping.
2. **Syntactic analysis**: The token stream is parsed according to Python's full grammar (defined in `Grammar/python.gram` in CPython). The result is a tree of `ast.AST` subclasses (`ast.Module`, `ast.FunctionDef`, `ast.Assign`, etc.).
3. **Position tracking**: Every node gets `lineno`, `col_offset`, `end_lineno`, and `end_col_offset` attributes for precise source location.

#### Stage 2: ASTConsumer Translation

```python
# ast_consumer.py:45-48
def _convert_module(self, node: ast.Module) -> Module:
    body = [self._convert_stmt(stmt) for stmt in node.body]
    return Module(body=body, line=1, col=1)
```

The `ASTConsumer` class walks the standard Python AST and translates each node into the project's custom node types. This translation uses a **dispatch pattern**:

```python
# ast_consumer.py:50-54
def _convert_stmt(self, node: ast.stmt) -> ASTNode:
    meth = f"_convert_{type(node).__name__}"
    conv = getattr(self, meth, self._generic_convert)
    return conv(node)
```

For each `ast.X` node type, there is a corresponding `_convert_X` method:

| Python AST Node | Custom Node | Method |
|-----------------|-------------|--------|
| `ast.Module` | `Module` | `_convert_module` |
| `ast.Assign` | `AssignStatement` | `_convert_Assign` |
| `ast.AugAssign` | `AugAssignStatement` | `_convert_AugAssign` |
| `ast.Expr` | `ExprStatement` | `_convert_Expr` |
| `ast.If` | `IfStatement` (with `ElifClause`) | `_convert_If` |
| `ast.While` | `WhileStatement` | `_convert_While` |
| `ast.For` | `ForStatement` | `_convert_For` |
| `ast.FunctionDef` | `FunctionDef` (with `Param`) | `_convert_FunctionDef` |
| `ast.Return` | `ReturnStatement` | `_convert_Return` |
| `ast.Import` / `ast.ImportFrom` | `ImportStatement` | `_convert_Import` / `_convert_ImportFrom` |
| `ast.Constant` | `Literal` | `_convert_Constant` |
| `ast.Name` | `Name` | `_convert_Name` |
| `ast.BinOp` | `BinaryOp` or `PercentFormat` | `_convert_BinOp` |
| `ast.UnaryOp` | `UnaryOp` | `_convert_UnaryOp` |
| `ast.BoolOp` | `BoolOp` | `_convert_BoolOp` |
| `ast.Compare` | `Compare` | `_convert_Compare` |
| `ast.Call` | `FCall` (with `Keyword`) | `_convert_Call` |
| `ast.Attribute` | `Attribute` | `_convert_Attribute` |
| `ast.Subscript` | `Subscript` | `_convert_Subscript` |
| `ast.JoinedStr` | `JoinedStr` | `_convert_JoinedStr` |
| `ast.FormattedValue` | `FormattedValue` | `_convert_FormattedValue` |
| `ast.Tuple` | `Tuple` | `_convert_Tuple` |
| `ast.List` | `PyList` | `_convert_List` |

#### Special Handling

**`elif` chain extraction** (`ast_consumer.py:71-99`):
Python represents `elif` as nested `If` nodes inside the `orelse` list. The `_convert_If` method walks this chain:

```python
current_orelse = node.orelse
while len(current_orelse) == 1 and isinstance(current_orelse[0], ast.If):
    elif_node = current_orelse[0]
    elif_clauses.append(ElifClause(...))
    current_orelse = elif_node.orelse
# Remaining orelse is the else body
else_body = [self._convert_stmt(s) for s in current_orelse]
```

**`%` format detection** (`ast_consumer.py:165-171`):
When a `BinOp` has the `Mod` operator (`%`), it is converted to a `PercentFormat` node instead of a generic `BinaryOp`, because this is a common SQLi propagation pattern:

```python
if op == "%":
    return PercentFormat(left=left, right=right, ...)
return BinaryOp(left=left, op=op, right=right, ...)
```

### Custom AST Node Hierarchy

```
ASTNode (base — stores line, col)
│
├── Statements
│   ├── Module              — root of the file (body: List[ASTNode])
│   ├── AssignStatement     — x = expr (targets: List[ASTNode], value: ASTNode)
│   ├── AugAssignStatement  — x += expr (target, op, value)
│   ├── ExprStatement       — standalone expression (e.g., function call)
│   ├── IfStatement         — if/elif/else (condition, then_body, elif_clauses, else_body)
│   ├── WhileStatement      — while loop (condition, body)
│   ├── ForStatement        — for loop (target, iter, body)
│   ├── FunctionDef         — function definition (name, params, body)
│   ├── ReturnStatement     — return value (value: Optional[ASTNode])
│   └── ImportStatement     — import / from X import Y (module, names, is_from)
│
└── Expressions
    ├── Literal             — str, int, float, bool, None (value, kind)
    ├── Name                — variable / identifier (name)
    ├── BinaryOp            — +, -, *, /, etc. (left, op, right)
    ├── UnaryOp             — not, - (op, operand)
    ├── BoolOp              — and/or with N operands (op, values)
    ├── Compare             — chained comparisons (left, ops, comparators)
    ├── FCall               — function call: func(args, kw=val) (func, args, keywords)
    ├── Attribute           — obj.attr (obj, attr)
    ├── Subscript           — obj[key] (obj, key)
    ├── JoinedStr           — f"...{expr}..." (values: List[ASTNode])
    ├── FormattedValue      — the {expr} inside an f-string (value, conversion)
    ├── PercentFormat       — "... %s ..." % val (left=format, right=args)
    ├── Tuple               — (a, b, c) (elements)
    └── PyList              — [a, b, c] (elements)
```

### Key design decisions

- **Every node stores `line` and `col`** for precise vulnerability reporting. These are copied directly from the Python AST node's `lineno` and `col_offset`.
- **`JoinedStr`** and **`PercentFormat`** are explicit node types because f-strings and `%` formatting are the most common SQLi propagation patterns in modern Python.
- **`Attribute`** nodes resolve compound sources like `request.args.get("name")` by chaining through the object tree. The `_full_attr_name()` method in the taint engine reconstructs the full dotted path.
- **`ElifClause`** is a separate node type (not a nested `IfStatement`) to make control flow analysis cleaner in the CFG builder.

### How the AST is used throughout the program

| Consumer | File | Method | Purpose |
|----------|------|--------|---------|
| CFG Builder | `cfg_builder.py` | `build(module)` | Traverses `Module.body` to create CFG nodes and edges |
| DFG Builder | `dfg_builder.py` | `build(module)` | Traverses `Module.body` to create DFG nodes and data flow edges |
| Taint Engine (Phase A) | `taint_engine.py` | `_analyze_stmt(stmt)` | Walks the AST to detect sources, propagations, and sanitizations |
| Taint Engine (Phase C) | `taint_engine.py` | `_detect_sinks(stmt)` | Walks the AST again to find sink calls with tainted arguments |
| AST Visualizer | `ast_visualizer.py` | `render(tree)` | Converts the tree to a Graphviz DOT graph for PNG export |
| AST Printer | `ast_printer.py` | `print_ast_tree(tree)` | Prints a formatted tree to the terminal for debugging |
| Report Generator | `report_generator.py` | `_build_path(vuln, ...)` | Uses source line numbers from AST nodes to build taint path traces |

### Output

`output/ast/<case>.png` — a formal academic-style tree diagram with color-coded node categories (9 categories distinguished by shape, border style, and fill).

---

## Phase 2a — CFG (Control Flow Graph)

### What is the CFG?

The CFG is a directed graph where each node represents a basic block of code and edges represent possible execution paths. It models **all possible flows of control** through the program, including branches, loops, and function definitions. The CFG answers the question: *"What statements can execute after this one?"*

### How it works internally

`CFGBuilder` (`cfg_builder.py`) traverses the custom AST using a **chain-based** approach. The core invariant is:

> Every `_build_stmt` method returns `(first_node, last_node)` — the entry and exit points of that statement's subgraph. The caller connects `last_node` of the previous statement to `first_node` of the next.

#### The `_chain` method (`cfg_builder.py:157-170`)

This is the backbone of CFG construction. It takes a starting node and a list of statements, builds each statement's subgraph, and connects them sequentially:

```python
def _chain(self, prev: CFGNode, stmts: List[ASTNode]) -> CFGNode:
    current = prev
    for stmt in stmts:
        result = self._build_stmt(stmt)
        if result is None:
            continue
        first, last = result
        self.cfg.add_edge(current, first)
        current = last
    return current
```

#### Entry and Exit

```python
# cfg_builder.py:146-153
def build(self, module: Module) -> CFG:
    self.cfg = CFG()
    self.cfg.entry  = self.cfg.new_node(CFGNodeType.ENTRY, label="ENTRY")
    self.cfg.exit   = self.cfg.new_node(CFGNodeType.EXIT,  label="EXIT")
    last = self._chain(self.cfg.entry, module.body)
    self.cfg.add_edge(last, self.cfg.exit)
    return self.cfg
```

The module's body is chained from `ENTRY`, and the last statement connects to `EXIT`.

#### Statement-Specific Construction

**Simple statements** (assign, expr, import, return) create a single node:

```python
# _build_assign → one ASSIGN node
# _build_expr_stmt → one CALL node
# _build_return → one RETURN node, connected to function exit or module exit
```

**`if/elif/else`** (`cfg_builder.py:222-261`):

```
         CONDITION (if cond)
         ├─ True  → [then_body] ──────────────┐
         ├─ False → CONDITION (elif) → [body] ─┤ → MERGE
         └─ False → [else_body] ───────────────┘
```

- Creates a `CONDITION` node for the `if` test
- Chains `then_body` from the True edge
- Walks `elif_clauses`, creating a chain of `CONDITION` nodes on the False edges
- The final False edge goes to `else_body` (or directly to `MERGE` if no else)
- All branches converge at an explicit `MERGE` node

**`while` loop** (`cfg_builder.py:265-279`):

```
         LOOP_HEAD (while cond)
         ├─ True  → [body] → back-edge → LOOP_HEAD
         └─ False → MERGE
```

- Creates a `LOOP_HEAD` node
- Chains the body from the True edge
- The last body node creates a **back-edge** to the `LOOP_HEAD`
- The False edge goes to a `MERGE` node (loop exit)

**`for` loop** (`cfg_builder.py:283-298`):

Same structure as `while`, with the label showing `for x in iter`.

**Function definitions** (`cfg_builder.py:302-324`):

```python
def _build_function(self, stmt: FunctionDef):
    func_entry = self.cfg.new_node(CFGNodeType.FUNC_DEF, stmt, f"def {stmt.name}(…)")
    func_exit  = self.cfg.new_node(CFGNodeType.MERGE, label=f"end {stmt.name}")
    
    prev_func_exit = self._func_exit
    self._func_exit = func_exit
    
    last_body = self._chain(func_entry, stmt.body)
    self.cfg.add_edge(last_body, func_exit)
    
    self._func_exit = prev_func_exit
    return func_entry, func_exit
```

- Creates a `FUNC_DEF` entry node and a `MERGE` exit node for the function
- Saves and restores `_func_exit` to handle nested functions correctly
- `return` statements inside the function connect to `_func_exit`, not the module `EXIT`

### CFG Node Types

| Node Type | Represents | Created By |
|-----------|------------|------------|
| `ENTRY` | Start of the module | `build()` |
| `EXIT` | End of the module | `build()` |
| `ASSIGN` | Variable assignment (`x = expr`, `x += expr`) | `_build_assign`, `_build_augassign` |
| `CALL` | Expression statement (function call as a statement) | `_build_expr_stmt` |
| `CONDITION` | `if` / `elif` condition evaluation | `_build_if` |
| `MERGE` | Convergence point after branches | `_build_if`, `_build_while`, `_build_for`, `_build_function` |
| `LOOP_HEAD` | `while` / `for` loop header | `_build_while`, `_build_for` |
| `RETURN` | Return from a function | `_build_return` |
| `IMPORT` | Import statement | `_build_import` |
| `FUNC_DEF` | Function definition (container node) | `_build_function` |

### How the CFG is used throughout the program

| Consumer | File | Method/Location | Purpose |
|----------|------|-----------------|---------|
| Taint Engine | — | — | The CFG is **not directly used** by the taint engine. Taint propagation operates on the AST + DFG. However, the CFG's structure influences severity classification. |
| Report Generator | `report_generator.py:209-215` | `_severity(cfg)` | Checks if the CFG has `CONDITION` or `LOOP_HEAD` nodes to classify vulnerabilities as `CRITICAL` (no branches) or `WARNING` (conditional paths) |
| Report Generator | `report_generator.py:375-393` | `assemble_report()` | Counts node types for §6 statistics: total nodes, conditions, assignments, calls, merges |
| CFG Visualizer | `cfg_visualizer.py` | `render(cfg)` | Converts the graph to a Graphviz DOT graph for PNG export, with different shapes per node type |
| `main.py` | `main.py:120` | `run_case()` | Stores the CFG to pass to report generation and visualization |

### Output

`output/cfg/<case>.png` — a directed graph showing all execution paths with labeled nodes. ENTRY is a double-circle, EXIT is a double-circle, CONDITION nodes are diamonds, MERGE nodes are hexagons, LOOP_HEAD nodes are octagons.

---

## Phase 2b — DFG (Data Flow Graph)

### What is the DFG?

The DFG is a directed graph where nodes represent **values** (variables, literals, computed expressions) and edges represent **data dependencies** — how values flow from one variable to another through assignments, operations, and function calls. The DFG answers the question: *"Where did the value in this variable come from?"*

### How it works internally

`DFGBuilder` (`dfg_builder.py`) traverses the AST and builds a graph tracking value propagation. Unlike the CFG (which tracks **control** flow), the DFG tracks **data** flow.

#### Scope Management

The DFG builder maintains a **scope stack** to handle function-local variables:

```python
# dfg_builder.py:216
self._scope_stack: List[Dict[str, DFGNode]] = []

def _push_scope(self): self._scope_stack.append({})
def _pop_scope(self):  self._scope_stack.pop()

def _lookup(self, name: str) -> Optional[DFGNode]:
    for scope in reversed(self._scope_stack):
        if name in scope:
            return scope[name]
    return self.dfg.nodes.get(name)

def _define(self, name: str, node: DFGNode):
    self._scope_stack[-1][name] = node
    self.dfg.nodes[name] = node
```

- `_push_scope()` is called when entering a function
- `_pop_scope()` is called when exiting
- `_lookup()` searches from innermost to outermost scope, then falls back to global nodes
- `_define()` stores in both the current scope and the global node dictionary

#### Node Creation Strategies

The DFG uses two strategies for node creation:

1. **`new_node()`** — always creates a fresh node with a unique key. Used for intermediate values (operators, call results, literals).
2. **`get_or_create()`** — reuses an existing node if the name already exists. Used for variables that may be reassigned.

#### SSA-Style Naming

When a variable is reassigned, the old version remains in the graph but the canonical name points to the new version:

```python
# dfg_builder.py:131-136
def new_node(self, name, t, ast_node=None, value=None):
    node = self._mk(name, t, ast_node, value)
    key = name if name not in self.nodes else f"{name}#{node.id}"
    self.nodes[key] = node
    return node
```

This produces names like `query#0`, `query#1` for different versions of the same variable.

#### Expression Building

**Literals** (`dfg_builder.py:339-342`):
```python
key = f"_lit_{id(expr)}"
return self.dfg.new_node(key, DFGNodeType.CONSTANT, ast_node=expr, value=expr.value)
```

**Names/Variables** (`dfg_builder.py:345-352`):
```python
existing = self._lookup(expr.name)
if existing:
    return existing  # Use the most recent definition
t = DFGNodeType.SOURCE if expr.name in _SOURCES else DFGNodeType.VARIABLE
node = self.dfg.get_or_create(expr.name, t, ast_node=expr)
self._define(expr.name, node)
return node
```

**Attributes** (`dfg_builder.py:421-440`):
Builds the chain `request → request.args → request.args.get` as separate nodes with edges between them. The canonical name is the full dotted path.

**Function Calls** (`dfg_builder.py:442-491`):
```
func_node (from _build_expr) ──► FUNCTION_CALL node ◄── arg nodes
                                       │
                                       ▼
                              (assigned to variable)
```

The call node is classified as `SOURCE` if the function is a known source (`input`, `request.args.get`), `SINK` if it's a SQL method (`execute`), or `FUNCTION_CALL` otherwise.

**Binary Operations** (`dfg_builder.py:493-504`):
```python
op = self.dfg.new_node(f"_binop_{expr.op}_{id(expr)}", DFGNodeType.OPERATOR, ast_node=expr)
self.dfg.add_edge(left, op, label="left")
self.dfg.add_edge(right, op, label="right")
return op
```

**F-strings** (`dfg_builder.py:506-521`):
Creates an `OPERATOR` node (`_fstring_NNN`) that receives edges from all `FormattedValue` parts.

**`%` format** (`dfg_builder.py:523-538`):
Creates an `OPERATOR` node (`_pctfmt_NNN`) that receives edges from both the format string and the arguments.

### DFG Node Types

| Node Type | Represents | Created When |
|-----------|------------|--------------|
| `CONSTANT` | Literal value (always safe) | `Literal` expression encountered |
| `PARAMETER` | Function parameter (potentially tainted) | Inside `FunctionDef`, for each `Param` |
| `VARIABLE` | Variable definition | `AssignStatement`, `Name` reference, `Attribute` chain |
| `OPERATOR` | Result of binary operation, f-string, or `%` format | `BinaryOp`, `JoinedStr`, `PercentFormat`, `BoolOp`, `Tuple` |
| `FUNCTION_CALL` | Result of a function call | `FCall` that is neither source nor sink |
| `SOURCE` | Known external input | `Name` or `Attribute` matching `_SOURCES`, or `FCall` to source function |
| `SINK` | SQL execution | `FCall` where the method name is in `_SINK_METHODS` |

### Known Sets

```python
# dfg_builder.py:84-106
_SOURCES = {"input", "request.args.get", "request.args", "request.form.get", ...}
_SINK_METHODS = {"execute", "executemany", "executescript", "raw", "query"}
_SANITIZERS = {"int", "float", "bool", "re.escape", "html.escape", "escape", "quote", "parameterize"}
```

### How the DFG is used throughout the program

| Consumer | File | Method/Location | Purpose |
|----------|------|-----------------|---------|
| Taint Engine (Phase B) | `taint_engine.py:384-504` | `_propagate_through_dfg()` | **Primary consumer**. Runs BFS from tainted seed nodes, propagating taint through outgoing edges. Checks if successors are sanitizers (stops propagation) or regular nodes (continues propagation). Reconciles DFG node taint back to the SymbolTable. |
| Taint Engine (Phase A) | `taint_engine.py:282, 309, 336, 361` | `_mark_dfg_node_tainted()` | Marks DFG nodes as tainted seeds when Phase A detects a source assignment. |
| Report Generator | `report_generator.py:396-410` | `assemble_report()` | Counts node types for §6 statistics: total nodes, edges, sources, sinks, operators, constants, variables, taint hops |
| DFG Visualizer | `dfg_visualizer.py` | `render(dfg)` | Converts the graph to a Graphviz DOT graph for PNG export, with different colors per node type (SOURCE=red, SINK=red, CONSTANT=green, etc.) |
| `main.py` | `main.py:129` | `run_case()` | Stores the DFG to pass to taint analysis, report generation, and visualization |

### DFG Example: Complete Flow

For the code:
```python
user_id = input("Enter ID: ")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

The DFG looks like:
```
_lit_NNN ("Enter ID: ") ──► input ──► SOURCE (input)
                                              │
                                              ▼
                                       VARIABLE (user_id)
                                              │
                                              ▼
_lit_MMM ("SELECT * FROM...") ──► OPERATOR (_binop_+) ◄── VARIABLE (user_id)
                                                              │
                                                              ▼
                                                       VARIABLE (query)
                                                              │
                                                              ▼
                                                       SINK (cursor.execute)
```

### Output

`output/dfg/<case>.png` — a directed graph showing how data flows between variables, with source/sink nodes highlighted in red, constants in green, and operators in orange.

---

## Phase 2c — Taint Analysis (Taint Engine)

### What is Taint Analysis?

Taint analysis tracks how **untrusted data** (user input, HTTP requests, environment variables) flows through a program. If tainted data reaches a **dangerous operation** (SQL execution, command execution) without being **sanitized**, a vulnerability is reported.

The taint engine is the **core analysis component** that consumes all three previous artifacts: the AST (for structure), the DFG (for data flow), and the SymbolTable (for variable state).

### Core Data Structures

#### TaintRecord (`taint_engine.py:89-97`)
Records a single taint event (source or propagation):
```python
@dataclass
class TaintRecord:
    variable:    str          # Variable name
    source:      str          # Source identifier (e.g., "input", "request.args.get")
    source_type: TaintSource  # Enum classification
    line:        int          # Source line
    col:         int          # Source column
    path:        List[str]    # Propagation path
```

#### Vulnerability (`taint_engine.py:100-115`)
Records a detected SQLi vulnerability:
```python
@dataclass
class Vulnerability:
    sink:        str           # e.g., "cursor.execute"
    arg_name:    str           # Tainted argument name
    taint_path:  List[str]     # Full trace: source → vars → sink
    source_type: TaintSource
    line:        int
    col:         int
```

#### TaintPropagationResult (`taint_engine.py:118-161`)
Aggregates all analysis results:
```python
class TaintPropagationResult:
    sources:         List[TaintRecord]   # All taint sources detected
    propagations:    List[TaintRecord]   # All taint propagation steps
    sanitizations:   List[str]           # Sanitizer functions found
    vulnerabilities: List[Vulnerability] # Detected vulnerabilities
```

### Analysis Algorithm: Three Phases

The `analyze()` method (`taint_engine.py:202-228`) orchestrates the three phases:

```python
def analyze(self, module: Module, dfg: DFG, symbol_table: SymbolTable) -> TaintPropagationResult:
    self._tainted_node_ids = set()
    result = TaintPropagationResult()
    
    # Phase A: AST pass — detect sources, propagate through assignments
    for stmt in module.body:
        self._analyze_stmt(stmt, dfg, symbol_table, result)
    
    # Phase B: DFG BFS — transitive taint propagation
    self._propagate_through_dfg(dfg, symbol_table, result)
    
    # Phase C: Sink detection — find tainted args in sink calls
    for stmt in module.body:
        self._detect_sinks(stmt, symbol_table, result)
    
    return result
```

### Phase A — AST Pass (Source Detection & Initial Taint)

**Entry point**: `_analyze_stmt()` (`taint_engine.py:234-249`)

Dispatches to statement-specific analyzers:

```python
def _analyze_stmt(self, stmt, dfg, st, result):
    if isinstance(stmt, AssignStatement):     self._analyze_assign(...)
    elif isinstance(stmt, AugAssignStatement):self._analyze_augassign(...)
    elif isinstance(stmt, ExprStatement):     self._analyze_expr_stmt(...)
    elif isinstance(stmt, IfStatement):       self._analyze_if(...)
    elif isinstance(stmt, WhileStatement):    self._analyze_while(...)
    elif isinstance(stmt, ForStatement):      self._analyze_for(...)
    elif isinstance(stmt, FunctionDef):       self._analyze_function(...)
```

#### Assignment Analysis (`_analyze_assign`, lines 251-285)

For each `target = value` assignment:

1. **Detect source**: Is `value` a direct source like `input()` or `request.args.get()`?
   ```python
   source_name = self._detect_source(stmt.value)
   ```

2. **Check existing taint**: Does `value` contain a tainted variable?
   ```python
   is_tainted = source_name is not None or self._is_tainted_expr(stmt.value, st)
   ```
   `_is_tainted_expr()` recursively checks all expression types:
   - `Name`: check SymbolTable
   - `Attribute`: check if the full path is a known source, or if the object is tainted
   - `BinaryOp`: tainted if either operand is tainted
   - `JoinedStr`: tainted if any `FormattedValue` is tainted
   - `PercentFormat`: tainted if the right side (args) is tainted
   - `FCall`: tainted if any argument is tainted (unless it's a sanitizer)

3. **Check sanitizer**: Is `value` wrapped in a sanitizing function?
   ```python
   sanitizer = self._detect_sanitizer(stmt.value, st)
   ```

4. **Update SymbolTable**:
   - If sanitizer → `st.mark_sanitized(tname, sanitizer)`
   - If tainted → `st.mark_tainted(tname, source=src_label)` + mark DFG node
   - Otherwise → `st.mark_safe(tname)`

#### Augmented Assignment Analysis (`_analyze_augassign`, lines 287-309)

For `target op= value`:

The target stays tainted if:
- The new `value` is tainted (new taint enters), OR
- The `target` was already tainted (taint persists through the operation)

```python
value_tainted = self._is_tainted_expr(stmt.value, st)
prev_tainted  = st.is_tainted(tname)
if value_tainted or prev_tainted or source_from_val:
    st.mark_tainted(tname, source=src_label, ...)
```

#### Function Analysis (`_analyze_function`, lines 339-378)

1. Creates a **child SymbolTable** for function-local scope
2. Marks all parameters as `PARAM` and conservatively as `TAINTED`
3. Analyzes the function body using the child table
4. **Merges** tainted symbols from child back to parent:
   ```python
   for sym in child_st.get_all_symbols():
       if sym.taint_status in (TaintStatus.TAINTED, TaintStatus.PARAM):
           if not st.is_tainted(sym.name):
               st.mark_tainted(sym.name, source=sym.sources[0], ...)
   ```
   This ensures Phase C sink detection can see taint from inside functions.

#### Control Flow Analysis

- **`if`**: Recursively analyzes `then_body`, `else_body`, and all `elif` bodies
- **`while`**: Recursively analyzes the loop body
- **`for`**: If the iterator is tainted, marks the loop variable as tainted, then analyzes the body

### Phase B — DFG BFS Propagation (Transitive Taint)

**Entry point**: `_propagate_through_dfg()` (`taint_engine.py:384-504`)

This phase propagates taint through the DFG using **Breadth-First Search**, catching taint flows that Phase A may have missed (e.g., through intermediate operator nodes).

#### Step 1: Seed the BFS

Iterates all DFG nodes and marks them as tainted if:

1. **Already tainted in SymbolTable** (from Phase A):
   ```python
   if st.is_tainted(canonical) or st.is_param(canonical):
       self._tainted_node_ids.add(node.id)
   ```

2. **Explicit SOURCE node** (e.g., `input`, `request.args.get`):
   ```python
   if node.type == DFGNodeType.SOURCE:
       self._tainted_node_ids.add(node.id)
       st.mark_tainted(canonical, source=canonical, ...)
   ```

3. **PARAMETER node** (function parameters):
   ```python
   if node.type == DFGNodeType.PARAMETER:
       self._tainted_node_ids.add(node.id)
   ```

4. **Implicit external variable** (used but never defined, not a builtin):
   ```python
   if (node.type == DFGNodeType.VARIABLE
       and not node.incoming          # no known source
       and not st.has(canonical)      # not defined in any scope
       and canonical not in _PYTHON_BUILTINS):
       self._tainted_node_ids.add(node.id)
       st.mark_tainted(canonical, source="external_implicit", ...)
   ```

#### Step 2: BFS Propagation

```python
queue = deque(tainted_nodes)
visited_as_tainted = set(self._tainted_node_ids)

while queue:
    node = queue.popleft()
    for succ in node.outgoing:
        if succ.id in visited_as_tainted:
            continue
        
        # Check if successor is a sanitizer
        if succ.type == DFGNodeType.FUNCTION_CALL:
            callee = succ.value
            if st.is_sanitizer(callee):
                # Mark downstream variables as SANITIZED
                for var_succ in succ.outgoing:
                    vname = var_succ.name.split("#")[0]
                    st.mark_sanitized(vname, sanitizer=callee)
                continue  # Stop propagation
        
        # Propagate taint
        visited_as_tainted.add(succ.id)
        self._tainted_node_ids.add(succ.id)
        queue.append(succ)
        
        # Reconcile with SymbolTable
        canonical = succ.name.split("#")[0]
        if not canonical.startswith("_"):
            st.mark_tainted(canonical, source=src, ...)
```

**Key behavior**: When a sanitizer is encountered, taint propagation **stops** at that node. The variables that receive the sanitized value are marked `SANITIZED`, not `TAINTED`.

### Phase C — Sink Detection

**Entry point**: `_detect_sinks()` (`taint_engine.py:510-526`)

Recursively walks the AST looking for function calls to known SQL sinks:

```python
def _detect_sinks(self, stmt, st, result):
    if isinstance(stmt, ExprStatement) and stmt.expression:
        self._check_sink_expr(stmt.expression, st, result)
    elif isinstance(stmt, IfStatement):
        for s in stmt.then_body: self._detect_sinks(s, st, result)
        for s in stmt.else_body: self._detect_sinks(s, st, result)
        for ec in stmt.elif_clauses:
            for s in ec.body: self._detect_sinks(s, st, result)
    elif isinstance(stmt, WhileStatement):
        for s in stmt.body: self._detect_sinks(s, st, result)
    elif isinstance(stmt, ForStatement):
        for s in stmt.body: self._detect_sinks(s, st, result)
    elif isinstance(stmt, FunctionDef):
        child_st = st.create_child() if st.get_function(stmt.name) else st
        for s in stmt.body: self._detect_sinks(s, child_st, result)
```

#### Sink Checking (`_check_sink_expr`, lines 528-556)

For each `FCall`:

1. Extract the function name (e.g., `cursor.execute` from the Attribute chain)
2. Check if it's a known sink: `st.is_sink(func_name)`
3. For each argument, check if it's tainted: `self._is_tainted_expr(arg, st)`
4. If tainted, create a `Vulnerability` record:
   ```python
   result.add_vulnerability(Vulnerability(
       sink       = func_name,
       arg_name   = arg_name,
       taint_path = path,        # [arg_name] + sym.sources
       source_type= stype,
       line       = expr.line,
       col        = expr.col,
   ))
   ```

### Helper: `_is_tainted_expr()` (lines 562-638)

This is the **core taint query** used throughout all three phases. It recursively determines if an expression produces or contains tainted data:

| Expression Type | Taint Condition |
|-----------------|-----------------|
| `Name` | `st.is_tainted(name)` or `st.is_param(name)` |
| `Literal` | Always `False` (literals are safe) |
| `Attribute` | Full path is a known source, or object is tainted |
| `Subscript` | Object is tainted |
| `FCall` | Any argument is tainted (unless callee is a sanitizer) |
| `BinaryOp` | Either operand is tainted |
| `UnaryOp` | Operand is tainted |
| `BoolOp` | Any value is tainted |
| `Compare` | Left or any comparator is tainted |
| `JoinedStr` | Any `FormattedValue` is tainted |
| `PercentFormat` | Left (format) or right (args) is tainted |
| `Tuple` / `PyList` | Any element is tainted |

### Symbol Table Integration

The `SymbolTable` (`symbol_table.py`) is the **shared state** between all three phases:

| Phase | Reads | Writes |
|-------|-------|--------|
| Phase A (AST pass) | `is_tainted()`, `is_sanitizer()`, `is_source()` | `mark_tainted()`, `mark_safe()`, `mark_sanitized()`, `mark_param()` |
| Phase B (DFG BFS) | `is_tainted()`, `is_param()`, `is_sanitizer()`, `has()` | `mark_tainted()`, `mark_sanitized()` |
| Phase C (Sink detection) | `is_tainted()`, `is_param()`, `is_sink()`, `get()` | — (read-only) |
| Report Generator | `get_all_symbols()`, `is_sink()`, `is_sanitizer()` | — (read-only) |

#### Taint Status Values

| Status | Meaning | Set By |
|--------|---------|--------|
| `UNKNOWN` | Initial state; no analysis yet | Default |
| `SAFE` | Value is known to be safe (literal, sanitized input) | `mark_safe()` |
| `TAINTED` | Value comes from an untrusted source | `mark_tainted()` |
| `SANITIZED` | Value was tainted but passed through a sanitizer | `mark_sanitized()` |
| `PARAM` | Value is a function parameter (conservatively tainted) | `mark_param()` |

### How the Taint Engine is used throughout the program

| Consumer | File | Method/Location | Purpose |
|----------|------|-----------------|---------|
| `main.py` | `main.py:142` | `run_case()` | `taint_engine.analyze(tree, dfg, symbol_table)` — the main analysis call |
| Report Generator | `report_generator.py:283-441` | `assemble_report()` | Consumes `TaintPropagationResult` to build vulnerability details, safe sinks, sanitization records, and statistics |
| Report Generator | `report_generator.py:457-653` | `render_terminal()` | Displays sources, propagations, vulnerabilities, and sanitizations in 7-section terminal report |
| Report Generator | `report_generator.py:660-729` | `render_json()` | Serializes results to JSON for CI/CD |
| PDF Report Generator | `pdf_report_generator.py` | `generate_all_pdfs()` | Converts JSON reports to formatted PDFs |

### Output

The taint engine produces a `TaintPropagationResult` object containing:
- **Sources**: List of all taint entry points with location and type
- **Propagations**: List of all taint propagation steps through the DFG
- **Sanitizations**: List of sanitizer functions that broke the taint chain
- **Vulnerabilities**: List of all detected SQLi vulnerabilities with full taint paths

This result is consumed by the Report Generator to produce terminal output, JSON reports, and PDF reports.

---

## Report Generation

### How Reports Consume All Previous Stages

The report generator (`report_generator.py`) is the **final consumer** that integrates data from all previous stages:

```python
def assemble_report(
    filepath:   str,           # File path
    source:     str,           # Raw source code (for line extraction)
    result:     TaintPropagationResult,  # From Taint Engine
    cfg:        CFG,           # From CFG Builder
    dfg:        DFG,           # From DFG Builder
    st:         SymbolTable,   # From Symbol Table
    elapsed_ms: float,         # Timing from main.py
) -> ReportData:
```

| Report Section | Data Source | How It's Built |
|----------------|-------------|----------------|
| §1 Header | `filepath`, `source` | Extracts filename, counts LOC, gets timestamp |
| §2 Summary | `result.vulnerabilities` | Counts by severity (CRITICAL/WARNING/INFO) |
| §3 Details | `result.vulnerabilities` + `cfg` + `source` | For each vuln: builds taint path trace, looks up source lines, determines severity from CFG structure, selects remediation based on source type |
| §4 Safe Paths | `result.sanitizations` + `st` + `source` | Finds sink calls in source that are protected by sanitizers |
| §5 Sanitizations | `result.sanitizations` + `st` | Lists sanitizer functions and the variables they protect |
| §6 Statistics | `cfg` + `dfg` + `result` | Counts CFG node types, DFG node/edge types, taint hops |
| §7 Footer | All of the above | Totals, analysis time, engine version, final verdict |

### Severity Classification Logic

```python
# report_generator.py:209-215
def _severity(cfg: CFG) -> str:
    has_conditions = any(
        n.type in (CFGNodeType.CONDITION, CFGNodeType.LOOP_HEAD)
        for n in cfg.nodes.values()
    )
    return "WARNING" if has_conditions else "CRITICAL"
```

- **CRITICAL**: The CFG has no condition or loop nodes — the vulnerability is on an unconditional path
- **WARNING**: The CFG has branches — the vulnerability exists only on some execution paths

### Verdict Logic

```python
if result.vulnerabilities:
    verdict = "VULNERABLE"
elif dfg_stats.sinks == 0:
    verdict = "SAFE (no SQL sink)"
else:
    verdict = "SAFE"
```

### Terminal Report (7 sections)

| Section | Content |
|---------|---------|
| §1 Header | Filename, timestamp, LOC, verdict |
| §2 Executive Summary | Vulnerability table with ID, severity, sink, source |
| §3 Vulnerability Details | Full details per vulnerability: sink location, taint path trace, remediation with code example |
| §4 Safe Paths Confirmed | Sinks that were analyzed and confirmed safe |
| §5 Sanitizations Detected | Sanitizer functions found and variables they protect |
| §6 CFG/DFG Statistics | Graph metrics (nodes, edges, sources, sinks, taint hops) |
| §7 Footer | Totals, analysis time, engine version, final verdict |

### JSON Report

Machine-readable report in `output/reports/<case>.json` with the same 7 sections, suitable for CI/CD integration.

### PDF Report

Formatted PDF in `output/pdf/<case>.pdf` with:
- Cover page with metadata
- Color-coded severity indicators
- Taint path trace tables
- Remediation code blocks
- Statistics tables
- Sanitizer detection tables

---

## Accuracy Metrics (§8)

### What are False Positives and False Negatives?

In static analysis, there are four possible outcomes for each test case:

| | **Actually Vulnerable** | **Actually Safe** |
|---|---|---|
| **Tool says VULNERABLE** | ✅ True Positive (TP) | ❌ **False Positive (FP)** |
| **Tool says SAFE** | ❌ **False Negative (FN)** | ✅ True Negative (TN) |

- **False Positive**: The tool reports a vulnerability that doesn't actually exist. This wastes developer time and causes alert fatigue.
- **False Negative**: The tool misses a real vulnerability. This is dangerous because vulnerable code ships undetected.

### Metrics Computed

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| **Precision** | `TP / (TP + FP)` | Of all reported vulnerabilities, how many are real? |
| **Recall** | `TP / (TP + FN)` | Of all real vulnerabilities, how many did we find? |
| **F1 Score** | `2 × (P × R) / (P + R)` | Harmonic mean of precision and recall |
| **False Positive Rate** | `FP / (FP + TN)` | Of all safe cases, how many were wrongly flagged? |
| **False Negative Rate** | `FN / (FN + TP)` | Of all vulnerable cases, how many were missed? |
| **Accuracy** | `(TP + TN) / Total` | Overall correctness across all cases |

### How It Works

#### Ground Truth (`samples/ground_truth.json`)

Each sample case has a ground truth entry defining what the linter *should* find:

```json
{
  "case2_sqli_concatenation.py": {
    "description": "SQLi via string concatenation",
    "expected_verdict": "VULNERABLE",
    "expected_vulns": 1,
    "expected_vulnerabilities": [
      {
        "sink": "cursor.execute",
        "line": 3,
        "source_type": "INPUT",
        "source_var": "user_id",
        "notes": "input() → concatenation → execute(query)"
      }
    ]
  }
}
```

**Key fields:**
| Field | Purpose |
|-------|---------|
| `expected_verdict` | `"VULNERABLE"` or `"SAFE"` |
| `expected_vulns` | Number of vulnerabilities that should be reported |
| `expected_vulnerabilities` | Per-vulnerability details: sink name, line, source type |

#### Vulnerability Matching (`test_metrics.py`)

The test harness matches actual vulnerabilities against expected ones using **sink line numbers**:

```python
def match_vulnerabilities(actual_vulns, expected_vulns):
    expected_lines = {v["line"] for v in expected_vulns}
    matched_lines = set()
    
    for vuln in actual_vulns:
        if vuln.line in expected_lines and vuln.line not in matched_lines:
            tp += 1
            matched_lines.add(vuln.line)
        else:
            fp += 1  # Reported vuln on unexpected line
    
    for exp in expected_vulns:
        if exp["line"] not in matched_lines:
            fn += 1  # Expected vuln not detected
```

#### Case-Level Classification

| Expected | Actual | Classification |
|----------|--------|----------------|
| VULNERABLE | VULNERABLE (all vulns found) | **TP** |
| SAFE | SAFE | **TN** |
| SAFE | VULNERABLE | **FP** |
| VULNERABLE | SAFE | **FN** |

### Bugs Fixed Using Metrics

The metrics system revealed and helped fix two critical bugs:

#### Bug 1: Function-Scoped Taint Lost in Phase C

**Symptom**: case3 (f-string in function) and case7 (ORM injection) were **false negatives**.

**Root cause**: Phase C `_detect_sinks()` created a **fresh** child SymbolTable for functions, but the taint was tracked in a **different** child table during Phase A. The sink detection couldn't see tainted variables inside functions.

**Fix** (`taint_engine.py:197, 353, 536`):
```python
# In __init__: cache for function symbol tables
self._func_tables: Dict[str, SymbolTable] = {}

# In _analyze_function: cache the child table
self._func_tables[stmt.name] = child_st

# In _detect_sinks: reuse the cached table
child_st = self._func_tables.get(stmt.name)
```

#### Bug 2: Parameterized Queries Flagged as Vulnerable

**Symptom**: case11 (enterprise app with parameterized queries) was a **false positive** — 2 vulns reported where none should exist.

**Root cause**: `_check_sink_expr()` checked **all** arguments of `execute()`. For parameterized queries like `cursor.execute(query, (username,))`, the tainted `username` in position 1 was flagged, even though it's safe (passed as a parameter, not interpolated into SQL).

**Fix** (`taint_engine.py:540-571`):
```python
# Only check position 0 (the SQL query string).
# Position 1+ are parameterized query parameters — safe by design.
if not expr.args:
    return
arg = expr.args[0]
arg_tainted = self._is_tainted_expr(arg, st)
```

#### Bug 3: Sink in Assignment Value Not Detected

**Symptom**: case7 `result = cursor.execute(query)` was not detected.

**Root cause**: `_detect_sinks()` only checked `ExprStatement` nodes. When a sink call is the **value** of an assignment (`result = cursor.execute(...)`), it's an `AssignStatement`, not an `ExprStatement`.

**Fix** (`taint_engine.py:521-523`):
```python
elif isinstance(stmt, AssignStatement) and stmt.value:
    # Sink can be the value of an assignment
    self._check_sink_expr(stmt.value, st, result)
```

### Running the Metrics

```bash
# Run analysis on all cases and compute metrics
python test_metrics.py

# Output:
#   - Rich terminal report (§8 Accuracy Metrics)
#   - JSON report → output/metrics.json
```

### Current Results

| Metric | Value |
|--------|-------|
| True Positives | 7 |
| True Negatives | 4 |
| False Positives | 0 |
| False Negatives | 0 |
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |
| **F1 Score** | **100.0%** |
| Accuracy | 100.0% |

### How to Add New Test Cases

1. Create the sample file in `samples/caseN_description.py`
2. Add an entry to `samples/ground_truth.json` with expected verdict and vulnerabilities
3. Add the case to `CASE_META` in `main.py` (for visualization)
4. Run `python test_metrics.py` to verify

---

## Directory Structure

```
samples/
├── ground_truth.json   ← Ground truth for accuracy metrics
└── case*.py            ← Input Python source files (one per case)
output/
├── ast/                ← AST visualization PNGs
├── cfg/                ← CFG visualization PNGs
├── dfg/                ← DFG visualization PNGs
├── legend/             ← AST node classification legend
├── reports/            ← JSON reports
├── pdf/                ← PDF reports
└── metrics.json        ← Accuracy metrics (TP/FP/TN/FN)
```

## Running the Project

```bash
# Install dependencies
pip install -r requirements.txt

# Run analysis on all samples (AST, CFG, DFG, taint, reports)
python main.py

# Run accuracy metrics (TP/FP/TN/FN analysis)
python test_metrics.py

# Generate PDFs from existing JSON reports
python pdf_report_generator.py
```

## Test Cases

| Case | Description | Expected | Actual | Result |
|------|-------------|----------|--------|--------|
| 1 | Simple assignment | SAFE | SAFE | ✅ TN |
| 2 | SQLi via string concatenation | VULNERABLE | VULNERABLE (1 vuln) | ✅ TP |
| 3 | SQLi via f-string (Flask) | VULNERABLE | VULNERABLE (1 vuln) | ✅ TP |
| 4 | SQLi via printf-style `%` | VULNERABLE | VULNERABLE (1 vuln) | ✅ TP |
| 5 | Safe path with `int()` sanitizer | SAFE | SAFE | ✅ TN |
| 6 | Conditional SQLi via AugAssign | VULNERABLE | VULNERABLE (1 vuln) | ✅ TP |
| 7 | ORM with raw SQL injection | VULNERABLE | VULNERABLE (1 vuln) | ✅ TP |
| 8 | Safe ORM with parameterized queries | SAFE | SAFE | ✅ TN |
| 9 | Complex taint propagation | VULNERABLE | VULNERABLE (2 vulns) | ✅ TP |
| 10 | Dynamic table/column names | VULNERABLE | VULNERABLE (2 vulns) | ✅ TP |
| 11 | Enterprise app with validation | SAFE | SAFE | ✅ TN |

**Total: 7 TP + 4 TN + 0 FP + 0 FN = 100% accuracy**
