"""
cfg_builder.py — Control Flow Graph Builder
============================================

Construye el CFG a partir del AST del subconjunto Python del linter.

Correcciones respecto a la versión original
-------------------------------------------
1. _build_function  : los nodos del body se encadenan linealmente entre sí
                      y se conectan correctamente al EXIT del módulo.
2. _build_if        : se crea un nodo MERGE explícito al que convergen
                      todas las ramas (True, False, elif). Así los nodos
                      que siguen al if tienen un predecesor concreto.
3. _build_while     : los nodos del body se encadenan entre sí y el último
                      forma la back-edge al header del loop.
4. _build_for       : igual que while — body encadenado.
5. Etiquetas        : se extraen del AST para que reflejen el código real
                      (se usan en el visualizador).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

from ast_nodes import (
    ASTNode,
    Module, AssignStatement, AugAssignStatement, ExprStatement,
    IfStatement, WhileStatement, ForStatement, FunctionDef, ReturnStatement,
    ImportStatement,
    FCall, Attribute, Name, BinaryOp, Literal,
    JoinedStr, PercentFormat,
)


# ──────────────────────────────────────────────────────────────────────────────
# Tipos y nodos
# ──────────────────────────────────────────────────────────────────────────────

class CFGNodeType(Enum):
    ENTRY     = auto()
    EXIT      = auto()
    ASSIGN    = auto()   # x = expr  /  x += expr
    CALL      = auto()   # expr usada como sentencia (execute, print, …)
    CONDITION = auto()   # if / elif / while condition
    MERGE     = auto()   # punto de convergencia tras if/elif/else
    LOOP_HEAD = auto()   # cabecera de while / for
    LOOP_BODY = auto()   # nodo sintético de cuerpo de loop
    RETURN    = auto()
    IMPORT    = auto()
    FUNC_DEF  = auto()   # definición de función (nodo contenedor)


@dataclass
class CFGNode:
    id:           int
    type:         CFGNodeType
    ast_node:     Optional[ASTNode] = None
    label:        str               = ""
    line:         int               = 0
    col:          int               = 0
    successors:   List["CFGNode"]   = field(default_factory=list)
    predecessors: List["CFGNode"]   = field(default_factory=list)

    def __hash__(self):   return self.id
    def __eq__(self, o):  return isinstance(o, CFGNode) and self.id == o.id
    def __repr__(self):   return f"CFGNode({self.id}, {self.type.name}, {self.label!r})"


class CFG:
    def __init__(self):
        self.nodes:   Dict[int, CFGNode] = {}
        self.entry:   Optional[CFGNode]  = None
        self.exit:    Optional[CFGNode]  = None
        self._next_id = 0

    def new_node(self, node_type: CFGNodeType,
                 ast_node: Optional[ASTNode] = None,
                 label: str = "") -> CFGNode:
        node = CFGNode(
            id       = self._next_id,
            type     = node_type,
            ast_node = ast_node,
            label    = label or node_type.name,
            line     = ast_node.line if ast_node else 0,
            col      = ast_node.col  if ast_node else 0,
        )
        self._next_id += 1
        self.nodes[node.id] = node
        return node

    def add_edge(self, src: CFGNode, dst: CFGNode):
        if dst not in src.successors:
            src.successors.append(dst)
        if src not in dst.predecessors:
            dst.predecessors.append(src)

    def get_all_paths(self, start: Optional[CFGNode] = None,
                      end: Optional[CFGNode] = None) -> List[List[CFGNode]]:
        if start is None: start = self.entry
        if end   is None: end   = self.exit
        paths, path, visited = [], [start], set()
        def dfs(node: CFGNode):
            if node == end:
                paths.append(path[:]); return
            visited.add(node.id)
            for s in node.successors:
                if s.id not in visited:
                    path.append(s); dfs(s); path.pop()
            visited.remove(node.id)
        dfs(start)
        return paths

    def __repr__(self) -> str:
        lines = [f"CFG(entry={self.entry.id}, exit={self.exit.id}, "
                 f"{len(self.nodes)} nodes)"]
        for node in self.nodes.values():
            succs = [s.id for s in node.successors]
            lines.append(f"  [{node.id}] {node.type.name:12} {node.label!r:35} → {succs}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Builder
# ──────────────────────────────────────────────────────────────────────────────

class CFGBuilder:
    """
    Construye el CFG a partir de un Module del parser.

    Uso:
        cfg = CFGBuilder().build(module)

    Invariante de retorno de _build_stmt / _build_stmts
    -----------------------------------------------------
    Cada método devuelve (first_node, last_node) o None si no generó nodos.
    El caller conecta last_node con lo que venga después.
    """

    def __init__(self):
        self.cfg: Optional[CFG] = None
        self._func_exit: Optional[CFGNode] = None

    # ── Punto de entrada ──────────────────────────────────────────────────────

    def build(self, module: Module) -> CFG:
        self.cfg        = CFG()
        self.cfg.entry  = self.cfg.new_node(CFGNodeType.ENTRY, label="ENTRY")
        self.cfg.exit   = self.cfg.new_node(CFGNodeType.EXIT,  label="EXIT")

        last = self._chain(self.cfg.entry, module.body)
        self.cfg.add_edge(last, self.cfg.exit)
        return self.cfg

    # ── Encadenado de listas de sentencias ───────────────────────────────────

    def _chain(self, prev: CFGNode, stmts: List[ASTNode]) -> CFGNode:
        """
        Construye los nodos de `stmts` y los encadena secuencialmente
        partiendo de `prev`. Devuelve el último nodo producido.
        """
        current = prev
        for stmt in stmts:
            result = self._build_stmt(stmt)
            if result is None:
                continue
            first, last = result
            self.cfg.add_edge(current, first)
            current = last
        return current

    # ── Dispatch de sentencias ────────────────────────────────────────────────

    def _build_stmt(self, stmt: ASTNode
                    ) -> Optional[Tuple[CFGNode, CFGNode]]:
        if isinstance(stmt, AssignStatement):    return self._build_assign(stmt)
        if isinstance(stmt, AugAssignStatement): return self._build_augassign(stmt)
        if isinstance(stmt, ExprStatement):      return self._build_expr_stmt(stmt)
        if isinstance(stmt, IfStatement):        return self._build_if(stmt)
        if isinstance(stmt, WhileStatement):     return self._build_while(stmt)
        if isinstance(stmt, ForStatement):       return self._build_for(stmt)
        if isinstance(stmt, FunctionDef):        return self._build_function(stmt)
        if isinstance(stmt, ReturnStatement):    return self._build_return(stmt)
        if isinstance(stmt, ImportStatement):    return self._build_import(stmt)
        return None

    # ── Sentencias simples ────────────────────────────────────────────────────

    def _build_assign(self, stmt: AssignStatement):
        t = self._target_label(stmt.targets[0]) if stmt.targets else "?"
        v = self._expr_label(stmt.value)
        n = self.cfg.new_node(CFGNodeType.ASSIGN, stmt, f"{t} = {v}")
        return n, n

    def _build_augassign(self, stmt: AugAssignStatement):
        t = self._name_of(stmt.target)
        v = self._expr_label(stmt.value)
        n = self.cfg.new_node(CFGNodeType.ASSIGN, stmt, f"{t} {stmt.op} {v}")
        return n, n

    def _build_expr_stmt(self, stmt: ExprStatement):
        label = self._expr_label(stmt.expression) if stmt.expression else "<expr>"
        n = self.cfg.new_node(CFGNodeType.CALL, stmt, label)
        return n, n

    def _build_return(self, stmt: ReturnStatement):
        val = self._expr_label(stmt.value) if stmt.value else ""
        n = self.cfg.new_node(CFGNodeType.RETURN, stmt, f"return {val}".strip())
        if self._func_exit is not None:
            self.cfg.add_edge(n, self._func_exit)
        else:
            self.cfg.add_edge(n, self.cfg.exit)
        return n, n

    def _build_import(self, stmt: ImportStatement):
        label = f"from {stmt.module} import …" if stmt.is_from else f"import {stmt.module}"
        n = self.cfg.new_node(CFGNodeType.IMPORT, stmt, label)
        return n, n

    # ── if / elif / else ──────────────────────────────────────────────────────

    def _build_if(self, stmt: IfStatement):
        """
        Estructura:

            CONDITION (if cond)
            ├─ True  → [then_body] ──────────────┐
            ├─ False → CONDITION (elif) → [body] ─┤ → MERGE
            └─ False → [else_body] ───────────────┘

        El nodo MERGE es el "last" que el caller conecta con lo siguiente.
        Si no hay else, el CONDITION también apunta directamente al MERGE
        (rama False implícita).
        """
        cond_label = self._expr_label(stmt.condition)
        cond = self.cfg.new_node(CFGNodeType.CONDITION, stmt, f"if {cond_label}")
        merge = self.cfg.new_node(CFGNodeType.MERGE, label="merge")

        # Rama True
        last_then = self._chain(cond, stmt.then_body)
        self.cfg.add_edge(last_then, merge)

        # Ramas elif
        prev_false = cond
        for ec in stmt.elif_clauses:
            ec_label = self._expr_label(ec.condition)
            ec_node = self.cfg.new_node(CFGNodeType.CONDITION, ec, f"elif {ec_label}")
            self.cfg.add_edge(prev_false, ec_node)
            last_elif = self._chain(ec_node, ec.body)
            self.cfg.add_edge(last_elif, merge)
            prev_false = ec_node

        # Rama False / else
        if stmt.else_body:
            last_else = self._chain(prev_false, stmt.else_body)
            self.cfg.add_edge(last_else, merge)
        else:
            # Sin else: la rama False salta directamente al merge
            self.cfg.add_edge(prev_false, merge)

        return cond, merge

    # ── while ─────────────────────────────────────────────────────────────────

    def _build_while(self, stmt: WhileStatement):
        """
            LOOP_HEAD (while cond)
            ├─ True  → [body] → back-edge → LOOP_HEAD
            └─ False → MERGE
        """
        cond_label = self._expr_label(stmt.condition)
        head  = self.cfg.new_node(CFGNodeType.LOOP_HEAD, stmt, f"while {cond_label}")
        merge = self.cfg.new_node(CFGNodeType.MERGE, label="while-exit")

        last_body = self._chain(head, stmt.body)
        self.cfg.add_edge(last_body, head)   # back-edge
        self.cfg.add_edge(head, merge)       # exit edge (condition False)

        return head, merge

    # ── for ───────────────────────────────────────────────────────────────────

    def _build_for(self, stmt: ForStatement):
        """
            LOOP_HEAD (for x in iter)
            ├─ has items → [body] → back-edge → LOOP_HEAD
            └─ exhausted → MERGE
        """
        tgt  = self._name_of(stmt.target)
        iter_= self._expr_label(stmt.iter)
        head  = self.cfg.new_node(CFGNodeType.LOOP_HEAD, stmt, f"for {tgt} in {iter_}")
        merge = self.cfg.new_node(CFGNodeType.MERGE, label="for-exit")

        last_body = self._chain(head, stmt.body)
        self.cfg.add_edge(last_body, head)
        self.cfg.add_edge(head, merge)

        return head, merge

    # ── def function ──────────────────────────────────────────────────────────

    def _build_function(self, stmt: FunctionDef):
        """
        Crea un subgrafo completo para la función con su propio ENTRY/EXIT
        y lo conecta al flujo del módulo como un nodo FUNC_DEF.

        El nodo FUNC_DEF representa la *definición* (no la llamada).
        El cuerpo se encadena internamente.
        """
        func_entry = self.cfg.new_node(CFGNodeType.FUNC_DEF, stmt,
                                       f"def {stmt.name}(…)")
        func_exit  = self.cfg.new_node(CFGNodeType.MERGE, label=f"end {stmt.name}")

        # Save previous func_exit (handles nested functions)
        prev_func_exit = self._func_exit
        self._func_exit = func_exit

        last_body = self._chain(func_entry, stmt.body)
        self.cfg.add_edge(last_body, func_exit)

        # Restore previous func_exit
        self._func_exit = prev_func_exit

        return func_entry, func_exit

    # ── Helpers de etiquetas ──────────────────────────────────────────────────

    def _expr_label(self, node: Optional[ASTNode], max_len: int = 40) -> str:
        if node is None:
            return ""
        label = self._expr_label_full(node)
        return label if len(label) <= max_len else label[:max_len - 1] + "…"

    def _expr_label_full(self, node: ASTNode) -> str:
        from ast_nodes import (Literal, Name, BinaryOp, UnaryOp, BoolOp,
                                Compare, FCall, Attribute, Subscript,
                                JoinedStr, FormattedValue, PercentFormat,
                                Tuple, PyList, Keyword)
        if isinstance(node, Literal):
            return repr(node.value)
        if isinstance(node, Name):
            return node.name
        if isinstance(node, Attribute):
            return f"{self._expr_label_full(node.obj)}.{node.attr}"
        if isinstance(node, Subscript):
            return f"{self._expr_label_full(node.obj)}[…]"
        if isinstance(node, BinaryOp):
            return (f"{self._expr_label_full(node.left)} "
                    f"{node.op} "
                    f"{self._expr_label_full(node.right)}")
        if isinstance(node, UnaryOp):
            return f"{node.op}{self._expr_label_full(node.operand)}"
        if isinstance(node, BoolOp):
            parts = [self._expr_label_full(v) for v in node.values]
            return f" {node.op} ".join(parts)
        if isinstance(node, Compare):
            left = self._expr_label_full(node.left)
            parts = [f"{op} {self._expr_label_full(c)}"
                     for op, c in zip(node.ops, node.comparators)]
            return f"{left} {' '.join(parts)}"
        if isinstance(node, FCall):
            func = self._expr_label_full(node.func)
            args = ", ".join(self._expr_label_full(a) for a in node.args)
            return f"{func}({args})"
        if isinstance(node, JoinedStr):
            return "f\"...\""
        if isinstance(node, PercentFormat):
            return f"{self._expr_label_full(node.left)} % …"
        if isinstance(node, Tuple):
            elems = ", ".join(self._expr_label_full(e) for e in node.elements)
            return f"({elems})"
        return "<expr>"

    def _target_label(self, node: ASTNode) -> str:
        return self._name_of(node)

    def _name_of(self, node: ASTNode) -> str:
        from ast_nodes import Name, Attribute, Subscript
        if isinstance(node, Name):      return node.name
        if isinstance(node, Attribute): return f"{self._name_of(node.obj)}.{node.attr}"
        if isinstance(node, Subscript): return f"{self._name_of(node.obj)}[…]"
        return "?"
