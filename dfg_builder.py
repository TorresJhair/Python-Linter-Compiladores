"""
dfg_builder.py — Data Flow Graph Builder
==========================================

Construye el DFG a partir del AST del subconjunto Python del linter.

Correcciones respecto a la versión original
-------------------------------------------
1. FCall args conectados al nodo resultado de la llamada.
     input("ID: ")  →  el arg "ID: " fluye a input_result,
     que luego fluye a la variable destino.
2. PARAMETER conectado a sus usos dentro del cuerpo de la función.
     product_id  →  int(product_id)  →  safe_id
3. PercentFormat / JoinedStr manejan la propagación de taint:
     "…%s…" % username  →  el nodo operador recibe username
     f"…{name}…"        →  el nodo join recibe name
4. Colisión de nombres en _binop_ solucionada usando id(expr).
5. FCall result: se crea un nodo FUNCTION_CALL separado del nodo del
   nombre de la función, para representar correctamente el valor de
   retorno (que es lo que se asigna a la variable).
6. Atributos encadenados (request.args.get) producen un solo nodo
   con nombre canónico, preservando la cadena de flujo.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set

from ast_nodes import (
    ASTNode,
    Module, AssignStatement, AugAssignStatement, ExprStatement,
    IfStatement, WhileStatement, ForStatement, FunctionDef, ReturnStatement,
    ImportStatement,
    FCall, Attribute, Name, BinaryOp, UnaryOp, BoolOp, Compare,
    Literal, Subscript, JoinedStr, FormattedValue, PercentFormat,
    Tuple, PyList,
)


# ──────────────────────────────────────────────────────────────────────────────
# Tipos y nodos
# ──────────────────────────────────────────────────────────────────────────────

class DFGNodeType(Enum):
    CONSTANT      = auto()   # literal inmutable — siempre safe
    PARAMETER     = auto()   # parámetro de función — potencialmente tainted
    VARIABLE      = auto()   # definición de variable
    OPERATOR      = auto()   # resultado de operación binaria / formato
    FUNCTION_CALL = auto()   # resultado de llamada a función
    SOURCE        = auto()   # fuente externa conocida (input, request.*)
    SINK          = auto()   # sumidero SQL conocido (execute)


@dataclass
class DFGNode:
    id:       int
    name:     str
    type:     DFGNodeType
    ast_node: Optional[ASTNode] = None
    line:     int               = 0
    col:      int               = 0
    value:    Any               = None
    outgoing: List["DFGNode"]   = field(default_factory=list)
    incoming: List["DFGNode"]   = field(default_factory=list)

    def __hash__(self):  return self.id
    def __eq__(self, o): return isinstance(o, DFGNode) and self.id == o.id
    def __repr__(self):  return f"DFGNode({self.id}, {self.type.name}, {self.name!r})"


@dataclass
class DataFlow:
    source: DFGNode
    target: DFGNode
    label:  str  = ""


# ──────────────────────────────────────────────────────────────────────────────
# DFG container
# ──────────────────────────────────────────────────────────────────────────────

# Fuentes externas conocidas (nombre de función o atributo)
_SOURCES: Set[str] = {
    "input",
    "request.args.get", "request.args",
    "request.form.get", "request.form",
    "request.GET.get",  "request.GET",
    "request.POST.get", "request.POST",
    "request.json.get", "request.json",
    "request.values.get",
    "os.environ.get",
    "sys.argv",
}

# Sumideros SQL conocidos (sufijo del nombre del atributo)
_SINK_METHODS: Set[str] = {
    "execute", "executemany", "executescript", "raw", "query",
}

# Sanitizadores conocidos
_SANITIZERS: Set[str] = {
    "int", "float", "bool",
    "re.escape", "html.escape",
    "escape", "quote", "parameterize",
}


class DFG:
    def __init__(self):
        self.nodes:    Dict[str, DFGNode] = {}
        self.edges:    List[DataFlow]     = []
        self._next_id: int                = 0

    # ── Creación de nodos ─────────────────────────────────────────────────────

    def _mk(self, name: str, t: DFGNodeType,
            ast_node: Optional[ASTNode] = None,
            value: Any = None) -> DFGNode:
        node = DFGNode(id=self._next_id, name=name, type=t,
                       ast_node=ast_node,
                       line=ast_node.line if ast_node else 0,
                       col=ast_node.col  if ast_node else 0,
                       value=value)
        self._next_id += 1
        return node

    def new_node(self, name: str, t: DFGNodeType,
                 ast_node: Optional[ASTNode] = None,
                 value: Any = None) -> DFGNode:
        """Crea un nodo con nombre único (nunca reutiliza)."""
        node = self._mk(name, t, ast_node, value)
        # Si el nombre ya existe, almacena con sufijo numérico interno
        key = name if name not in self.nodes else f"{name}#{node.id}"
        self.nodes[key] = node
        return node

    def get_or_create(self, name: str, t: DFGNodeType,
                      ast_node: Optional[ASTNode] = None,
                      value: Any = None) -> DFGNode:
        """Reutiliza el nodo si el nombre ya existe (para variables)."""
        if name in self.nodes:
            return self.nodes[name]
        node = self._mk(name, t, ast_node, value)
        self.nodes[name] = node
        return node

    def update_var(self, name: str, t: DFGNodeType,
                   ast_node: Optional[ASTNode] = None) -> DFGNode:
        """
        Crea una nueva versión del nodo de variable (SSA-lite):
        la versión anterior queda en el grafo; la nueva se almacena
        bajo el mismo nombre (shadow). Útil para aug-assign.
        """
        old = self.nodes.get(name)
        node = self._mk(name, t, ast_node)
        # Guardar con sufijo para no perder el nodo anterior
        key = f"{name}#{node.id}"
        self.nodes[key] = node
        self.nodes[name] = node   # nueva versión canónica
        return node, old

    # ── Aristas ───────────────────────────────────────────────────────────────

    def add_edge(self, src: DFGNode, dst: DFGNode, label: str = ""):
        if src is None or dst is None or src is dst:
            return
        if dst not in src.outgoing:
            src.outgoing.append(dst)
            dst.incoming.append(src)
            self.edges.append(DataFlow(source=src, target=dst, label=label))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def get_all_paths(self, source_name: str, target_name: str
                      ) -> List[List[DFGNode]]:
        src = self.nodes.get(source_name)
        dst = self.nodes.get(target_name)
        if not src or not dst:
            return []
        paths, path, visited = [], [src], set()
        def dfs(n: DFGNode):
            if n == dst:
                paths.append(path[:]); return
            visited.add(n.id)
            for s in n.outgoing:
                if s.id not in visited:
                    path.append(s); dfs(s); path.pop()
            visited.remove(n.id)
        dfs(src)
        return paths

    def __repr__(self) -> str:
        lines = [f"DFG({len(self.nodes)} nodes, {len(self.edges)} edges)"]
        for name, node in self.nodes.items():
            outs = [n.name for n in node.outgoing]
            lines.append(f"  [{node.id}] {node.type.name:15} {name!r:35} → {outs}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Builder
# ──────────────────────────────────────────────────────────────────────────────

class DFGBuilder:
    """
    Construye el DFG a partir de un Module del parser.

    Uso:
        dfg = DFGBuilder().build(module)
    """

    def __init__(self):
        self.dfg: Optional[DFG] = None
        # scope stack: cada entrada es un dict nombre→DFGNode
        self._scope_stack: List[Dict[str, DFGNode]] = []

    # ── Punto de entrada ──────────────────────────────────────────────────────

    def build(self, module: Module) -> DFG:
        self.dfg = DFG()
        self._scope_stack = [{}]
        for stmt in module.body:
            self._build_stmt(stmt)
        return self.dfg

    # ── Scope helpers ─────────────────────────────────────────────────────────

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

    # ── Dispatch de sentencias ────────────────────────────────────────────────

    def _build_stmt(self, stmt: ASTNode):
        if isinstance(stmt, AssignStatement):    self._build_assign(stmt)
        elif isinstance(stmt, AugAssignStatement): self._build_augassign(stmt)
        elif isinstance(stmt, ExprStatement):    self._build_expr_stmt(stmt)
        elif isinstance(stmt, IfStatement):      self._build_if(stmt)
        elif isinstance(stmt, WhileStatement):   self._build_while(stmt)
        elif isinstance(stmt, ForStatement):     self._build_for(stmt)
        elif isinstance(stmt, FunctionDef):      self._build_function(stmt)
        elif isinstance(stmt, ImportStatement):  pass  # no genera nodos DFG

    # ── Asignación ────────────────────────────────────────────────────────────

    def _build_assign(self, stmt: AssignStatement):
        val_node = self._build_expr(stmt.value)
        for target in stmt.targets:
            name = self._var_name(target)
            if not name:
                continue
            var = self.dfg.get_or_create(name, DFGNodeType.VARIABLE, ast_node=target)
            self.dfg.add_edge(val_node, var, label="assign")
            self._define(name, var)

    # ── Asignación aumentada ──────────────────────────────────────────────────

    def _build_augassign(self, stmt: AugAssignStatement):
        """
        x += expr  →  nuevo nodo OPERATOR que recibe la versión anterior de x
        y el valor de la expresión, y cuyo resultado es la nueva versión de x.
        """
        name = self._var_name(stmt.target)
        val_node = self._build_expr(stmt.value)
        prev_var = self._lookup(name) if name else None

        op_node = self.dfg.new_node(
            f"_augop_{stmt.op}_{id(stmt)}",
            DFGNodeType.OPERATOR,
            ast_node=stmt,
        )
        self.dfg.add_edge(prev_var,  op_node, label="lhs")
        self.dfg.add_edge(val_node,  op_node, label="rhs")

        if name:
            new_var = self.dfg.new_node(name, DFGNodeType.VARIABLE, ast_node=stmt.target)
            self.dfg.add_edge(op_node, new_var, label="result")
            self._define(name, new_var)

    # ── Expresión como sentencia ──────────────────────────────────────────────

    def _build_expr_stmt(self, stmt: ExprStatement):
        if stmt.expression:
            self._build_expr(stmt.expression)

    # ── Sentencias de control ─────────────────────────────────────────────────

    def _build_if(self, stmt: IfStatement):
        self._build_expr(stmt.condition)
        for s in stmt.then_body:  self._build_stmt(s)
        for s in stmt.else_body:  self._build_stmt(s)
        for ec in stmt.elif_clauses:
            self._build_expr(ec.condition)
            for s in ec.body: self._build_stmt(s)

    def _build_while(self, stmt: WhileStatement):
        self._build_expr(stmt.condition)
        for s in stmt.body: self._build_stmt(s)

    def _build_for(self, stmt: ForStatement):
        iter_node = self._build_expr(stmt.iter)
        name = self._var_name(stmt.target)
        if name:
            var = self.dfg.get_or_create(name, DFGNodeType.VARIABLE, ast_node=stmt.target)
            self.dfg.add_edge(iter_node, var, label="iter")
            self._define(name, var)
        for s in stmt.body: self._build_stmt(s)

    def _build_function(self, stmt: FunctionDef):
        self._push_scope()
        # Parámetros como nodos PARAMETER
        for param in stmt.params:
            pnode = self.dfg.new_node(
                param.name, DFGNodeType.PARAMETER,
                ast_node=param,
            )
            self._define(param.name, pnode)
        for s in stmt.body:
            self._build_stmt(s)
        self._pop_scope()

    # ── Expresiones ───────────────────────────────────────────────────────────

    def _build_expr(self, expr: Optional[ASTNode]) -> Optional[DFGNode]:
        if expr is None:
            return None

        # ── Literal ───────────────────────────────────────────────────────────
        if isinstance(expr, Literal):
            key = f"_lit_{id(expr)}"
            return self.dfg.new_node(key, DFGNodeType.CONSTANT,
                                     ast_node=expr, value=expr.value)

        # ── Nombre (variable) ─────────────────────────────────────────────────
        if isinstance(expr, Name):
            existing = self._lookup(expr.name)
            if existing:
                return existing
            t = DFGNodeType.SOURCE if expr.name in _SOURCES else DFGNodeType.VARIABLE
            node = self.dfg.get_or_create(expr.name, t, ast_node=expr)
            self._define(expr.name, node)
            return node

        # ── Atributo: obj.attr ────────────────────────────────────────────────
        if isinstance(expr, Attribute):
            return self._build_attribute(expr)

        # ── Índice: obj[key] ──────────────────────────────────────────────────
        if isinstance(expr, Subscript):
            obj = self._build_expr(expr.obj)
            self._build_expr(expr.key)   # key también puede ser tainted
            return obj

        # ── Llamada a función ─────────────────────────────────────────────────
        if isinstance(expr, FCall):
            return self._build_fcall(expr)

        # ── Operación binaria ─────────────────────────────────────────────────
        if isinstance(expr, BinaryOp):
            return self._build_binop(expr)

        # ── F-string ──────────────────────────────────────────────────────────
        if isinstance(expr, JoinedStr):
            return self._build_joinedstr(expr)

        # ── Printf-style: fmt % args ──────────────────────────────────────────
        if isinstance(expr, PercentFormat):
            return self._build_percentformat(expr)

        # ── Unario ────────────────────────────────────────────────────────────
        if isinstance(expr, UnaryOp):
            return self._build_expr(expr.operand)

        # ── BoolOp (and / or) ─────────────────────────────────────────────────
        if isinstance(expr, BoolOp):
            nodes = [self._build_expr(v) for v in expr.values]
            nodes = [n for n in nodes if n]
            if not nodes:
                return None
            # El resultado es un nodo que recibe todos los operandos
            op = self.dfg.new_node(f"_boolop_{id(expr)}",
                                   DFGNodeType.OPERATOR, ast_node=expr)
            for n in nodes:
                self.dfg.add_edge(n, op)
            return op

        # ── Compare ───────────────────────────────────────────────────────────
        if isinstance(expr, Compare):
            left = self._build_expr(expr.left)
            for c in expr.comparators:
                self._build_expr(c)
            return left

        # ── Tupla / lista ─────────────────────────────────────────────────────
        if isinstance(expr, (Tuple, PyList)):
            elems = [self._build_expr(e) for e in expr.elements]
            elems = [e for e in elems if e]
            if not elems:
                return self.dfg.new_node(f"_empty_{id(expr)}",
                                         DFGNodeType.CONSTANT, ast_node=expr)
            tup = self.dfg.new_node(f"_tuple_{id(expr)}",
                                    DFGNodeType.OPERATOR, ast_node=expr)
            for e in elems:
                self.dfg.add_edge(e, tup)
            return tup

        return None

    # ── Helpers de expresión ──────────────────────────────────────────────────

    def _build_attribute(self, expr: Attribute) -> DFGNode:
        """
        Construye la cadena request → request.args → request.args.get
        como nodos separados con aristas entre ellos.
        El nombre canónico es el atributo completo: "request.args.get".
        """
        obj_node = self._build_expr(expr.obj)
        full_name = (f"{obj_node.name}.{expr.attr}"
                     if obj_node and not obj_node.name.startswith("_")
                     else expr.attr)

        existing = self._lookup(full_name)
        if existing:
            return existing

        t = DFGNodeType.SOURCE if full_name in _SOURCES else DFGNodeType.VARIABLE
        attr_node = self.dfg.get_or_create(full_name, t, ast_node=expr)
        self.dfg.add_edge(obj_node, attr_node, label="attr")
        self._define(full_name, attr_node)
        return attr_node

    def _build_fcall(self, expr: FCall) -> DFGNode:
        """
        func(arg1, arg2, …)

        Estructura DFG:
          arg_i  →  FUNCTION_CALL_node  →  (asignado a variable destino)
          func_name_node  →  FUNCTION_CALL_node

        El nodo FUNCTION_CALL representa el *valor de retorno*.
        Se clasifica como SOURCE si la función es una fuente conocida.
        """
        func_node = self._build_expr(expr.func)

        # Nombre de la función para clasificación
        func_name = func_node.name if func_node else ""
        # Quitar prefijo de objeto: "cursor.execute" → "execute"
        method_name = func_name.split(".")[-1] if "." in func_name else func_name

        is_source    = func_name in _SOURCES
        is_sink      = method_name in _SINK_METHODS
        is_sanitizer = func_name in _SANITIZERS or method_name in _SANITIZERS

        if is_sink:
            node_type = DFGNodeType.SINK
        elif is_source:
            node_type = DFGNodeType.SOURCE
        else:
            node_type = DFGNodeType.FUNCTION_CALL

        call_node = self.dfg.new_node(
            f"_call_{func_name}_{id(expr)}",
            node_type,
            ast_node=expr,
        )
        call_node.value = func_name   # útil para el visualizador

        # func → call (quién ejecuta la llamada)
        self.dfg.add_edge(func_node, call_node, label="func")

        # args → call (qué datos entran)
        for i, arg in enumerate(expr.args):
            arg_node = self._build_expr(arg)
            self.dfg.add_edge(arg_node, call_node, label=f"arg{i}")

        # kwargs → call
        for kw in expr.keywords:
            kw_node = self._build_expr(kw.value)
            self.dfg.add_edge(kw_node, call_node, label=f"kw:{kw.key}")

        return call_node

    def _build_binop(self, expr: BinaryOp) -> DFGNode:
        left  = self._build_expr(expr.left)
        right = self._build_expr(expr.right)
        op    = self.dfg.new_node(
            f"_binop_{expr.op}_{id(expr)}",
            DFGNodeType.OPERATOR,
            ast_node=expr,
        )
        op.value = expr.op
        self.dfg.add_edge(left,  op, label="left")
        self.dfg.add_edge(right, op, label="right")
        return op

    def _build_joinedstr(self, expr: JoinedStr) -> DFGNode:
        """
        f"texto {var} texto"
        Crea un nodo OPERATOR que recibe todos los FormattedValue.
        """
        join_node = self.dfg.new_node(
            f"_fstring_{id(expr)}",
            DFGNodeType.OPERATOR,
            ast_node=expr,
        )
        join_node.value = "f-string"
        for part in expr.values:
            if isinstance(part, FormattedValue):
                pnode = self._build_expr(part.value)
                self.dfg.add_edge(pnode, join_node, label="fmt")
        return join_node

    def _build_percentformat(self, expr: PercentFormat) -> DFGNode:
        """
        "…%s…" % (val,)
        El nodo OPERATOR recibe la cadena de formato y los argumentos.
        """
        fmt_node  = self._build_expr(expr.left)
        args_node = self._build_expr(expr.right)
        op = self.dfg.new_node(
            f"_pctfmt_{id(expr)}",
            DFGNodeType.OPERATOR,
            ast_node=expr,
        )
        op.value = "%-format"
        self.dfg.add_edge(fmt_node,  op, label="fmt")
        self.dfg.add_edge(args_node, op, label="args")
        return op

    # ── Nombre de variable ────────────────────────────────────────────────────

    def _var_name(self, node: ASTNode) -> Optional[str]:
        if isinstance(node, Name):      return node.name
        if isinstance(node, Attribute):
            base = self._var_name(node.obj)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, Subscript): return self._var_name(node.obj)
        return None
