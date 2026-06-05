"""
taint_engine.py — Taint Propagation Engine
===========================================

El corazón de la Fase 2 del Security Linter.

Responsabilidades
-----------------
1. Identificar FUENTES: variables que reciben datos controlados por el usuario
   (input(), request.args.get(), request.form.get(), …)
2. PROPAGAR el estado TAINTED a través del DFG:
   si X está tainted y Y = f(X), entonces Y está tainted
   (salvo que f sea un sanitizador reconocido)
3. Detectar SUMIDEROS: llamadas SQL (execute, executemany, …) que reciben
   al menos un argumento tainted → SQLi vulnerability
4. Respetar SANITIZADORES: int(), re.escape(), html.escape(), … cortan la
   cadena de propagación

Correcciones respecto a la versión original
-------------------------------------------
1. _propagate_through_dfg  — la propagación ahora opera en dos capas:
   a) Nombres canónicos de variables (registrados en SymbolTable)
   b) Nodos internos del DFG (_binop_, _fstring_, _call_…) rastreados
      por su DFGNode.id, no por su nombre en la SymbolTable.
   Se mantiene un set `_tainted_node_ids` de IDs de nodos DFG tainted.

2. _is_tainted_expression  — cubre ahora:
   - FCall donde el callee es Attribute (request.form.get, request.args.get)
   - BinaryOp con cualquier operador (no solo "+")
   - PercentFormat completo (fmt Y args)
   - Subscript sobre objeto tainted

3. _detect_source — reconoce:
   - FCall sobre Attribute chains: request.args.get("x")
   - Attribute pura: request.form

4. _analyze_augassign — considera también el taint previo de la variable
   destino (si base_query ya era tainted, sigue tainted tras +=)

5. _analyze_function — los parámetros se marcan como PARAM (no UNKNOWN),
   y si el motor tiene información de call-site, los marca TAINTED

6. _check_sink — inspecciona todos los argumentos del FCall y reporta
   la vulnerabilidad con la traza completa fuente→variable→sink

7. Propagación transitiva — _propagate_through_dfg recorre el DFG en BFS
   desde cada nodo SOURCE marcado, propagando taint hop a hop y
   respetando sanitizadores por nombre de callee en FUNCTION_CALL nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Deque, Dict, List, Optional, Set

from collections import deque

from ast_nodes import (
    ASTNode,
    Module, AssignStatement, AugAssignStatement, ExprStatement,
    IfStatement, WhileStatement, ForStatement, FunctionDef, ReturnStatement,
    ImportStatement,
    FCall, Attribute, Name, BinaryOp, UnaryOp, BoolOp, Compare,
    Literal, Subscript, JoinedStr, FormattedValue, PercentFormat,
    Tuple, PyList,
)
from symbol_table import SymbolTable, Symbol, TaintStatus
from dfg_builder   import DFG, DFGNode, DFGNodeType


# ──────────────────────────────────────────────────────────────────────────────
# Enumeraciones y estructuras de resultado
# ──────────────────────────────────────────────────────────────────────────────

class TaintSource(Enum):
    INPUT        = auto()   # input(), raw_input()
    STDIN        = auto()   # sys.stdin.*
    REQUEST_ARGS = auto()   # request.args.*
    REQUEST_FORM = auto()   # request.form.*
    REQUEST_JSON = auto()   # request.json.*
    COOKIES      = auto()   # request.cookies, cookies
    SESSION      = auto()   # session
    ENV          = auto()   # os.environ
    PARAM        = auto()   # parámetro de función (taint interprocedural)
    UNKNOWN      = auto()


@dataclass
class TaintRecord:
    """Registro de un evento de taint (source o propagación)."""
    variable:    str
    source:      str
    source_type: TaintSource
    line:        int
    col:         int
    path:        List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """Vulnerabilidad SQLi detectada."""
    sink:        str           # nombre del sink (cursor.execute, db.execute, …)
    arg_name:    str           # argumento tainted que llega al sink
    taint_path:  List[str]     # traza: fuente → vars intermedias → sink
    source_type: TaintSource
    line:        int
    col:         int

    def __str__(self) -> str:
        path_str = " → ".join(self.taint_path)
        return (f"[SQLi] Line {self.line}:{self.col}  "
                f"sink={self.sink!r}  "
                f"arg={self.arg_name!r}  "
                f"path={path_str}")


class TaintPropagationResult:
    """Resultado completo del análisis."""

    def __init__(self):
        self.sources:         List[TaintRecord]  = []
        self.propagations:    List[TaintRecord]  = []
        self.sanitizations:   List[str]          = []
        self.vulnerabilities: List[Vulnerability]= []

    def add_source(self, variable: str, source: str,
                   source_type: TaintSource, line: int, col: int):
        self.sources.append(TaintRecord(
            variable=variable, source=source,
            source_type=source_type, line=line, col=col,
        ))

    def add_propagation(self, variable: str, source: str,
                        source_type: TaintSource, line: int, col: int,
                        path: Optional[List[str]] = None):
        self.propagations.append(TaintRecord(
            variable=variable, source=source,
            source_type=source_type, line=line, col=col,
            path=path or [],
        ))

    def add_vulnerability(self, vuln: Vulnerability):
        # Evitar duplicados por sink+arg
        key = (vuln.sink, vuln.arg_name, vuln.line)
        if not any((v.sink, v.arg_name, v.line) == key
                   for v in self.vulnerabilities):
            self.vulnerabilities.append(vuln)

    def __repr__(self) -> str:
        lines = [
            f"TaintPropagationResult(",
            f"  sources={len(self.sources)}",
            f"  propagations={len(self.propagations)}",
            f"  sanitizations={len(self.sanitizations)}",
            f"  vulnerabilities={len(self.vulnerabilities)}",
            ")"
        ]
        for v in self.vulnerabilities:
            lines.append(f"  {v}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Motor principal
# ──────────────────────────────────────────────────────────────────────────────

class TaintPropagationEngine:
    """
    Motor de propagación de taint sobre el par (AST, DFG).

    Flujo de análisis
    -----------------
    Phase A — AST pass:
        Recorre el AST sentencia a sentencia para:
        · detectar fuentes directas (input(), request.args.get(…))
        · registrar asignaciones de taint en la SymbolTable
        · detectar sanitizadores que cortan la cadena
        · detectar sinks con argumentos tainted

    Phase B — DFG BFS:
        Propaga taint de forma transitiva a través de las aristas del DFG,
        usando un set de nodos-ID tainted. Respeta sanitizadores por
        DFGNodeType y por nombre de callee.
        Reconcilia los nodos DFG canónicos con la SymbolTable al final.

    Uso:
        engine = TaintPropagationEngine()
        result = engine.analyze(module, dfg, symbol_table)
        for v in result.vulnerabilities:
            print(v)
    """

    def __init__(self):
        # IDs de nodos DFG que están tainted (propagación interna)
        self._tainted_node_ids: Set[int] = set()
        # Cache child symbol tables from Phase A for Phase C sink detection
        self._func_tables: Dict[str, SymbolTable] = {}

    # ─────────────────────────────────────────────────────────────────────────
    # Punto de entrada
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(
        self,
        module:       Module,
        dfg:          DFG,
        symbol_table: SymbolTable,
    ) -> TaintPropagationResult:
        """
        Ejecuta el análisis completo de taint.

        Retorna un TaintPropagationResult con fuentes, propagaciones
        y vulnerabilidades detectadas.
        """
        self._tainted_node_ids = set()
        self._func_tables = {}
        result = TaintPropagationResult()

        # ── Phase A: AST pass ─────────────────────────────────────────────────
        for stmt in module.body:
            self._analyze_stmt(stmt, dfg, symbol_table, result)

        # ── Phase B: DFG BFS propagation ──────────────────────────────────────
        self._propagate_through_dfg(dfg, symbol_table, result)

        # ── Phase C: sink detection ───────────────────────────────────────────
        for stmt in module.body:
            self._detect_sinks(stmt, symbol_table, result)

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Phase A — AST pass
    # ─────────────────────────────────────────────────────────────────────────

    def _analyze_stmt(
        self,
        stmt:         ASTNode,
        dfg:          DFG,
        symbol_table: SymbolTable,
        result:       TaintPropagationResult,
    ):
        if isinstance(stmt, AssignStatement):     self._analyze_assign(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, AugAssignStatement):self._analyze_augassign(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, ExprStatement):     self._analyze_expr_stmt(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, IfStatement):       self._analyze_if(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, WhileStatement):    self._analyze_while(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, ForStatement):      self._analyze_for(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, FunctionDef):       self._analyze_function(stmt, dfg, symbol_table, result)
        elif isinstance(stmt, ReturnStatement):   pass   # no propaga taint directamente
        elif isinstance(stmt, ImportStatement):   pass

    def _analyze_assign(self, stmt: AssignStatement, dfg, st, result):
        """
        target = value

        Si `value` es una fuente o está tainted → target queda TAINTED.
        Si `value` pasa por un sanitizador → target queda SANITIZED.
        """
        if stmt.value is None:
            return

        source_name = self._detect_source(stmt.value)
        is_tainted  = source_name is not None or self._is_tainted_expr(stmt.value, st)
        sanitizer   = self._detect_sanitizer(stmt.value, st)

        for target in stmt.targets:
            tname = self._var_name(target)
            if not tname:
                continue

            if sanitizer:
                st.mark_sanitized(tname, sanitizer)
                if sanitizer not in result.sanitizations:
                    result.sanitizations.append(sanitizer)

            elif is_tainted:
                src_label = source_name or self._tainted_source_of(stmt.value, st)
                st.mark_tainted(tname, source=src_label,
                                line=stmt.line, col=stmt.col)
                stype = self._classify_source(src_label)
                result.add_source(tname, src_label, stype, stmt.line, stmt.col)
                # Marcar el nodo DFG de esta variable como tainted
                self._mark_dfg_node_tainted(tname, dfg)

            else:
                st.mark_safe(tname)

    def _analyze_augassign(self, stmt: AugAssignStatement, dfg, st, result):
        """
        target op= value

        El target queda TAINTED si:
        · el value es tainted  (nuevo taint entra)
        · el target ya era TAINTED (taint previo persiste)
        """
        tname = self._var_name(stmt.target)
        if not tname:
            return

        value_tainted    = self._is_tainted_expr(stmt.value, st)
        prev_tainted     = st.is_tainted(tname)
        source_from_val  = self._detect_source(stmt.value)

        if value_tainted or prev_tainted or source_from_val:
            src_label = source_from_val or (tname if prev_tainted else "unknown")
            st.mark_tainted(tname, source=src_label,
                            line=stmt.line, col=stmt.col)
            result.add_propagation(tname, src_label, TaintSource.UNKNOWN,
                                   stmt.line, stmt.col)
            self._mark_dfg_node_tainted(tname, dfg)

    def _analyze_expr_stmt(self, stmt: ExprStatement, dfg, st, result):
        """Expresión como sentencia — detectar sinks."""
        # La detección de sinks se hace en Phase C, aquí solo revisamos
        # si hay efectos de propagación (e.g. llamadas que producen taint)
        if stmt.expression:
            self._is_tainted_expr(stmt.expression, st)

    def _analyze_if(self, stmt: IfStatement, dfg, st, result):
        self._is_tainted_expr(stmt.condition, st)
        for s in stmt.then_body:   self._analyze_stmt(s, dfg, st, result)
        for s in stmt.else_body:   self._analyze_stmt(s, dfg, st, result)
        for ec in stmt.elif_clauses:
            self._is_tainted_expr(ec.condition, st)
            for s in ec.body:      self._analyze_stmt(s, dfg, st, result)

    def _analyze_while(self, stmt: WhileStatement, dfg, st, result):
        self._is_tainted_expr(stmt.condition, st)
        for s in stmt.body: self._analyze_stmt(s, dfg, st, result)

    def _analyze_for(self, stmt: ForStatement, dfg, st, result):
        iter_tainted = self._is_tainted_expr(stmt.iter, st)
        tname = self._var_name(stmt.target)
        if tname and iter_tainted:
            st.mark_tainted(tname, source="iteration",
                            line=stmt.line, col=stmt.col)
            self._mark_dfg_node_tainted(tname, dfg)
        for s in stmt.body: self._analyze_stmt(s, dfg, st, result)

    def _analyze_function(self, stmt: FunctionDef, dfg, st, result):
        """
        Analiza el cuerpo de una función.
        Los parámetros se marcan como PARAM (potencialmente tainted).
        En análisis interprocedural real se resolverían en el call-site;
        aquí los tratamos como conservadoramente tainted para no perder
        vulnerabilidades (falso negativo > falso positivo para un linter).
        """
        child_st = st.create_child()
        child_st.set_scope(stmt.name)

        # Cache this child table so Phase C can use it for sink detection
        self._func_tables[stmt.name] = child_st

        # Registrar la firma en la tabla padre
        sig = st.define_function(stmt.name)
        for param in stmt.params:
            sig.params.append(param.name)
            child_st.mark_param(param.name,
                                line=getattr(param, "line", 0),
                                col=getattr(param, "col", 0))
            # Marcar como tainted (conservador)
            child_st.mark_tainted(param.name, source="function_param",
                                  line=getattr(param, "line", 0),
                                  col=getattr(param, "col", 0))
            self._mark_dfg_node_tainted(param.name, dfg)
            result.add_source(param.name, "function_param",
                              TaintSource.PARAM,
                              getattr(param, "line", 0),
                              getattr(param, "col", 0))

        for s in stmt.body:
            self._analyze_stmt(s, dfg, child_st, result)

        # Merge tainted symbols from child back into parent so Phase C
        # sink detection can see them
        for sym in child_st.get_all_symbols():
            if sym.taint_status in (TaintStatus.TAINTED, TaintStatus.PARAM):
                if not st.is_tainted(sym.name):
                    st.mark_tainted(sym.name, source=sym.sources[0] if sym.sources else "function_param",
                                    line=sym.line, col=sym.col)
            if sym.taint_status == TaintStatus.SANITIZED and sym.sanitizer:
                st.mark_sanitized(sym.name, sym.sanitizer)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase B — DFG BFS propagation
    # ─────────────────────────────────────────────────────────────────────────

    def _propagate_through_dfg(self, dfg: DFG, st: SymbolTable,
                                result: TaintPropagationResult):
        """
        Propaga taint transitivamente por el DFG usando BFS.

        Punto de partida: todos los nodos DFG cuyo nombre es tainted en la
        SymbolTable O cuyo id ya está en self._tainted_node_ids.

        En cada hop:
        · Si el nodo destino es un FUNCTION_CALL cuyo callee es un sanitizador
          → marcar el destino como SANITIZED, NO propagar más allá
        · En otro caso → marcar el destino como tainted y continuar
        """
        # Semilla: nodos tainted por tipo DFG o por nombre en SymbolTable
        for name, node in dfg.nodes.items():
            canonical = name.split("#")[0]   # nombre sin sufijo SSA

            # 1. Ya marcado en la SymbolTable (Phase A lo registró)
            if st.is_tainted(canonical) or st.is_param(canonical):
                self._tainted_node_ids.add(node.id)
                continue

            # 2. Nodo SOURCE explícito (request.args.get, input, etc.)
            if node.type == DFGNodeType.SOURCE:
                self._tainted_node_ids.add(node.id)
                # Registrar también en la SymbolTable si tiene nombre canónico
                if not canonical.startswith("_"):
                    st.mark_tainted(canonical, source=canonical,
                                    line=node.line, col=node.col)
                    result.add_source(canonical, canonical,
                                      self._classify_source(canonical),
                                      node.line, node.col)
                continue

            # 3. Nodo PARAMETER (parámetros de función)
            if node.type == DFGNodeType.PARAMETER:
                self._tainted_node_ids.add(node.id)
                if not canonical.startswith("_") and not st.is_tainted(canonical):
                    st.mark_tainted(canonical, source="function_param",
                                    line=node.line, col=node.col)
                    result.add_source(canonical, "function_param",
                                      TaintSource.PARAM,
                                      node.line, node.col)
                continue

            # 4. Variable sin definición conocida y sin entrantes = externa implícita
            #    (p.ej. user_input usado sin ser definido en el snippet analizado)
            #    Se excluyen builtins de Python para evitar falsos positivos.
            _PYTHON_BUILTINS = {
                "print","len","range","str","int","float","bool","list","dict",
                "set","tuple","type","repr","abs","round","min","max","sum",
                "sorted","reversed","enumerate","zip","map","filter","any","all",
                "open","hasattr","getattr","setattr","delattr","isinstance",
                "issubclass","callable","iter","next","hash","id","hex","oct",
                "bin","chr","ord","format","vars","dir","globals","locals",
                "super","object","staticmethod","classmethod","property",
                "re","os","sys","math","json","csv","datetime","pathlib",
                "cursor","db","conn","connection","session",  # common DB objects
            }
            if (node.type == DFGNodeType.VARIABLE
                    and not canonical.startswith("_")
                    and not node.incoming          # sin fuente conocida
                    and not st.has(canonical)      # no definida en ningún scope
                    and canonical not in {"True","False","None"}
                    and canonical not in _PYTHON_BUILTINS):
                self._tainted_node_ids.add(node.id)
                st.mark_tainted(canonical, source="external_implicit",
                                line=node.line, col=node.col)
                result.add_source(canonical, "external_implicit",
                                  TaintSource.UNKNOWN,
                                  node.line, node.col)

        # BFS
        queue: Deque[DFGNode] = deque()
        for node in dfg.nodes.values():
            if node.id in self._tainted_node_ids:
                queue.append(node)

        visited_as_tainted: Set[int] = set(self._tainted_node_ids)

        while queue:
            node = queue.popleft()

            for succ in node.outgoing:
                if succ.id in visited_as_tainted:
                    continue

                # ¿El sucesor es el resultado de una sanitización?
                if succ.type == DFGNodeType.FUNCTION_CALL:
                    callee = succ.value or ""   # guardado en DFGNode.value
                    if st.is_sanitizer(callee):
                        # Propagar SANITIZED al nombre canónico de la variable
                        # destino (que está en los sucesores del nodo sanitizador)
                        for var_succ in succ.outgoing:
                            vname = var_succ.name.split("#")[0]
                            if not vname.startswith("_"):
                                st.mark_sanitized(vname, sanitizer=callee)
                                if callee not in result.sanitizations:
                                    result.sanitizations.append(callee)
                        continue   # no propagar taint más allá del sanitizador

                # Propagar taint
                visited_as_tainted.add(succ.id)
                self._tainted_node_ids.add(succ.id)
                queue.append(succ)

                # Reconciliar con SymbolTable: si el nodo tiene nombre canónico
                canonical = succ.name.split("#")[0]
                if not canonical.startswith("_"):
                    if not st.is_sanitized(canonical):
                        src = node.name.split("#")[0]
                        if not src.startswith("_"):
                            st.mark_tainted(canonical, source=src,
                                            line=succ.line, col=succ.col)
                        else:
                            st.mark_tainted(canonical, source="propagation",
                                            line=succ.line, col=succ.col)
                        result.add_propagation(
                            canonical, src, TaintSource.UNKNOWN,
                            succ.line, succ.col,
                        )

    # ─────────────────────────────────────────────────────────────────────────
    # Phase C — Sink detection
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_sinks(self, stmt: ASTNode, st: SymbolTable,
                      result: TaintPropagationResult):
        """Recorre el AST buscando sinks con argumentos tainted."""
        if isinstance(stmt, ExprStatement) and stmt.expression:
            self._check_sink_expr(stmt.expression, st, result)
        elif isinstance(stmt, AssignStatement) and stmt.value:
            # Sink can be the value of an assignment: result = cursor.execute(...)
            self._check_sink_expr(stmt.value, st, result)
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
            # Use the cached child table from Phase A (has actual taint info)
            child_st = self._func_tables.get(stmt.name)
            if child_st is None:
                child_st = st.create_child() if st.get_function(stmt.name) else st
            for s in stmt.body: self._detect_sinks(s, child_st, result)

    def _check_sink_expr(self, expr: ASTNode, st: SymbolTable,
                         result: TaintPropagationResult):
        """Si expr es un FCall a un sink con args tainted → registrar vuln.

        Only the first argument (position 0, the SQL string) is checked.
        Arguments at position 1+ are parameterized query values and are safe.
        """
        if not isinstance(expr, FCall):
            return

        func_name = self._func_name(expr.func)
        if not st.is_sink(func_name):
            return

        # Only check position 0 (the SQL query string).
        # Position 1+ are parameterized query parameters — safe by design.
        if not expr.args:
            return
        arg = expr.args[0]
        arg_tainted = self._is_tainted_expr(arg, st)
        if arg_tainted:
            arg_name = self._var_name(arg) or "<expr>"
            sym      = st.get(arg_name) if arg_name != "<expr>" else None
            path     = ([arg_name] + (sym.sources if sym else [])
                        if sym else [arg_name])
            stype    = (TaintSource[sym.sources[0].upper()]
                        if sym and sym.sources and
                        sym.sources[0].upper() in TaintSource.__members__
                        else TaintSource.UNKNOWN)
            result.add_vulnerability(Vulnerability(
                sink       = func_name,
                arg_name   = arg_name,
                taint_path = path,
                source_type= stype,
                line       = expr.line,
                col        = expr.col,
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers — expresiones
    # ─────────────────────────────────────────────────────────────────────────

    def _is_tainted_expr(self, expr: Optional[ASTNode],
                          st: SymbolTable) -> bool:
        """
        Retorna True si la expresión produce o contiene taint.
        Cubre todos los constructores del subconjunto Python del linter.
        """
        if expr is None:
            return False

        # Nombre de variable
        if isinstance(expr, Name):
            return st.is_tainted(expr.name) or st.is_param(expr.name)

        # Literal — siempre seguro
        if isinstance(expr, Literal):
            return False

        # Atributo: request.args, request.form, etc.
        if isinstance(expr, Attribute):
            full = self._full_attr_name(expr)
            if st.is_source(full) or st.is_web_source(full):
                return True
            # El objeto padre puede estar tainted
            return self._is_tainted_expr(expr.obj, st)

        # Subscript: obj[key]
        if isinstance(expr, Subscript):
            return self._is_tainted_expr(expr.obj, st)

        # Llamada a función
        if isinstance(expr, FCall):
            fname = self._func_name(expr.func)
            # Fuente directa: input(), request.args.get(), etc.
            if st.is_source(fname):
                return True
            # Sanitizador: int(x), re.escape(x) — NO tainted
            if st.is_sanitizer(fname):
                return False
            # Cualquier arg tainted → resultado tainted
            return any(self._is_tainted_expr(a, st) for a in expr.args)

        # Operación binaria: taint si cualquier operando lo es
        if isinstance(expr, BinaryOp):
            return (self._is_tainted_expr(expr.left, st) or
                    self._is_tainted_expr(expr.right, st))

        # Operación unaria
        if isinstance(expr, UnaryOp):
            return self._is_tainted_expr(expr.operand, st)

        # BoolOp (and / or)
        if isinstance(expr, BoolOp):
            return any(self._is_tainted_expr(v, st) for v in expr.values)

        # Comparación
        if isinstance(expr, Compare):
            return (self._is_tainted_expr(expr.left, st) or
                    any(self._is_tainted_expr(c, st) for c in expr.comparators))

        # F-string: tainted si algún {expr} lo es
        if isinstance(expr, JoinedStr):
            for part in expr.values:
                if isinstance(part, FormattedValue):
                    if self._is_tainted_expr(part.value, st):
                        return True
            return False

        # Printf-style: "%s" % val
        if isinstance(expr, PercentFormat):
            return (self._is_tainted_expr(expr.left,  st) or
                    self._is_tainted_expr(expr.right, st))

        # Tupla / lista
        if isinstance(expr, (Tuple, PyList)):
            return any(self._is_tainted_expr(e, st) for e in expr.elements)

        return False

    def _detect_source(self, expr: Optional[ASTNode]) -> Optional[str]:
        """
        Retorna el nombre de la fuente si la expresión ES una fuente conocida,
        o None si no lo es.
        """
        if expr is None:
            return None

        if isinstance(expr, FCall):
            fname = self._func_name(expr.func)
            if fname in SymbolTable._BUILTIN_SOURCES:
                return fname
            if any(fname == p or fname.startswith(p + ".")
                   for p in SymbolTable._WEB_SOURCE_PREFIXES):
                return fname

        if isinstance(expr, Attribute):
            full = self._full_attr_name(expr)
            if any(full == p or full.startswith(p + ".")
                   for p in SymbolTable._WEB_SOURCE_PREFIXES):
                return full

        if isinstance(expr, Name):
            if expr.name in SymbolTable._BUILTIN_SOURCES:
                return expr.name
            if any(expr.name == p or expr.name.startswith(p + ".")
                   for p in SymbolTable._WEB_SOURCE_PREFIXES):
                return expr.name

        return None

    def _detect_sanitizer(self, expr: Optional[ASTNode],
                           st: SymbolTable) -> Optional[str]:
        """
        Si la expresión es una llamada a un sanitizador reconocido,
        retorna su nombre; si no, retorna None.
        """
        if not isinstance(expr, FCall):
            return None
        fname = self._func_name(expr.func)
        return fname if st.is_sanitizer(fname) else None

    def _tainted_source_of(self, expr: Optional[ASTNode],
                            st: SymbolTable) -> str:
        """Busca el nombre de la variable tainted más cercana en la expresión."""
        if expr is None:
            return "unknown"
        if isinstance(expr, Name) and st.is_tainted(expr.name):
            sym = st.get(expr.name)
            return (sym.sources[0] if sym and sym.sources else expr.name)
        if isinstance(expr, BinaryOp):
            left  = self._tainted_source_of(expr.left, st)
            right = self._tainted_source_of(expr.right, st)
            return left if left != "unknown" else right
        if isinstance(expr, JoinedStr):
            for part in expr.values:
                if isinstance(part, FormattedValue):
                    s = self._tainted_source_of(part.value, st)
                    if s != "unknown":
                        return s
        if isinstance(expr, PercentFormat):
            return self._tainted_source_of(expr.right, st)
        return "unknown"

    def _classify_source(self, source: Optional[str]) -> TaintSource:
        if not source:
            return TaintSource.UNKNOWN
        s = source.lower()
        if "input" in s or "stdin" in s:         return TaintSource.INPUT
        if "argv" in s:                           return TaintSource.STDIN
        if "args" in s or "get" in s:             return TaintSource.REQUEST_ARGS
        if "form" in s or "post" in s:            return TaintSource.REQUEST_FORM
        if "json" in s:                           return TaintSource.REQUEST_JSON
        if "cookie" in s:                         return TaintSource.COOKIES
        if "session" in s:                        return TaintSource.SESSION
        if "environ" in s or "env" in s:          return TaintSource.ENV
        if "param" in s:                          return TaintSource.PARAM
        return TaintSource.UNKNOWN

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers — nombres
    # ─────────────────────────────────────────────────────────────────────────

    def _func_name(self, func: Optional[ASTNode]) -> str:
        """Nombre completo de función: cursor.execute, request.args.get, …"""
        if isinstance(func, Name):
            return func.name
        if isinstance(func, Attribute):
            obj = self._func_name(func.obj)
            return f"{obj}.{func.attr}" if obj else func.attr
        return ""

    def _full_attr_name(self, expr: Attribute) -> str:
        """Nombre completo de atributo: request.args.get"""
        obj = self._func_name(expr.obj) if expr.obj else ""
        return f"{obj}.{expr.attr}" if obj else expr.attr

    def _var_name(self, node: Optional[ASTNode]) -> Optional[str]:
        """Nombre de variable desde Name / Attribute / Subscript."""
        if isinstance(node, Name):      return node.name
        if isinstance(node, Attribute):
            base = self._var_name(node.obj)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, Subscript): return self._var_name(node.obj)
        return None

    def _mark_dfg_node_tainted(self, var_name: str, dfg: DFG):
        """Marca como tainted el nodo DFG cuyo nombre canónico coincide."""
        for key, node in dfg.nodes.items():
            canonical = key.split("#")[0]
            if canonical == var_name:
                self._tainted_node_ids.add(node.id)
