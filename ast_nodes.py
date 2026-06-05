"""
ast_nodes.py — Nodos del Árbol Sintáctico Abstracto (AST)
==========================================================

Subconjunto de Python orientado a detección de SQLi.
Cada nodo almacena línea y columna para reportes precisos.

Jerarquía:
  ASTNode (base)
  ├── Statements
  │   ├── Module              (raíz del archivo)
  │   ├── AssignStatement     (x = expr)
  │   ├── AugAssignStatement  (x += expr)
  │   ├── ExprStatement       (llamada suelta, etc.)
  │   ├── IfStatement
  │   ├── WhileStatement
  │   ├── ForStatement
  │   ├── FunctionDef
  │   ├── ReturnStatement
  │   └── ImportStatement
  └── Expressions
      ├── Literal             (str, int, float, bool, None)
      ├── Name                (identificador / variable)
      ├── BinaryOp            (+, -, *, /, %, ==, !=, <, >, and, or, ...)
      ├── UnaryOp             (not, -)
      ├── BoolOp              (and / or con N operandos)
      ├── Compare             (a < b < c, encadenados)
      ├── FCall               (func(args, kw=val))
      ├── Attribute           (obj.attr)
      ├── Subscript           (obj[key]  →  request.args['id'])
      ├── JoinedStr           (f"...{expr}..."  →  fuente de SQLi)
      ├── FormattedValue      (el {expr} dentro de un f-string)
      └── PercentFormat       ("... %s ..." % (val,)  →  otra fuente SQLi)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Base
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ASTNode:
    """Clase base. Todos los nodos heredan de aquí."""
    line: int = 0
    col:  int = 0

    def accept(self, visitor: "ASTVisitor"):
        """
        Patrón Visitor.
        Busca visit_<ClassName> en el visitor; si no existe llama generic_visit.
        Esto permite que el Taint Analyzer (Fase 2) recorra el árbol sin
        modificar los nodos.
        """
        method = f"visit_{type(self).__name__}"
        fn = getattr(visitor, method, visitor.generic_visit)
        return fn(self)

    def __repr__(self) -> str:
        attrs = {
            k: v for k, v in self.__dict__.items()
            if k not in ("line", "col") and v is not None
        }
        return f"{type(self).__name__}({attrs})"


# ──────────────────────────────────────────────────────────────────────────────
# Statements
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Module(ASTNode):
    """Nodo raíz: representa el archivo completo."""
    body: List[ASTNode] = field(default_factory=list)


@dataclass
class AssignStatement(ASTNode):
    """
    x = expr
    targets es lista porque Python permite: a = b = expr
    """
    targets: List[ASTNode]     = field(default_factory=list)
    value:   Optional[ASTNode] = None


@dataclass
class AugAssignStatement(ASTNode):
    """
    x += expr   (también -=, *=, etc.)
    Relevante para SQLi cuando se acumula:
        query += " WHERE id=" + user_input
    """
    target: Optional[ASTNode] = None
    op:     str               = "+="
    value:  Optional[ASTNode] = None


@dataclass
class ExprStatement(ASTNode):
    """
    Expresión usada como sentencia.
    El caso más importante: cursor.execute(query)
    """
    expression: Optional[ASTNode] = None


@dataclass
class ElifClause(ASTNode):
    condition: Optional[ASTNode] = None
    body:      List[ASTNode]     = field(default_factory=list)


@dataclass
class IfStatement(ASTNode):
    """if cond: body [elif cond: body]* [else: body]"""
    condition:    Optional[ASTNode]  = None
    then_body:    List[ASTNode]      = field(default_factory=list)
    elif_clauses: List[ElifClause]   = field(default_factory=list)
    else_body:    List[ASTNode]      = field(default_factory=list)


@dataclass
class WhileStatement(ASTNode):
    """while cond: body"""
    condition: Optional[ASTNode] = None
    body:      List[ASTNode]     = field(default_factory=list)


@dataclass
class ForStatement(ASTNode):
    """
    for target in iter: body
    target puede ser Name o Tuple (for k, v in items())
    """
    target: Optional[ASTNode] = None
    iter:   Optional[ASTNode] = None
    body:   List[ASTNode]     = field(default_factory=list)


@dataclass
class Param(ASTNode):
    """Parámetro de función. default=None si no tiene valor por defecto."""
    name:    str               = ""
    default: Optional[ASTNode] = None


@dataclass
class FunctionDef(ASTNode):
    """
    def nombre(params):
        body
    """
    name:   str           = ""
    params: List[Param]   = field(default_factory=list)
    body:   List[ASTNode] = field(default_factory=list)


@dataclass
class ReturnStatement(ASTNode):
    """return [expr]"""
    value: Optional[ASTNode] = None


@dataclass
class ImportStatement(ASTNode):
    """
    import modulo  /  from modulo import nombre
    Relevante para detectar frameworks fuente de datos externos
    (flask, django, fastapi, …).
    """
    module:  str       = ""
    names:   List[str] = field(default_factory=list)
    is_from: bool      = False   # True → from X import Y


# ──────────────────────────────────────────────────────────────────────────────
# Expressions
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Literal(ASTNode):
    """
    Valor literal.
    kind ∈ {"str", "int", "float", "bool", "none"}
    Los literales son SIEMPRE seguros (no taint).
    """
    value: Any = None
    kind:  str = "str"


@dataclass
class Name(ASTNode):
    """
    Identificador: variable, función, clase, constante.
    name es el texto tal como aparece en el fuente.
    """
    name: str = ""


@dataclass
class BinaryOp(ASTNode):
    """
    Operación binaria: left OP right
    op ∈ {"+", "-", "*", "/", "%", "//", "**",
           "==", "!=", "<", ">", "<=", ">=",
           "&", "|", "^", "<<", ">>"}

    NOTA para el taint engine (Fase 2):
      "+"  entre cadenas es concatenación → propaga taint.
      "%"  con string izquierdo es printf-style → propaga taint.
    """
    left:  Optional[ASTNode] = None
    op:    str               = ""
    right: Optional[ASTNode] = None


@dataclass
class UnaryOp(ASTNode):
    """not expr  |  -expr  |  +expr  |  ~expr"""
    op:      str               = ""
    operand: Optional[ASTNode] = None


@dataclass
class BoolOp(ASTNode):
    """
    and / or con N operandos (Python los agrupa así en su propio AST).
    op ∈ {"and", "or"}
    """
    op:     str           = "and"
    values: List[ASTNode] = field(default_factory=list)


@dataclass
class Compare(ASTNode):
    """
    Comparaciones encadenadas: a < b <= c
    left        → primer operando
    ops         → ["<", "<="]
    comparators → [b, c]
    """
    left:        Optional[ASTNode] = None
    ops:         List[str]         = field(default_factory=list)
    comparators: List[ASTNode]     = field(default_factory=list)


@dataclass
class Keyword(ASTNode):
    """Argumento keyword en una llamada: func(key=value)"""
    key:   str               = ""
    value: Optional[ASTNode] = None


@dataclass
class FCall(ASTNode):
    """
    Llamada a función o método.
    func puede ser Name o Attribute.

    Casos críticos para el análisis de seguridad:
      Fuentes (sources):
        - input(...)              → taint directo (stdin)
        - request.args.get(...)   → taint (Flask/Werkzeug)
        - request.form.get(...)   → taint (Flask)
        - request.GET.get(...)    → taint (Django)
        - request.POST.get(...)   → taint (Django)
      Sanitizadores:
        - int(...), float(...)    → cast numérico, elimina taint string
        - re.escape(...)          → escapa metacaracteres
        - html.escape(...)        → escapa HTML (insuficiente para SQL)
      Sumideros SQL (sinks):
        - cursor.execute(...)
        - db.execute(...)
        - session.execute(...)
        - connection.execute(...)
    """
    func:     Optional[ASTNode] = None
    args:     List[ASTNode]     = field(default_factory=list)
    keywords: List[Keyword]     = field(default_factory=list)


@dataclass
class Attribute(ASTNode):
    """
    Acceso a atributo: obj.attr
    Ejemplos relevantes:
      request.args   → fuente de datos externos
      cursor.execute → sink SQL
    """
    obj:  Optional[ASTNode] = None
    attr: str               = ""


@dataclass
class Subscript(ASTNode):
    """
    Acceso por índice/clave: obj[key]
    Ejemplos:
      request.args['user_id']  → taint
      row[0]                   → puede propagar taint de la BD
    """
    obj: Optional[ASTNode] = None
    key: Optional[ASTNode] = None


@dataclass
class FormattedValue(ASTNode):
    """
    El {expr} dentro de un f-string.
    conversion ∈ {None, "s", "r", "a"}  (sin conversión, !s, !r, !a)
    Si expr está tainted, el JoinedStr padre queda tainted.
    """
    value:      Optional[ASTNode] = None
    conversion: Optional[str]     = None


@dataclass
class JoinedStr(ASTNode):
    """
    F-string: f"SELECT * FROM users WHERE id={user_id}"
    values es lista mezclada de Literal y FormattedValue.
    Es una de las fuentes de SQLi más comunes en Python moderno.
    """
    values: List[ASTNode] = field(default_factory=list)


@dataclass
class PercentFormat(ASTNode):
    """
    Formato printf-style: "SELECT * FROM t WHERE x='%s'" % (val,)
    Se representa como nodo propio porque su semántica de propagación
    de taint difiere de BinaryOp con op="%".
    left  → la cadena de formato (Literal)
    right → la tupla / valor de sustitución
    """
    left:  Optional[ASTNode] = None
    right: Optional[ASTNode] = None


@dataclass
class Tuple(ASTNode):
    """Tupla literal: (a, b, c) — usada en % formatting y for-targets."""
    elements: List[ASTNode] = field(default_factory=list)


@dataclass
class PyList(ASTNode):
    """Lista literal: [a, b, c]"""
    elements: List[ASTNode] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# Visitor base
# ──────────────────────────────────────────────────────────────────────────────

class ASTVisitor:
    """
    Clase base para todos los visitantes del AST.
    Las fases posteriores (CFG Builder, Taint Analyzer) heredan de aquí.
    generic_visit recorre automáticamente todos los hijos del nodo.
    """

    def generic_visit(self, node: ASTNode):
        for value in node.__dict__.values():
            if isinstance(value, ASTNode):
                value.accept(self)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ASTNode):
                        item.accept(self)

    def visit_Module(self, node: Module):
        self.generic_visit(node)

    def visit_FunctionDef(self, node: FunctionDef):
        self.generic_visit(node)
