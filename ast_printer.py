"""
ast_printer.py — Visualización del AST en consola
==================================================

Imprime el AST como un árbol jerárquico en la terminal usando la
librería `rich`, con colores semánticos y símbolos de árbol Unicode.

Cada línea muestra:
  [TIPO_NODO]  campo=valor …  @ línea:col

Categorías de color
-------------------
  bold cyan          → Module (raíz)
  bold blue          → Sentencias estructurales (FunctionDef, If, While, For)
  bold green         → Sentencias simples (Assign, AugAssign, Return, Import)
  bold red           → Nodos de interés de seguridad ALTO (FCall, Attribute, Subscript)
  bold magenta       → Construcciones de cadena (JoinedStr, FormattedValue, PercentFormat)
  bold yellow        → Names (variables / identificadores)
  white              → Expresiones aritméticas / lógicas (BinaryOp, UnaryOp, BoolOp, Compare)
  dim white          → Literales (siempre seguros)
"""

from __future__ import annotations

from rich.console import Console
from rich.text    import Text
from rich.panel   import Panel
from rich.rule    import Rule

from ast_nodes import ASTNode

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# Paleta semántica
# ──────────────────────────────────────────────────────────────────────────────

_STYLE: dict[str, str] = {
    # Raíz
    "Module":              "bold cyan",
    # Sentencias estructurales
    "FunctionDef":         "bold blue",
    "IfStatement":         "bold blue",
    "ElifClause":          "blue",
    "WhileStatement":      "bold blue",
    "ForStatement":        "bold blue",
    # Sentencias simples
    "AssignStatement":     "bold green",
    "AugAssignStatement":  "bold green",
    "ExprStatement":       "green",
    "ReturnStatement":     "green",
    "ImportStatement":     "green",
    "Param":               "green",
    # Interés de seguridad ALTO
    "FCall":               "bold red",
    "Attribute":           "red",
    "Subscript":           "red",
    # Construcciones de cadena — interés de seguridad MEDIO-ALTO
    "JoinedStr":           "bold magenta",
    "FormattedValue":      "magenta",
    "PercentFormat":       "bold magenta",
    # Variables
    "Name":                "bold yellow",
    # Expresiones aritméticas / lógicas
    "BinaryOp":            "white",
    "UnaryOp":             "white",
    "BoolOp":              "white",
    "Compare":             "white",
    "Keyword":             "white",
    "Tuple":               "white",
    "PyList":              "white",
    # Literales — siempre seguros
    "Literal":             "dim white",
}

_DEFAULT_STYLE = "dim white"

# Caracteres de árbol Unicode
_PIPE      = "│   "
_BRANCH    = "├── "
_LAST      = "└── "
_BLANK     = "    "


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _scalar_attrs(node: ASTNode) -> list[tuple[str, str]]:
    """
    Devuelve los atributos escalares (no-nodo, no-lista-de-nodos)
    de un nodo como lista de (nombre, repr).
    """
    result = []
    for k, v in node.__dict__.items():
        if k in ("line", "col"):
            continue
        if isinstance(v, ASTNode):
            continue
        if isinstance(v, list):
            # Incluir solo listas de puros escalares (p.ej. ops, names)
            if any(isinstance(i, ASTNode) for i in v):
                continue
        if v is None or v == [] or v == "":
            continue
        result.append((k, repr(v)))
    return result


def _children(node: ASTNode) -> list[tuple[str, ASTNode]]:
    """
    Devuelve los hijos ASTNode del nodo como lista de (etiqueta, nodo).
    Los hijos en listas se etiquetan como campo[i].
    """
    result = []
    for k, v in node.__dict__.items():
        if k in ("line", "col"):
            continue
        if isinstance(v, ASTNode):
            result.append((k, v))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, ASTNode):
                    result.append((f"{k}[{i}]", item))
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Impresión recursiva
# ──────────────────────────────────────────────────────────────────────────────

def _print_node(
    node: ASTNode,
    prefix: str,
    is_last: bool,
    edge_label: str,
    con: Console,
):
    """Imprime un nodo y luego visita sus hijos recursivamente."""

    node_type = type(node).__name__
    style     = _STYLE.get(node_type, _DEFAULT_STYLE)

    # ── Conector del árbol ────────────────────────────────────────────────────
    connector = _LAST if is_last else _BRANCH

    # ── Línea del nodo ────────────────────────────────────────────────────────
    line = Text()
    line.append(prefix + connector, style="dim white")

    # Etiqueta del campo (edge)
    if edge_label:
        line.append(f"{edge_label}: ", style="dim cyan")

    # Tipo del nodo
    line.append(f"[{node_type}]", style=style)

    # Atributos escalares
    for attr_name, attr_val in _scalar_attrs(node):
        line.append(f"  {attr_name}=", style="dim white")
        # Truncar valores muy largos para no romper el árbol
        display = attr_val if len(attr_val) <= 40 else attr_val[:37] + "…'"
        line.append(display, style="italic " + style)

    # Posición en el fuente
    line.append(f"  @ {node.line}:{node.col}", style="dim white")

    con.print(line)

    # ── Hijos ─────────────────────────────────────────────────────────────────
    children    = _children(node)
    child_prefix = prefix + (_BLANK if is_last else _PIPE)

    for idx, (label, child) in enumerate(children):
        child_is_last = (idx == len(children) - 1)
        _print_node(child, child_prefix, child_is_last, label, con)


# ──────────────────────────────────────────────────────────────────────────────
# API pública
# ──────────────────────────────────────────────────────────────────────────────

def print_ast_tree(
    root: ASTNode,
    title: str = "",
    con: Console | None = None,
):
    """
    Imprime el AST completo en la consola.

    Parámetros
    ----------
    root  : nodo raíz (normalmente Module)
    title : título opcional que se muestra sobre el árbol
    con   : instancia de Console de rich (usa la global si es None)
    """
    con = con or console

    if title:
        con.print(Rule(f"[bold cyan]🌳  AST — {title}[/bold cyan]",
                       style="dim cyan"))

    children = _children(root)
    node_type = type(root).__name__
    style     = _STYLE.get(node_type, _DEFAULT_STYLE)

    # Raíz
    line = Text()
    line.append(f"[{node_type}]", style=style)
    for attr_name, attr_val in _scalar_attrs(root):
        line.append(f"  {attr_name}=", style="dim white")
        line.append(attr_val, style="italic " + style)
    line.append(f"  @ {root.line}:{root.col}", style="dim white")
    con.print(line)

    for idx, (label, child) in enumerate(children):
        is_last = (idx == len(children) - 1)
        _print_node(child, "", is_last, label, con)

    con.print()


def print_token_table(tokens: list, con: Console | None = None):
    """
    Imprime los tokens en una tabla alineada con rich.

    Columnas: #  TIPO  VALOR  LÍNEA:COL
    """
    from rich.table import Table

    con = con or console
    table = Table(
        show_header=True,
        header_style="bold dim white",
        border_style="dim white",
        box=None,
        pad_edge=False,
        show_edge=False,
    )
    table.add_column("#",      style="dim white",  width=4,  justify="right")
    table.add_column("TIPO",   style="bold cyan",  width=24)
    table.add_column("VALOR",  style="yellow",     width=36)
    table.add_column("POS",    style="dim white",  width=10)

    for i, tok in enumerate(tokens, 1):
        val = repr(tok.value) if tok.value else "—"
        if len(val) > 34:
            val = val[:31] + "…'"
        table.add_row(
            str(i),
            tok.type.name,
            val,
            f"{tok.line}:{tok.col}",
        )

    con.print(table)
    con.print()
