"""
ast_visualizer.py — Generador de PNG formal estilo paper científico
===================================================================

Estrategia de distinción visual optimizada para publicación académica:
- Alto contraste para impresión B/N
- Formas geométricas diferenciadas
- Bordes con diferente grosor y estilo
- Paleta de colores académicos profesionales

Estilo visual:
- Marco formal con border de doble línea
- Caption con numeración de figura
- Footer con metadatos del sistema
- Tipografía: Times New Roman (serif académico)
"""

from __future__ import annotations

import os
from typing import Optional

import graphviz

from ast_nodes import ASTNode


# ──────────────────────────────────────────────────────────────────────────────
# Esquema visual académico
# Fill: color de relleno | Pen: grosor borde | Style: estilo borde
# Peri: número de bordes | Shape: forma geométrica | FColor: color texto header
# HBG: color fondo header
# ──────────────────────────────────────────────────────────────────────────────

_S = dict[str, tuple]

_STYLE: _S = {
    # Categoría 1: Module (raíz) - negro oscuro con texto blanco
    "Module":              ("#0d0d0d", "2.5", "solid",  "1", "rectangle",     "white",  "#000000"),

    # Categoría 2: Sentencias estructurales - gris oscuro
    "FunctionDef":         ("#3d3d3d", "2.0", "solid",  "1", "rectangle",     "white",  "#1a1a1a"),
    "IfStatement":         ("#3d3d3d", "2.0", "solid",  "1", "rectangle",     "white",  "#1a1a1a"),
    "ElifClause":          ("#5a5a5a", "1.8", "solid",  "1", "rectangle",     "white",  "#333333"),
    "WhileStatement":      ("#3d3d3d", "2.0", "solid",  "1", "rectangle",     "white",  "#1a1a1a"),
    "ForStatement":        ("#3d3d3d", "2.0", "solid",  "1", "rectangle",     "white",  "#1a1a1a"),

    # Categoría 3: Sentencias simples - gris medio
    "AssignStatement":     ("#9a9a9a", "1.5", "solid",  "1", "rectangle",     "black",  "#666666"),
    "AugAssignStatement":  ("#9a9a9a", "1.5", "solid",  "1", "rectangle",     "black",  "#666666"),
    "ExprStatement":       ("#b0b0b0", "1.2", "solid",  "1", "rectangle",     "black",  "#808080"),
    "ReturnStatement":     ("#b0b0b0", "1.2", "solid",  "1", "rectangle",     "black",  "#808080"),
    "ImportStatement":     ("#b0b0b0", "1.2", "solid",  "1", "rectangle",     "black",  "#808080"),
    "Param":               ("#c0c0c0", "1.0", "solid",  "1", "rectangle",     "black",  "#909090"),

    # Categoría 4: FCall / Sink - doble borde (notación de seguridad)
    "FCall":               ("#f5f5f5", "2.2", "solid",  "2", "octagon",       "black",  "#d0d0d0"),
    "Subscript":           ("#f0f0f0", "2.0", "solid",  "2", "octagon",       "black",  "#c5c5c5"),

    # Categoría 5: Attribute - borde discontinuo
    "Attribute":           ("#e5e5e5", "1.5", "dashed", "1", "rectangle",     "black",  "#bbbbbb"),

    # Categoría 6: String format - diamante
    "JoinedStr":           ("#6a6a6a", "1.8", "solid",  "1", "diamond",       "white",  "#404040"),
    "FormattedValue":      ("#888888", "1.4", "solid",  "1", "diamond",       "white",  "#5a5a5a"),
    "PercentFormat":       ("#6a6a6a", "1.8", "solid",  "1", "diamond",       "white",  "#404040"),

    # Categoría 7: Name (identificador)
    "Name":                ("#fafafa", "1.0", "solid",  "1", "ellipse",       "black",  "#e0e0e0"),

    # Categoría 8: Expresiones - borde punteado
    "BinaryOp":            ("#f5f5f5", "0.8", "dotted", "1", "rectangle",     "black",  "#e5e5e5"),
    "UnaryOp":             ("#f5f5f5", "0.8", "dotted", "1", "rectangle",     "black",  "#e5e5e5"),
    "BoolOp":              ("#f5f5f5", "0.8", "dotted", "1", "rectangle",     "black",  "#e5e5e5"),
    "Compare":             ("#f5f5f5", "0.8", "dotted", "1", "rectangle",     "black",  "#e5e5e5"),
    "Keyword":             ("#f5f5f5", "0.6", "dotted", "1", "rectangle",     "black",  "#e5e5e5"),
    "Tuple":               ("#f8f8f8", "0.6", "dotted", "1", "rectangle",     "black",  "#eeeeee"),
    "PyList":              ("#f8f8f8", "0.6", "dotted", "1", "rectangle",     "black",  "#eeeeee"),

    # Categoría 9: Literal - elipse gris
    "Literal":             ("#d0d0d0", "0.8", "solid",  "1", "ellipse",       "black",  "#a0a0a0"),
}

_DEFAULT_STYLE = ("#f8f8f8", "0.8", "solid", "1", "rectangle", "black", "#dddddd")

_FONT_TITLE = "Times New Roman"
_FONT_MONO  = "Courier New"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def _trunc(value: str, n: int = 28) -> str:
    s = str(value)
    return s if len(s) <= n else s[:n - 3] + "..."


def _scalar_attrs(node: ASTNode) -> list[tuple[str, str]]:
    result = []
    for k, v in node.__dict__.items():
        if k in ("line", "col"):
            continue
        if isinstance(v, ASTNode):
            continue
        if isinstance(v, list) and any(isinstance(i, ASTNode) for i in v):
            continue
        if v is None or v == [] or v == "":
            continue
        result.append((k, _esc(_trunc(repr(v)))))
    return result


def _children(node: ASTNode) -> list[tuple[str, ASTNode]]:
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


def _make_label(node: ASTNode) -> str:
    """
    Etiqueta formal estilo académico:
      ┌─────────────────────────────┐
      │  [HEADER]    TIPO_NODO      │  bold 10pt
      ├─────────────────────────────┤
      │  field       value          │  8pt / 8pt mono
      ├─────────────────────────────┤
      │                    [l:n]     │  7pt italic
      └─────────────────────────────┘
    """
    node_type = type(node).__name__
    fill, pw, bstyle, peri, shape, fcolor, hbg = _STYLE.get(node_type, _DEFAULT_STYLE)

    hdr_font = "white" if fcolor == "white" else "black"

    rows = (
        f'<TR>'
        f'<TD BORDER="0" ALIGN="CENTER" COLSPAN="2" BGCOLOR="{hbg}" SIDES="TB">'
        f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10" COLOR="{hdr_font}">'
        f'{node_type}</FONT></B>'
        f'</TD></TR>'
    )

    for attr_name, attr_val in _scalar_attrs(node):
        rows += (
            f'<TR>'
            f'<TD BORDER="0" ALIGN="LEFT" BGCOLOR="{fill}">'
            f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8" COLOR="#222222">'
            f'<I>{attr_name}</I></FONT>'
            f'</TD>'
            f'<TD BORDER="0" ALIGN="LEFT" BGCOLOR="{fill}">'
            f'<FONT FACE="{_FONT_MONO}" POINT-SIZE="8" COLOR="#222222">'
            f'{attr_val}</FONT>'
            f'</TD></TR>'
        )

    rows += (
        f'<TR>'
        f'<TD BORDER="0" COLSPAN="2" ALIGN="RIGHT" BGCOLOR="{fill}">'
        f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="7" COLOR="#666666">'
        f'<I>[{node.line}:{node.col}]</I></FONT>'
        f'</TD></TR>'
    )

    return (
        f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" '
        f'CELLPADDING="3" COLOR="#666666">{rows}</TABLE>>'
    )


# ──────────────────────────────────────────────────────────────────────────────
# Visualizador
# ──────────────────────────────────────────────────────────────────────────────

class ASTVisualizer:
    """
    Genera PNGs del AST en estilo paper científico B/N con alta distinción
    visual entre categorías de nodos.

    Métodos públicos
    ----------------
    render(root, filename, caption)  → PNG del AST (sin leyenda)
    render_legend(output_dir, dpi)   → legend.png standalone
    """

    def __init__(
        self,
        output_dir: str = "output/ast",
        dpi: int = 200,
        rankdir: str = "TB",
    ):
        self.output_dir = output_dir
        self.dpi        = dpi
        self.rankdir    = rankdir
        self._uid       = 0
        os.makedirs(output_dir, exist_ok=True)

    # ── Render del AST ────────────────────────────────────────────────────────

    def render(self, root: ASTNode, filename: str, caption: str = "") -> str:
        self._uid = 0
        g = graphviz.Digraph(name=filename, comment=f"AST — {filename}")
        self._configure_graph(g, caption)
        self._visit(g, root, parent_id=None, edge_label="")

        out_base = os.path.join(self.output_dir, filename)
        g.render(out_base, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out_base + ".png")

    # ── Leyenda standalone ────────────────────────────────────────────────────

    @staticmethod
    def render_legend(output_dir: str = "output/legend", dpi: int = 200) -> str:
        """
        Genera legend.png con una tabla formal de doble columna:
          columna izquierda  → nodo de ejemplo (forma + relleno + borde reales)
          columna derecha    → descripción tipográfica estructurada

        Layout: rankdir=TB con subgrafos de rank=same para alinear columnas.
        """
        os.makedirs(output_dir, exist_ok=True)

        g = graphviz.Digraph(name="legend", comment="AST Legend")
        g.attr(
            rankdir   = "TB",
            bgcolor   = "white",
            fontname  = _FONT_TITLE,
            splines   = "line",
            nodesep   = "0.5",
            ranksep   = "0.45",
            pad       = "0.7",
            dpi       = str(dpi),
        )
        g.attr("node",
            fontname  = _FONT_TITLE,
            fontsize  = "10",
            color     = "black",
            style     = "filled",
            margin    = "0.12,0.08",
        )
        g.attr("edge",
            color     = "black",
            arrowhead = "none",
            penwidth  = "0.6",
        )

        # ── Título formal ──────────────────────────────────────────────────────
        g.node("title",
            label = (
                f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="8">'
                f'<TR><TD>'
                f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="13" COLOR="#1a1a1a">'
                f'Figure A. AST Node Classification Legend</FONT></B>'
                f'</TD></TR>'
                f'<TR><TD>'
                f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="9" COLOR="#444444">'
                f'<I>Security Linter — Phase 1: Lexer + Parser + AST</I>'
                f'</FONT>'
                f'</TD></TR>'
                f'</TABLE>>'
            ),
            shape     = "plaintext",
            fillcolor = "white",
            penwidth  = "0",
        )

        # ── Separador horizontal ───────────────────────────────────────────────
        g.node("sep",
            label    = (
                f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="2">'
                f'<TR><TD WIDTH="600" HEIGHT="1" BGCOLOR="#333333"></TD></TR>'
                f'</TABLE>>'
            ),
            shape    = "plaintext",
            fillcolor= "white",
            penwidth = "0",
        )
        g.edge("title", "sep", style="invis")

        # ── Cabecera de columnas ───────────────────────────────────────────────
        g.node("col_hdr_node",
            label = (
                f'<<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10">'
                f'Node Example</FONT></B>>'
            ),
            shape="plaintext", fillcolor="white", penwidth="0",
        )
        g.node("col_hdr_desc",
            label = (
                f'<<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10">'
                f'Classification &amp; Description</FONT></B>>'
            ),
            shape="plaintext", fillcolor="white", penwidth="0",
        )
        with g.subgraph() as s:
            s.attr(rank="same")
            s.node("col_hdr_node")
            s.node("col_hdr_desc")
        g.edge("sep", "col_hdr_node", style="invis")
        g.edge("sep", "col_hdr_desc", style="invis")
        g.edge("col_hdr_node", "col_hdr_desc",
               style="invis", minlen="2")

        # ── Entradas de la leyenda ─────────────────────────────────────────────
        entries = [
            # (id_slug, node_types_display, fill, pw, bstyle, peri, shape, fcolor, hbg,
            #  category_label, description_lines)
            (
                "module",
                "Module",
                "#1a1a1a", "3.0", "solid", "1", "rectangle", "white", "#000000",
                "Category 1 — Root",
                ["Unique root of the program AST.",
                 "Black fill; thick solid border (3.0 pt).",
                 "Always a single node per translation unit."],
            ),
            (
                "structural",
                "FunctionDef  ·  IfStatement\nWhileStatement  ·  ForStatement",
                "#4a4a4a", "2.0", "solid", "1", "rectangle", "white", "#333333",
                "Category 2 — Structural Statements",
                ["Block-scoping control-flow constructs.",
                 "Dark grey fill; solid border (2.0 pt).",
                 "Introduce new lexical scopes in the CFG."],
            ),
            (
                "simple",
                "AssignStatement  ·  AugAssignStatement\nReturnStatement  ·  ImportStatement",
                "#aaaaaa", "1.2", "solid", "1", "rectangle", "black", "#888888",
                "Category 3 — Simple Statements",
                ["Leaf-level executable statements.",
                 "Medium grey fill; solid border (1.2 pt).",
                 "Primary taint propagation targets."],
            ),
            (
                "fcall",
                "FCall  ·  Subscript",
                "#ffffff", "2.5", "solid", "2", "octagon", "black", "#dddddd",
                "Category 4 — Calls & Subscripts  ★",
                ["High-security-interest nodes.",
                 "White fill; double octagon border (2.5 pt).",
                 "Potential taint sources (input, request.*)",
                 "and SQL sinks (cursor.execute)."],
            ),
            (
                "attribute",
                "Attribute",
                "#e8e8e8", "1.8", "dashed", "1", "rectangle", "black", "#cccccc",
                "Category 5 — Attribute Access",
                ["Member access expression: obj.attr.",
                 "Light grey fill; dashed border (1.8 pt).",
                 "Resolves taint of compound sources",
                 "such as request.args.get(…)."],
            ),
            (
                "strfmt",
                "JoinedStr  ·  PercentFormat\nFormattedValue",
                "#777777", "1.8", "solid", "1", "diamond", "white", "#555555",
                "Category 6 — String Format Expressions",
                ["f-strings and printf-style formatting.",
                 "Dark grey diamond; solid border (1.8 pt).",
                 "Most frequent SQLi propagation pattern",
                 "in modern Python codebases."],
            ),
            (
                "name",
                "Name",
                "#ffffff", "1.2", "solid", "1", "ellipse", "black", "#dddddd",
                "Category 7 — Identifier",
                ["Variable or function name reference.",
                 "White ellipse; solid border (1.2 pt).",
                 "Taint state assigned per variable",
                 "during Phase 2 DFG analysis."],
            ),
            (
                "expr",
                "BinaryOp  ·  UnaryOp\nBoolOp  ·  Compare",
                "#eeeeee", "1.0", "dotted", "1", "rectangle", "black", "#d8d8d8",
                "Category 8 — Arithmetic / Logic Expressions",
                ["Computational expression nodes.",
                 "Near-white fill; dotted border (1.0 pt).",
                 "Propagate taint transitively when",
                 "any operand is tainted."],
            ),
            (
                "literal",
                "Literal",
                "#cccccc", "0.8", "solid", "1", "ellipse", "black", "#b0b0b0",
                "Category 9 — Literal Value",
                ["Constant: str, int, float, bool, None.",
                 "Grey ellipse; thin solid border (0.8 pt).",
                 "Always taint-free by definition;",
                 "never triggers a security alert."],
            ),
        ]

        prev_node = "col_hdr_node"
        prev_desc = "col_hdr_desc"

        for entry in entries:
            (slug, type_lbl, fill, pw, bstyle, peri,
             shape, fcolor, hbg, cat_label, desc_lines) = entry

            ex_id   = f"ex_{slug}"
            desc_id = f"desc_{slug}"
            anch_id = f"anch_{slug}"   # ancla invisible para alinear filas

            # ── Nodo de ejemplo (fiel al estilo del grafo real) ────────────────
            hdr_font = "white" if fcolor == "white" else "black"
            type_lbl_esc = _esc(type_lbl).replace("\\n", "<BR/>")

            ex_rows = (
                f'<TR><TD ALIGN="CENTER" COLSPAN="2" BGCOLOR="{hbg}">'
                f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="9" COLOR="{hdr_font}">'
                f'{type_lbl_esc}</FONT></B></TD></TR>'
                f'<TR>'
                f'<TD ALIGN="LEFT" BGCOLOR="{fill}">'
                f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8" COLOR="black">'
                f'<I>field</I></FONT></TD>'
                f'<TD ALIGN="LEFT" BGCOLOR="{fill}">'
                f'<FONT FACE="{_FONT_MONO}" POINT-SIZE="8" COLOR="black">'
                f"'value'</FONT></TD>"
                f'</TR>'
                f'<TR><TD COLSPAN="2" ALIGN="RIGHT" BGCOLOR="{fill}">'
                f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="7" COLOR="#444444">'
                f'<I>[line:col]</I></FONT></TD></TR>'
            )

            g.node(
                ex_id,
                label       = (
                    f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" '
                    f'CELLPADDING="3" COLOR="#888888">{ex_rows}</TABLE>>'
                ),
                shape       = shape,
                fillcolor   = fill,
                penwidth    = pw,
                peripheries = peri,
                color       = "black",
                style       = f"filled,{bstyle}",
                width       = "2.5",
            )

            # ── Nodo de descripción ────────────────────────────────────────────
            desc_inner = (
                f'<TR><TD ALIGN="LEFT">'
                f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10">'
                f'{_esc(cat_label)}</FONT></B>'
                f'</TD></TR>'
            )
            for line in desc_lines:
                desc_inner += (
                    f'<TR><TD ALIGN="LEFT">'
                    f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="9">'
                    f'{_esc(line)}</FONT>'
                    f'</TD></TR>'
                )

            g.node(
                desc_id,
                label    = (
                    f'<<TABLE BORDER="0" CELLBORDER="0" '
                    f'CELLSPACING="1" CELLPADDING="2">'
                    f'{desc_inner}</TABLE>>'
                ),
                shape    = "plaintext",
                fillcolor= "white",
                penwidth = "0",
                width    = "4.2",
            )

            # ── Alinear ejemplo y descripción en la misma fila (rank=same) ────
            with g.subgraph() as row:
                row.attr(rank="same")
                row.node(ex_id)
                row.node(desc_id)

            # Separador horizontal entre categorías (nodo invisible)
            g.node(anch_id, shape="point", width="0.01",
                   fillcolor="white", color="white", penwidth="0")
            with g.subgraph() as row2:
                row2.attr(rank="same")
                row2.node(anch_id)

            # Aristas para mantener el orden vertical
            g.edge(prev_node, ex_id,   style="invis")
            g.edge(prev_desc, desc_id, style="invis")
            g.edge(ex_id,   anch_id,   style="invis")
            g.edge(desc_id, anch_id,   style="invis")

            # Línea horizontal separadora entre filas
            g.edge(ex_id, desc_id,
                   arrowhead="none",
                   penwidth="0.8",
                   style="solid",
                   color="#cccccc",
                   constraint="false")

            prev_node = anch_id
            prev_desc = anch_id

        # ── Pie de leyenda ─────────────────────────────────────────────────────
        g.node("footer",
            label = (
                f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="4">'
                f'<TR><TD WIDTH="600" HEIGHT="1" BGCOLOR="#333333"></TD></TR>'
                f'<TR><TD ALIGN="LEFT">'
                f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8" COLOR="#555555">'
                f'<I>★ Double-border nodes are high-security-interest: '
                f'they represent potential taint sources or SQL injection sinks.</I>'
                f'</FONT></TD></TR>'
                f'</TABLE>>'
            ),
            shape    = "plaintext",
            fillcolor= "white",
            penwidth = "0",
        )
        g.edge(prev_node, "footer", style="invis")

        out_base = os.path.join(output_dir, "legend")
        g.render(out_base, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out_base + ".png")

    # ── Configuración del grafo de AST ────────────────────────────────────────

    def _configure_graph(self, g: graphviz.Digraph, caption: str):
        fig_num = ""
        fig_title = ""
        if caption:
            parts = caption.split(". ", 1)
            if len(parts) > 1:
                fig_num = parts[0]
                fig_title = parts[1]
            else:
                fig_title = caption

        caption_label = ""
        if fig_num or fig_title:
            rows = ""
            if fig_num:
                rows += (
                    f'<TR><TD ALIGN="CENTER">'
                    f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="12" COLOR="#1a1a1a">'
                    f'<B>{_esc(fig_num)}</B></FONT>'
                    f'</TD></TR>'
                )
            if fig_title:
                rows += (
                    f'<TR><TD ALIGN="CENTER">'
                    f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="11" COLOR="#333333">'
                    f'<I>{_esc(fig_title)}</I></FONT>'
                    f'</TD></TR>'
                )
            caption_label = (
                f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="0">'
                f'{rows}</TABLE>>'
            )

        g.attr(
            rankdir   = self.rankdir,
            bgcolor   = "white",
            fontname  = _FONT_TITLE,
            fontsize  = "10",
            splines   = "ortho",
            nodesep   = "0.35",
            ranksep   = "0.50",
            pad       = "0.8",
            dpi       = str(self.dpi),
            label     = caption_label,
            labelloc  = "t",
            labeljust = "c",
            margin    = "0.5,0.3",
        )
        g.attr("node",
            fontname  = _FONT_TITLE,
            fontsize  = "9",
            fontcolor = "black",
            color     = "black",
            style     = "filled",
            margin    = "0.10,0.05",
        )
        g.attr("edge",
            color     = "#2a2a2a",
            fontname  = _FONT_TITLE,
            fontsize  = "7",
            fontcolor = "#444444",
            arrowsize = "0.6",
            penwidth  = "0.8",
            arrowhead = "normal",
        )

    # ── Recorrido recursivo ───────────────────────────────────────────────────

    def _next_id(self) -> str:
        self._uid += 1
        return f"n{self._uid}"

    def _visit(
        self,
        g: graphviz.Digraph,
        node: ASTNode,
        parent_id: Optional[str],
        edge_label: str,
    ) -> str:
        node_id   = self._next_id()
        node_type = type(node).__name__
        fill, pw, bstyle, peri, shape, fcolor, hbg = _STYLE.get(
            node_type, _DEFAULT_STYLE
        )

        g.node(
            node_id,
            label       = _make_label(node),
            shape       = shape,
            fillcolor   = fill,
            penwidth    = pw,
            peripheries = peri,
            color       = "black",
            style       = f"filled,{bstyle}",
        )

        if parent_id is not None:
            g.edge(
                parent_id,
                node_id,
                label = (
                    f'<<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8">'
                    f'<I>{_esc(edge_label)}</I></FONT>>'
                ),
            )

        for field_label, child in _children(node):
            self._visit(g, child, node_id, field_label)

        return node_id
