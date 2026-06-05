"""
dfg_visualizer.py — Generador de PNG formal del DFG (paper científico)
=======================================================================

Estrategia visual B/N con alta distinción entre tipos de nodo DFG:

  Tipo           Forma          Relleno    Borde           Texto
  ─────────────  ─────────────  ─────────  ──────────────  ──────
  CONSTANT       ellipse        #f0f0f0    dotted 0.8pt    black   (valores literales)
  PARAMETER      hexagon        #888888    solid  2.0pt    white   (params de función)
  VARIABLE       rectangle      #ffffff    solid  1.2pt    black   (variables)
  OPERATOR       diamond        #666666    solid  1.8pt    white   (binop, f-string, %)
  FUNCTION_CALL  octagon        #dddddd    solid  1.5pt    black   (resultado de llamada)
  SOURCE         hexagon        #111111    solid  2.5pt    white   (input, request.*)
  SINK           octagon        #333333    solid  2.5pt ×2 white   (execute — doble borde)

Aristas etiquetadas con el rol semántico: assign, arg0, arg1, left, right, fmt, …

Leyenda: render_legend(output_dir, dpi) → legend_dfg.png independiente.
"""

from __future__ import annotations

import os
from typing import Optional

import graphviz

from dfg_builder import DFG, DFGNode, DFGNodeType


_FONT_TITLE = "Times New Roman"
_FONT_MONO  = "Courier New"

# (fillcolor, penwidth, border_style, peripheries, shape, fontcolor, header_bg)
_STYLE: dict[str, tuple] = {
    "CONSTANT":      ("#f0f0f0", "0.8", "dotted", "1", "ellipse",    "black", "#d8d8d8"),
    "PARAMETER":     ("#888888", "2.0", "solid",  "1", "hexagon",    "white", "#666666"),
    "VARIABLE":      ("#ffffff", "1.2", "solid",  "1", "rectangle",  "black", "#dddddd"),
    "OPERATOR":      ("#666666", "1.8", "solid",  "1", "diamond",    "white", "#444444"),
    "FUNCTION_CALL": ("#e8e8e8", "1.5", "solid",  "1", "octagon",    "black", "#cccccc"),
    "SOURCE":        ("#111111", "2.5", "solid",  "1", "hexagon",    "white", "#000000"),
    "SINK":          ("#333333", "2.5", "solid",  "2", "octagon",    "white", "#111111"),
}
_DEFAULT = ("#ffffff", "0.8", "solid", "1", "rectangle", "black", "#dddddd")


def _esc(t: str) -> str:
    return (str(t).replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))

def _trunc(s: str, n: int = 32) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n-3] + "..."

def _display_name(node: DFGNode) -> str:
    """Nombre legible para mostrar en el nodo (limpia prefijos internos)."""
    name = node.name
    # Prefijos internos: _lit_NNN, _binop_+_NNN, _call_func_NNN, etc.
    if name.startswith("_lit_"):         return repr(node.value) if node.value is not None else "lit"
    if name.startswith("_binop_"):       return node.value or name.split("_")[2]  # operador
    if name.startswith("_augop_"):       return node.value or "+= op"
    if name.startswith("_fstring_"):     return "f-string"
    if name.startswith("_pctfmt_"):      return "%-format"
    if name.startswith("_call_"):
        # _call_cursor.execute_NNN  →  cursor.execute(…)
        parts = name[6:].rsplit("_", 1)
        return f"{parts[0]}(…)" if parts else name
    if name.startswith("_boolop_"):      return "bool-op"
    if name.startswith("_tuple_"):       return "tuple"
    if name.startswith("_empty_"):       return "()"
    if "#" in name:                      return name.split("#")[0]  # versión SSA
    return name

def _node_label(node: DFGNode) -> str:
    tp = node.type.name
    fill, pw, bs, peri, shape, fc, hbg = _STYLE.get(tp, _DEFAULT)
    hfc = "white" if fc == "white" else "black"
    disp = _esc(_trunc(_display_name(node)))
    loc  = f"[{node.line}:{node.col}]" if node.line else ""
    rows = (
        f'<TR><TD ALIGN="CENTER" BGCOLOR="{hbg}">'
        f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10" COLOR="{hfc}">{tp}</FONT></B>'
        f'</TD></TR>'
        f'<TR><TD ALIGN="CENTER" BGCOLOR="{fill}">'
        f'<FONT FACE="{_FONT_MONO}" POINT-SIZE="9" COLOR="black">{disp}</FONT>'
        f'</TD></TR>'
    )
    if loc:
        rows += (f'<TR><TD ALIGN="RIGHT" BGCOLOR="{fill}">'
                 f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="7" COLOR="#555555">'
                 f'<I>{loc}</I></FONT></TD></TR>')
    return (f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" '
            f'CELLPADDING="3" COLOR="#aaaaaa">{rows}</TABLE>>')


class DFGVisualizer:
    """
    Genera PNGs del DFG en estilo paper científico B/N.

    Métodos:
        render(dfg, filename, caption)   → output_dir/filename.png
        render_legend(output_dir, dpi)   → output_dir/legend_dfg.png
    """

    def __init__(self, output_dir: str = "output/dfg",
                 dpi: int = 200, rankdir: str = "TB"):
        self.output_dir = output_dir
        self.dpi        = dpi
        self.rankdir    = rankdir
        os.makedirs(output_dir, exist_ok=True)

    # ── Render del DFG ────────────────────────────────────────────────────────

    def render(self, dfg: DFG, filename: str, caption: str = "") -> str:
        g = graphviz.Digraph(name=filename, comment=f"DFG — {filename}")
        self._configure(g, caption)

        # Nodos — usar id numérico como identificador Graphviz
        id_map: dict[int, str] = {}   # DFGNode.id → graphviz node id
        for key, node in dfg.nodes.items():
            gv_id = f"n{node.id}"
            id_map[node.id] = gv_id
            tp = node.type.name
            fill, pw, bs, peri, shape, fc, _ = _STYLE.get(tp, _DEFAULT)
            g.node(
                gv_id,
                label       = _node_label(node),
                shape       = shape,
                fillcolor   = fill,
                penwidth    = pw,
                peripheries = peri,
                color       = "black",
                style       = f"filled,{bs}",
            )

        # Aristas con etiqueta de rol
        seen_edges: set[tuple] = set()
        for edge in dfg.edges:
            src_gv = id_map.get(edge.source.id)
            dst_gv = id_map.get(edge.target.id)
            if not src_gv or not dst_gv:
                continue
            key = (src_gv, dst_gv, edge.label)
            if key in seen_edges:
                continue
            seen_edges.add(key)

            edge_label = ""
            if edge.label:
                edge_label = (f'<<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8">'
                              f'<I>{_esc(edge.label)}</I></FONT>>')

            g.edge(src_gv, dst_gv,
                   label    = edge_label,
                   penwidth = "0.9",
                   color    = "black",
                   arrowhead= "normal",
                   arrowsize= "0.6")

        out = os.path.join(self.output_dir, filename)
        g.render(out, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out + ".png")

    # ── Leyenda standalone ────────────────────────────────────────────────────

    @staticmethod
    def render_legend(output_dir: str = "output/legend",
                      dpi: int = 200) -> str:
        os.makedirs(output_dir, exist_ok=True)
        g = graphviz.Digraph(name="legend_dfg")
        g.attr(rankdir="TB", bgcolor="white", fontname=_FONT_TITLE,
               splines="line", nodesep="0.4", ranksep="0.45", pad="0.6",
               dpi=str(dpi))
        g.attr("node", fontname=_FONT_TITLE, style="filled",
               color="black", margin="0.1,0.06")
        g.attr("edge", color="black", arrowhead="none", penwidth="0.6")

        # Título
        g.node("title",
            label=(f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="5">'
                   f'<TR><TD><B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="14">'
                   f'Figure C. Node Classification Legend — DFG</FONT></B></TD></TR>'
                   f'<TR><TD><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10">'
                   f'<I>Data Flow Graph · Security Linter, Phase 2</I>'
                   f'</FONT></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")
        g.node("sep", label=(
            f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="2">'
            f'<TR><TD WIDTH="560" HEIGHT="1" BGCOLOR="#333333"></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")
        g.edge("title", "sep", style="invis")

        entries = [
            ("source",   "SOURCE",       "#111111","2.5","solid", "1","hexagon",   "white",
             "External tainted input.\ninput(), request.args.get(), request.form.get(), …\n"
             "All outgoing edges carry taint."),
            ("param",    "PARAMETER",    "#888888","2.0","solid", "1","hexagon",   "white",
             "Function parameter — potentially tainted.\n"
             "Taint determined at call site (Phase 2)."),
            ("variable", "VARIABLE",     "#ffffff","1.2","solid", "1","rectangle", "black",
             "Named variable definition.\n"
             "Taint state = union of incoming edge taint."),
            ("operator", "OPERATOR",     "#666666","1.8","solid", "1","diamond",   "white",
             "Computed expression: BinaryOp (+, %, …), f-string, %-format.\n"
             "Tainted if ANY input is tainted."),
            ("fcall",    "FUNCTION_CALL","#e8e8e8","1.5","solid", "1","octagon",   "black",
             "Return value of a function call.\n"
             "Marked SOURCE if callee is a known taint source.\n"
             "Taint = union of arg taint (if callee not a sanitizer)."),
            ("sink",     "SINK",         "#333333","2.5","solid", "2","octagon",   "white",
             "SQL sink — double border (high priority).\ncursor.execute(), db.execute(), …\n"
             "Reaching this node with tainted input = SQLi vulnerability."),
            ("const",    "CONSTANT",     "#f0f0f0","0.8","dotted","1","ellipse",   "black",
             "Literal constant: str, int, float, bool, None.\n"
             "Always taint-free by definition.\nDotted border signals zero risk."),
        ]

        prev_ex = "sep"
        for slug, tp_name, fill, pw, bs, peri, shape, fc, desc in entries:
            ex_id   = f"ex_{slug}"
            desc_id = f"desc_{slug}"
            anch_id = f"anch_{slug}"
            hfc     = "white" if fc == "white" else "black"
            hbg     = "#333333" if fc == "white" else "#dddddd"

            g.node(ex_id,
                label=(f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0"'
                       f' CELLPADDING="3" COLOR="#aaaaaa">'
                       f'<TR><TD ALIGN="CENTER" BGCOLOR="{hbg}">'
                       f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="9" COLOR="{hfc}">'
                       f'{tp_name}</FONT></B></TD></TR>'
                       f'<TR><TD ALIGN="CENTER" BGCOLOR="{fill}">'
                       f'<FONT FACE="{_FONT_MONO}" POINT-SIZE="8" COLOR="black">'
                       f'value</FONT></TD></TR></TABLE>>'),
                shape=shape, fillcolor=fill, penwidth=pw, peripheries=peri,
                color="black", style=f"filled,{bs}", width="2.2")

            desc_rows = "".join(
                f'<TR><TD ALIGN="LEFT"><FONT FACE="{_FONT_TITLE}" POINT-SIZE="9">'
                f'{_esc(l)}</FONT></TD></TR>' for l in desc.split("\n")
            )
            g.node(desc_id,
                label=f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="1" CELLPADDING="2">'
                      f'{desc_rows}</TABLE>>',
                shape="plaintext", fillcolor="white", penwidth="0", width="4.2")

            with g.subgraph() as row:
                row.attr(rank="same"); row.node(ex_id); row.node(desc_id)

            g.node(anch_id, shape="point", width="0.01",
                   fillcolor="white", color="white", penwidth="0")
            with g.subgraph() as row2:
                row2.attr(rank="same"); row2.node(anch_id)

            g.edge(prev_ex,   ex_id,   style="invis")
            g.edge(ex_id,    desc_id,  arrowhead="none", penwidth="0.7",
                   color="#bbbbbb", constraint="false")
            g.edge(ex_id,    anch_id,  style="invis")

            prev_ex = anch_id

        g.node("footer",
            label=(f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="4">'
                   f'<TR><TD WIDTH="560" HEIGHT="1" BGCOLOR="#333333"></TD></TR>'
                   f'<TR><TD ALIGN="LEFT"><FONT FACE="{_FONT_TITLE}" POINT-SIZE="8" COLOR="#555555">'
                   f'<I>Edge labels: assign · arg0/arg1 · left/right · fmt/args · func · iter · lhs/rhs'
                   f' — all indicate the semantic role of the data flow.</I>'
                   f'</FONT></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")
        g.edge(prev_ex, "footer", style="invis")

        out = os.path.join(output_dir, "legend_dfg")
        g.render(out, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out + ".png")

    def _configure(self, g: graphviz.Digraph, caption: str):
        lbl = (f'<<FONT FACE="{_FONT_TITLE}" POINT-SIZE="11">'
               f'<I>{_esc(caption)}</I></FONT>>') if caption else ""
        g.attr(rankdir=self.rankdir, bgcolor="white", fontname=_FONT_TITLE,
               splines="ortho", nodesep="0.45", ranksep="0.60",
               pad="0.55", dpi=str(self.dpi),
               label=lbl, labelloc="b", labeljust="c")
        g.attr("node", fontname=_FONT_TITLE, fontsize="10",
               color="black", style="filled", margin="0.12,0.07")
        g.attr("edge", color="black", fontname=_FONT_TITLE, fontsize="8",
               fontcolor="#333333", arrowsize="0.6", penwidth="0.9",
               arrowhead="normal")
