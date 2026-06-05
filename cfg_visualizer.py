"""
cfg_visualizer.py — Generador de PNG formal del CFG (paper científico)
=======================================================================

Estrategia visual B/N con alta distinción entre tipos de nodo CFG:

  Tipo          Forma          Relleno    Borde           Texto
  ──────────── ────────────── ─────────  ──────────────  ──────
  ENTRY        circle         #111111    solid 2.5pt     white
  EXIT         circle         #444444    solid 2.5pt     white
  ASSIGN       rectangle      #ffffff    solid 1.2pt     black
  CALL         rectangle      #aaaaaa    solid 1.8pt     black   (doble borde si es SINK)
  CONDITION    diamond        #666666    solid 2.0pt     white
  MERGE        diamond        #cccccc    dashed 1.2pt    black
  LOOP_HEAD    hexagon        #333333    solid 2.0pt     white
  RETURN       rectangle      #888888    solid 1.5pt     white
  IMPORT       rectangle      #eeeeee    dashed 0.8pt    black
  FUNC_DEF     rectangle      #555555    solid 2.0pt     white   (doble borde)

Aristas:
  - Aristas normales: flecha sólida
  - Back-edges (loop): flecha curva con etiqueta "back"
  - Rama True/False del CONDITION: etiquetadas

Leyenda: render_legend(output_dir, dpi) → legend_cfg.png independiente.
"""

from __future__ import annotations

import os
from typing import Optional, Set

import graphviz

from cfg_builder import CFG, CFGNode, CFGNodeType


_FONT_TITLE = "Times New Roman"
_FONT_MONO  = "Courier New"

# (fillcolor, penwidth, border_style, peripheries, shape, fontcolor, header_bg)
_STYLE: dict[str, tuple] = {
    "ENTRY":     ("#111111", "2.5", "solid",  "1", "circle",    "white", "#000000"),
    "EXIT":      ("#444444", "2.5", "solid",  "1", "circle",    "white", "#222222"),
    "ASSIGN":    ("#ffffff", "1.2", "solid",  "1", "rectangle", "black", "#dddddd"),
    "CALL":      ("#aaaaaa", "1.8", "solid",  "1", "rectangle", "black", "#888888"),
    "CONDITION": ("#555555", "2.0", "solid",  "1", "diamond",   "white", "#333333"),
    "MERGE":     ("#dddddd", "1.2", "dashed", "1", "diamond",   "black", "#bbbbbb"),
    "LOOP_HEAD": ("#333333", "2.0", "solid",  "1", "hexagon",   "white", "#111111"),
    "RETURN":    ("#888888", "1.5", "solid",  "1", "rectangle", "white", "#666666"),
    "IMPORT":    ("#f5f5f5", "0.8", "dashed", "1", "rectangle", "black", "#e0e0e0"),
    "FUNC_DEF":  ("#444444", "2.0", "solid",  "2", "rectangle", "white", "#222222"),
}
_DEFAULT = ("#ffffff", "0.8", "solid", "1", "rectangle", "black", "#dddddd")


def _esc(t: str) -> str:
    return (str(t).replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))

def _trunc(s: str, n: int = 38) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n-3] + "..."

def _node_label(node: CFGNode) -> str:
    tp = node.type.name
    fill, pw, bs, peri, shape, fc, hbg = _STYLE.get(tp, _DEFAULT)
    hfc = "white" if fc == "white" else "black"
    label_text = _esc(_trunc(node.label))
    loc = f"[{node.line}:{node.col}]" if node.line else ""
    rows = (
        f'<TR><TD ALIGN="CENTER" BGCOLOR="{hbg}">'
        f'<B><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10" COLOR="{hfc}">{tp}</FONT></B>'
        f'</TD></TR>'
        f'<TR><TD ALIGN="CENTER" BGCOLOR="{fill}">'
        f'<FONT FACE="{_FONT_MONO}" POINT-SIZE="9" COLOR="black">{label_text}</FONT>'
        f'</TD></TR>'
    )
    if loc:
        rows += (
            f'<TR><TD ALIGN="RIGHT" BGCOLOR="{fill}">'
            f'<FONT FACE="{_FONT_TITLE}" POINT-SIZE="7" COLOR="#555555"><I>{loc}</I></FONT>'
            f'</TD></TR>'
        )
    return (f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" '
            f'CELLPADDING="3" COLOR="#aaaaaa">{rows}</TABLE>>')


class CFGVisualizer:
    """
    Genera PNGs del CFG en estilo paper científico B/N.

    Métodos:
        render(cfg, filename, caption)   → output_dir/filename.png
        render_legend(output_dir, dpi)   → output_dir/legend_cfg.png
    """

    def __init__(self, output_dir: str = "output/cfg",
                 dpi: int = 200, rankdir: str = "TB"):
        self.output_dir = output_dir
        self.dpi        = dpi
        self.rankdir    = rankdir
        os.makedirs(output_dir, exist_ok=True)

    # ── Render del CFG ────────────────────────────────────────────────────────

    def render(self, cfg: CFG, filename: str, caption: str = "") -> str:
        g = graphviz.Digraph(name=filename, comment=f"CFG — {filename}")
        self._configure(g, caption)

        # Detectar back-edges (nodo apunta a un predecesor — indica loop)
        back_edges: Set[tuple] = set()
        visited: Set[int] = set()
        def find_back(n: CFGNode, ancestors: Set[int]):
            visited.add(n.id)
            ancestors.add(n.id)
            for s in n.successors:
                if s.id in ancestors:
                    back_edges.add((n.id, s.id))
                elif s.id not in visited:
                    find_back(s, ancestors)
            ancestors.discard(n.id)
        find_back(cfg.entry, set())

        # Nodos
        for node in cfg.nodes.values():
            tp = node.type.name
            fill, pw, bs, peri, shape, fc, _ = _STYLE.get(tp, _DEFAULT)
            # CALL que llega a un nodo SINK (cursor.execute, db.execute)
            is_sink_call = (tp == "CALL" and any(
                kw in node.label for kw in ("execute","executemany","raw","query")
            ))
            peri_final = "2" if (tp == "FUNC_DEF" or is_sink_call) else peri
            g.node(
                str(node.id),
                label       = _node_label(node),
                shape       = shape,
                fillcolor   = fill,
                penwidth    = pw,
                peripheries = peri_final,
                color       = "black",
                style       = f"filled,{bs}",
            )

        # Aristas
        condition_ids = {n.id for n in cfg.nodes.values()
                         if n.type in (CFGNodeType.CONDITION, CFGNodeType.LOOP_HEAD)}
        for node in cfg.nodes.values():
            for i, succ in enumerate(node.successors):
                is_back = (node.id, succ.id) in back_edges
                is_cond = node.id in condition_ids
                # Etiqueta de rama True/False en condiciones
                if is_cond and len(node.successors) >= 2:
                    edge_label = "T" if i == 0 else "F"
                elif is_back:
                    edge_label = "back"
                else:
                    edge_label = ""

                g.edge(
                    str(node.id), str(succ.id),
                    label     = (f'<<FONT FACE="{_FONT_TITLE}" POINT-SIZE="8">'
                                 f'<I>{edge_label}</I></FONT>>') if edge_label else "",
                    style     = "dashed" if is_back else "solid",
                    penwidth  = "0.7"    if is_back else "1.0",
                    color     = "#555555" if is_back else "black",
                    constraint= "false"  if is_back else "true",
                )

        out = os.path.join(self.output_dir, filename)
        g.render(out, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out + ".png")

    # ── Leyenda standalone ────────────────────────────────────────────────────

    @staticmethod
    def render_legend(output_dir: str = "output/legend",
                      dpi: int = 200) -> str:
        os.makedirs(output_dir, exist_ok=True)
        g = graphviz.Digraph(name="legend_cfg")
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
                   f'Figure B. Node Classification Legend — CFG</FONT></B></TD></TR>'
                   f'<TR><TD><FONT FACE="{_FONT_TITLE}" POINT-SIZE="10">'
                   f'<I>Control Flow Graph · Security Linter, Phase 2</I>'
                   f'</FONT></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")

        g.node("sep", label=(
            f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="2">'
            f'<TR><TD WIDTH="560" HEIGHT="1" BGCOLOR="#333333"></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")
        g.edge("title", "sep", style="invis")

        entries = [
            ("entry",    "ENTRY",     "Program start",
             "#111111","2.5","solid","1","circle","white"),
            ("exit",     "EXIT",      "Program end — all paths terminate here",
             "#444444","2.5","solid","1","circle","white"),
            ("assign",   "ASSIGN",    "Assignment or augmented assignment (x = …, x += …)",
             "#ffffff","1.2","solid","1","rectangle","black"),
            ("call",     "CALL",      "Expression statement — function/method call\n"
                                      "Double border if it is a SQL sink (execute…)",
             "#aaaaaa","1.8","solid","1","rectangle","black"),
            ("cond",     "CONDITION", "Conditional test — if / elif / while\n"
                                      "Outgoing edges labelled T (true) / F (false)",
             "#555555","2.0","solid","1","diamond","white"),
            ("merge",    "MERGE",     "Convergence point — branches re-join\n"
                                      "Also used as loop exit",
             "#dddddd","1.2","dashed","1","diamond","black"),
            ("loop",     "LOOP_HEAD", "Loop header — while / for condition\n"
                                      "Back-edge (dashed) returns from body",
             "#333333","2.0","solid","1","hexagon","white"),
            ("ret",      "RETURN",    "return statement — adds edge to EXIT",
             "#888888","1.5","solid","1","rectangle","white"),
            ("imp",      "IMPORT",    "import / from … import statement",
             "#f5f5f5","0.8","dashed","1","rectangle","black"),
            ("fdef",     "FUNC_DEF",  "Function definition — double border\n"
                                      "Body is sequentially chained inside",
             "#444444","2.0","solid","2","rectangle","white"),
        ]

        prev_ex = "sep"
        for slug, tp_name, desc, fill, pw, bs, peri, shape, fc in entries:
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
                       f'label</FONT></TD></TR></TABLE>>'),
                shape=shape, fillcolor=fill, penwidth=pw, peripheries=peri,
                color="black", style=f"filled,{bs}", width="2.2",
            )

            desc_lines = desc.split("\n")
            desc_rows = "".join(
                f'<TR><TD ALIGN="LEFT"><FONT FACE="{_FONT_TITLE}" POINT-SIZE="9">'
                f'{_esc(l)}</FONT></TD></TR>' for l in desc_lines
            )
            g.node(desc_id,
                label=f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="1" CELLPADDING="2">'
                      f'{desc_rows}</TABLE>>',
                shape="plaintext", fillcolor="white", penwidth="0", width="4.0")

            with g.subgraph() as row:
                row.attr(rank="same")
                row.node(ex_id); row.node(desc_id)

            g.node(anch_id, shape="point", width="0.01",
                   fillcolor="white", color="white", penwidth="0")
            with g.subgraph() as row2:
                row2.attr(rank="same"); row2.node(anch_id)

            g.edge(prev_ex, ex_id, style="invis")
            g.edge(ex_id, desc_id, arrowhead="none", penwidth="0.7",
                   color="#bbbbbb", constraint="false")
            g.edge(ex_id, anch_id, style="invis")

            prev_ex = anch_id

        # Pie con nota de aristas
        g.node("footer",
            label=(f'<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="4">'
                   f'<TR><TD WIDTH="560" HEIGHT="1" BGCOLOR="#333333"></TD></TR>'
                   f'<TR><TD ALIGN="LEFT"><FONT FACE="{_FONT_TITLE}" POINT-SIZE="8" COLOR="#555555">'
                   f'<I>Edges: solid = sequential flow · T/F labels on CONDITION · '
                   f'dashed = back-edge (loop) · double border = high-security node</I>'
                   f'</FONT></TD></TR></TABLE>>'),
            shape="plaintext", fillcolor="white", penwidth="0")
        g.edge(prev_ex, "footer", style="invis")

        out = os.path.join(output_dir, "legend_cfg")
        g.render(out, format="png", cleanup=True, quiet=True)
        return os.path.abspath(out + ".png")

    def _configure(self, g: graphviz.Digraph, caption: str):
        lbl = (f'<<FONT FACE="{_FONT_TITLE}" POINT-SIZE="11">'
               f'<I>{_esc(caption)}</I></FONT>>') if caption else ""
        g.attr(rankdir=self.rankdir, bgcolor="white", fontname=_FONT_TITLE,
               splines="ortho", nodesep="0.5", ranksep="0.65",
               pad="0.55", dpi=str(self.dpi),
               label=lbl, labelloc="b", labeljust="c")
        g.attr("node", fontname=_FONT_TITLE, fontsize="10",
               color="black", style="filled", margin="0.12,0.07")
        g.attr("edge", color="black", fontname=_FONT_TITLE, fontsize="8",
               fontcolor="#333333", arrowsize="0.65", penwidth="0.9",
               arrowhead="normal")
