#!/usr/bin/env python3
"""
build_edges.py -- parse the ASCII attack trees into the "Attack Tree Edges"
sheet that evaluate.py needs for gate propagation.

    python3 build_edges.py

Reads  : ../input/attack-trees-ascii.txt   (the rendered trees)
         ../Control_Traceability_Matrix.xlsx  (node IDs, gate types, leaf list)
Writes : ../output/Attack_Tree_Edges.xlsx  -- one sheet, ready to copy across
         ../output/attack_tree_edges.csv   -- same rows, for paste-special
         ../output/edges_build_report.txt  -- what matched, what did not

WHY A SEPARATE FILE RATHER THAN EDITING THE WORKBOOK
    The scoring columns in the leaf matrix are Excel formulas, and this
    toolchain reads the cached values Excel stores beside them. openpyxl drops
    that cache on save -- so a script that appended a sheet to the workbook
    would leave every formula intact and every value blank. The edges therefore
    ship as their own file:

        open Attack_Tree_Edges.xlsx, right-click the sheet tab,
        Move or Copy -> To book: Control_Traceability_Matrix.xlsx -> Copy

    Keep the sheet name exactly "Attack Tree Edges", save in Excel, then re-run
    evaluate.py.

PARSING
    Depth comes from the column of the branch character, so the drawing's own
    indentation defines the hierarchy. Gate labels are matched back to node IDs
    from the structure sheet; a gate whose label matches no node is treated as
    an unnamed pass-through and collapsed into its parent (see the report --
    there are three, and in every case the workbook's gate type for the parent
    already equals the pass-through's, so collapsing changes no semantics).
"""

from __future__ import annotations

import csv
import re
from collections import Counter

import openpyxl

import core as C
from core import Model, OUTPUT_DIR, PROJECT_DIR

ASCII_PATH = PROJECT_DIR / "input" / "attack-trees-ascii.txt"
SHEET_NAME = C.SHEET_EDGES          # "Attack Tree Edges"

BRANCH = "├└"
GATE_RE = re.compile(r"\[(AND|OR)\]\s*(.*)$")
LEAF_RE = re.compile(r"\b(L-\d{3})\b")
TREE_RE = re.compile(r"\((AN-\d+)\)")
# leading outline numbering: "1. ", "1.1 ", "2.1. ", "1.1.1. "
NUM_RE = re.compile(r"^\d+(?:\.\d+)*\.?\s+")


def norm(s: str) -> str:
    """Normalise a label for matching: case, whitespace, trailing punctuation."""
    s = re.sub(r"\s+", " ", (s or "").strip())
    s = re.sub(r"[.;:,]+$", "", s)
    return s.lower()


def parse(text: str, node_by_label: dict[str, str]):
    """
    Walk the drawing and emit (tree, parent_id, child_id) in document order.
    Also returns the diagnostics the report needs.
    """
    edges = []
    passthrough = []        # (tree, label, gate, absorbed_into)
    gate_decl = {}          # node_id -> gate type as the drawing labels it
    unmatched = []          # (tree, label) gate labels that matched no node
    tree = None
    stack = []              # [(column, node_id)]

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        # tree header, e.g. "The Unknowingly Altered Print File (AN-1):"
        hit = TREE_RE.search(line)
        if hit and "GOAL" not in line and not any(c in line for c in BRANCH):
            tree = hit.group(1)
            stack = [(-1, tree)]
            continue
        if line.lstrip().startswith("GOAL"):
            continue
        if tree is None:
            continue

        col = min((line.index(c) for c in BRANCH if c in line), default=None)
        if col is None:
            continue

        # the parent is the deepest open node strictly shallower than this one
        while stack and stack[-1][0] >= col:
            stack.pop()
        parent = stack[-1][1] if stack else tree

        g = GATE_RE.search(line)
        if g:
            gate, label = g.group(1), NUM_RE.sub("", g.group(2).strip())
            nid = node_by_label.get(norm(label))
            if nid is None:
                # Unnamed pass-through ("Initial access vector", "Cause",
                # "Path"). It carries no node row, so it cannot be an edge
                # endpoint. Its children attach to its parent instead.
                passthrough.append((tree, label, gate, parent))
                unmatched.append((tree, label))
                stack.append((col, parent))
            else:
                edges.append((tree, parent, nid))
                gate_decl[nid] = gate
                stack.append((col, nid))
            continue

        lf = LEAF_RE.search(line)
        if lf:
            edges.append((tree, parent, lf.group(1)))

    return edges, passthrough, gate_decl, unmatched


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if not ASCII_PATH.exists():
        raise SystemExit(f"ASCII trees not found at {ASCII_PATH}")

    m = Model()
    node_by_label = {norm(n.label): n.id for n in m.nodes if not n.is_leaf}
    edges, passthrough, gate_decl, unmatched = parse(
        ASCII_PATH.read_text(), node_by_label)

    # child_order, numbered within each parent in document order
    seen = Counter()
    rows = []
    for tree, parent, child in edges:
        seen[(tree, parent)] += 1
        rows.append((tree, parent, child, seen[(tree, parent)]))

    # ---- write the sheet -------------------------------------------------
    # Header text comes from ctm_core so the writer and the reader cannot
    # drift apart. Reading canonicalises headers, so renaming these does not
    # break an existing workbook.
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = SHEET_NAME
    ws.append(list(C.EDGE_COLUMNS))
    for r in rows:
        ws.append(list(r))
    bold = openpyxl.styles.Font(bold=True)
    for cell in ws[1]:
        cell.font = bold
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:D{ws.max_row}"
    for col, head in zip("ABCD", C.EDGE_COLUMNS):
        ws.column_dimensions[col].width = max(11, len(head) + 4)
    xlsx = OUTPUT_DIR / "Attack_Tree_Edges.xlsx"
    wb.save(xlsx)

    csv_path = OUTPUT_DIR / "attack_tree_edges.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(list(C.EDGE_COLUMNS))
        w.writerows(rows)

    # ---- report ----------------------------------------------------------
    L = []
    w = L.append
    w("=" * 78)
    w("ATTACK TREE EDGES -- BUILD REPORT")
    w("=" * 78)
    w(f"source drawing : {ASCII_PATH.name}")
    w(f"workbook       : {m.workbook_path.name}")
    w(f"edges built    : {len(rows)}")
    w("")
    for t in m.trees:
        te = [r for r in rows if r[0] == t]
        gates = {r[2] for r in te if r[2].startswith("N-")}
        leaves = {r[2] for r in te if r[2].startswith("L-")}
        w(f"  {t}: {len(te):>3} edges   {len(gates)} gates   {len(leaves)} distinct leaves")
    w("")

    w("-" * 78)
    w("UNNAMED PASS-THROUGH GATES, COLLAPSED")
    w("-" * 78)
    if not passthrough:
        w("  none")
    for tree, label, gate, parent in passthrough:
        pg = m.node_by_id[parent].gate if parent in m.node_by_id else "?"
        ok = "consistent" if pg == gate else f"*** DIFFERS from parent gate {pg} ***"
        w(f"  {tree}  [{gate}] \"{label}\"  ->  absorbed into {parent} (gate {pg})   {ok}")
    w("")
    w("  These appear in the drawing but have no row in the structure sheet, so")
    w("  they cannot be edge endpoints. Each has exactly one parent and only leaf")
    w("  children, and in every case the parent's gate type already equals the")
    w("  pass-through's -- so collapsing them changes no computed value.")
    w("")

    w("-" * 78)
    w("GATE TYPE: DRAWING vs WORKBOOK")
    w("-" * 78)
    diffs = [(nid, g, m.node_by_id[nid].gate) for nid, g in sorted(gate_decl.items())
             if nid in m.node_by_id and m.node_by_id[nid].gate != g]
    if not diffs:
        w("  all gate types agree")
    else:
        w("  The workbook is authoritative -- propagation reads its gate column, not")
        w("  the drawing. These disagree:")
        w("")
        for nid, drawn, book in diffs:
            lab = m.node_by_id[nid].label
            w(f"    {nid}  drawing says {drawn:<3}  workbook says {book:<3}  {lab[:46]}")
        w("")
        w("  Every one of these is a gate whose unnamed pass-through child carries the")
        w("  workbook's type, so after collapsing, the effective gate over the leaves")
        w("  matches the workbook. The drawing's label is the artefact, not the model.")
    w("")

    w("-" * 78)
    w("COVERAGE AGAINST THE LEAF MATRIX")
    w("-" * 78)
    placed = {}
    for tree, _parent, child, _o in rows:
        if child.startswith("L-"):
            placed.setdefault(child, set()).add(tree)
    claimed = {lf.id: set(lf.trees) for lf in m.leaves}

    never = sorted(set(claimed) - set(placed))
    w(f"  leaves placed in the drawing : {len(placed)} of {len(m.leaves)}")
    w(f"  leaves placed nowhere        : {', '.join(never) if never else 'none'}")
    w("")

    extra, missing = [], []
    for lid, trees in sorted(claimed.items()):
        got = placed.get(lid, set())
        for t in sorted(trees - got):
            missing.append((lid, t))
        for t in sorted(got - trees):
            extra.append((lid, t))

    w("  (a) Claimed by the matrix, absent from the drawing:")
    if not missing:
        w("      none")
    for lid, t in missing:
        lf = m.by_id[lid]
        w(f"      {lid} in {t}   {lf.short(52)}")
    if missing:
        w("")
        w("      These leaves name that tree in their 'Attack Trees' cell but do not")
        w("      appear in its drawing. Until that is resolved they contribute to the")
        w("      tree's AGGREGATE total but not to its PROPAGATED value, because")
        w("      propagation can only reach a leaf through an edge.")
        w("      Either add the branch to the drawing and re-run this script, or drop")
        w("      the tree from the leaf's cell. Do not leave them disagreeing.")
    w("")
    w("  (b) In the drawing, not claimed by the matrix:")
    if not extra:
        w("      none")
    for lid, t in extra:
        w(f"      {lid} in {t}   {m.by_id[lid].short(52)}")
    w("")

    dup = [(lid, t, n) for (lid, t), n in
           Counter((r[2], r[0]) for r in rows if r[2].startswith("L-")).items() if n > 1]
    w("  (c) Leaves appearing more than once within one tree:")
    if not dup:
        w("      none")
    for lid, t, n in sorted(dup):
        parents = [r[1] for r in rows if r[2] == lid and r[0] == t]
        w(f"      {lid} appears {n}x in {t} under {', '.join(parents)}")
    if dup:
        w("      Legitimate -- the same condition can sit on two branches of one tree.")
        w("      MIN/MAX propagation handles it; the leaf is still counted once in the")
        w("      aggregate totals.")
    w("")

    w("  (d) Gate nodes in the structure sheet never used as an edge endpoint:")
    unused = sorted({n.id for n in m.nodes if n.is_gate} -
                    {r[2] for r in rows if r[2].startswith("N-")})
    w(f"      {', '.join(unused) if unused else 'none'}")
    w("")

    w("-" * 78)
    w("NEXT STEP")
    w("-" * 78)
    w(f"  1. Open {xlsx.name}")
    w("  2. Right-click the sheet tab -> Move or Copy")
    w(f"     To book: {m.workbook_path.name}    [x] Create a copy")
    w(f"  3. Confirm the sheet is named exactly: {SHEET_NAME}")
    w("  4. Save in EXCEL (never openpyxl -- it would blank the formula cache)")
    w("  5. Re-run evaluate.py")
    w("")
    w("  Propagated root values will then appear in scores_tree_level.txt and")
    w("  fig10_tree_propagation_bar.png.")

    rpt = OUTPUT_DIR / "edges_build_report.txt"
    rpt.write_text("\n".join(L) + "\n")

    print(f"edges built : {len(rows)}")
    for t in m.trees:
        n = len([r for r in rows if r[0] == t])
        print(f"  {t}: {n} edges")
    if missing:
        print(f"\nWARNING: {len(missing)} leaf-tree pairs claimed by the matrix are not in "
              f"the drawing:")
        for lid, t in missing:
            print(f"  {lid} in {t}")
        print("See edges_build_report.txt section (a).")
    print()
    for p in (xlsx, csv_path, rpt):
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
