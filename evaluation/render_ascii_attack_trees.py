#!/usr/bin/env python3
"""
render_ascii.py — render any attack tree from traceability_matrix.xlsx as an
ASCII outline, so the report text can never drift from the computed model.

    python render_ascii.py            # all trees
    python render_ascii.py AN-1       # one tree
    python render_ascii.py AN-1 --status mediated   # annotate leaf status
"""

import argparse
import sys
import pandas as pd

TYPE_FLAG = {"Frequency": "[F]", "Condition": "[V]"}


def load(path):
    nodes = pd.read_excel(path, sheet_name="nodes").set_index("node_id")
    edges = pd.read_excel(path, sheet_name="edges")
    leaves = pd.read_excel(path, sheet_name="leaf_scoring").set_index("leaf_id")
    kids = {}
    for tree, g in edges.groupby("tree"):
        for parent, sub in g.groupby("parent_id"):
            kids[(tree, parent)] = list(sub.sort_values("child_order")["child_id"])
    return nodes, kids, leaves, sorted(edges["tree"].unique())


def render(tree, nodes, kids, leaves, status=None):
    out = [f"GOAL: {nodes.at[tree, 'label']}"]

    def walk(node, prefix, number, is_last, depth):
        children = kids.get((tree, node), [])
        gate = nodes.at[node, "gate"] if node in nodes.index else None
        is_leaf = str(node).startswith("L-")

        elbow = "└─" if is_last else "├─"
        if is_leaf:
            row = leaves.loc[node]
            flag = TYPE_FLAG.get(row["leaf_type"], "")
            line = f"{prefix}{elbow} {node} {row['description']} {flag}"
            if status:
                st = row.get(f"{status}_status", "")
                lk = row.get(f"{status}_lkhd", "")
                if pd.notna(st) and st not in ("", "nan"):
                    lk_txt = "" if pd.isna(lk) else f", lkhd {lk:.0f}"
                    line += f"  <{st}{lk_txt}>"
            out.append(line)
            return

        label = nodes.at[node, "label"]
        num = f"{number}. " if number else ""
        out.append(f"{prefix}{elbow}[{gate}] {num}{label}")

        child_prefix = prefix + ("   " if is_last else "│  ")
        out.append(child_prefix + "│")
        gate_i = 0
        for i, c in enumerate(children):
            last = i == len(children) - 1
            if str(c).startswith("L-"):
                cn = ""
            else:
                gate_i += 1
                cn = f"{number}.{gate_i}" if number else str(gate_i)
            if i and not str(c).startswith("L-") and str(children[i - 1]).startswith("L-"):
                out.append(child_prefix + "│")
            walk(c, child_prefix, cn, last, depth + 1)
            if not last and not str(c).startswith("L-"):
                out.append(child_prefix + "│")

    top = kids.get((tree, tree), [])
    out.append("│")
    for i, c in enumerate(top):
        last = i == len(top) - 1
        walk(c, "", str(i + 1), last, 1)
        if not last:
            out.append("│")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tree", nargs="?", default=None)
    ap.add_argument("--workbook", default="traceability_matrix.xlsx")
    ap.add_argument("--status", choices=["baseline", "observational", "mediated"])
    a = ap.parse_args()

    nodes, kids, leaves, trees = load(a.workbook)
    targets = [a.tree] if a.tree else trees
    for t in targets:
        if t not in trees:
            sys.exit(f"unknown tree {t}; have {trees}")
        print(render(t, nodes, kids, leaves, a.status))
        print()


if __name__ == "__main__":
    main()