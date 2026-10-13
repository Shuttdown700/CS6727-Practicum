#!/usr/bin/env python3
"""
Description: Ingest the Control Traceability Matrix workbook, score it, and
write infographics (.png) plus raw score dumps (.txt) to ../output.

    python3 evaluate.py

No arguments. All configuration lives in ctm_core.py.

WHAT THIS PRODUCES
    fig01_aggregate_risk_bar.png      aggregate risk by variant, split by leaf type
    fig02_tree_risk_bar.png           per-tree risk, grouped by variant
    fig03_tree_delta_bar.png          per-tree change against baseline (diverging)
    fig04_leaf_dumbbell_dot.png       every leaf: baseline -> variant (dot plot)
    fig05_leaf_delta_dot.png          per-leaf change against baseline (dot plot)
    fig06_coverage_stacked_bar.png    condition-leaf status counts by variant
    fig07_cumulative_risk_line.png    cumulative risk across ranked leaves (line)
    fig08_feature_attribution_bar.png risk reduction attributable to each feature
    fig09_riskclass_bar.png           risk by risk class, grouped by variant
    fig10_tree_propagation_bar.png    gate-propagated root values  [EDGES ONLY]

    scores_summary.txt                headline numbers
    scores_leaf_level.txt             full per-leaf table
    scores_tree_level.txt             per-tree aggregates (+ propagation if available)
    validation_report.txt             integrity checks against the NIST matrices
    attack_tree_edges_TEMPLATE.csv    emitted only when no edge table is present

A NOTE ON TREE-LEVEL SCORES
    Two different things can be called "tree-level risk" and this script
    distinguishes them:

    (a) AGGREGATE  -- the sum of leaf risk over leaves whose "Attack Trees"
        field names that tree. Always available. Measures total exposure
        carried by the tree. Because a shared leaf counts once per tree, the
        tree totals deliberately do not sum to the grand total.

    (b) PROPAGATED -- MIN/MAX pushed up through the AND/OR gates to the root.
        Measures the easiest path. This requires parent/child relationships,
        which the workbook does not currently record: the "Attack Tree
        Structure" sheet lists nodes and gate types but no edges. Add an
        "Attack Tree Edges" sheet (columns Tree / Parent ID / Child ID /
        Child Order) and this script computes it automatically. build_edges.py
        generates that sheet from the ASCII trees; run evaluate.py once
        without it and a blank template is written to ../output instead.
"""

from __future__ import annotations

import csv
from collections import Counter, defaultdict

import numpy as np
import matplotlib.pyplot as plt

import core as C
from core import Model, OUTPUT_DIR, SERIES, DIV_GOOD, DIV_BAD, DIV_ZERO, INK, INK_SOFT, INK_MUTED


# =============================================================================
# The gate skeleton below is INFERRED from the node labels and the N-1xx
# numbering in the structure sheet, for the edge template only. It is never used
# for scoring. Leaf placement cannot be inferred -- the leaf matrix records
# which TREE a leaf belongs to, not which GATE -- so those rows are left blank
# in the template for you to fill, with the candidate gates listed alongside.
# =============================================================================
INFERRED_GATE_EDGES = {
    "AN-1": [("AN-1", "N-110"), ("AN-1", "N-120"),
             ("N-110", "N-101"), ("N-110", "N-102"), ("N-110", "N-103"),
             ("N-101", "N-111"), ("N-101", "N-112"), ("N-101", "N-113"),
             ("N-120", "N-114"), ("N-120", "N-115")],
    "AN-3": [("AN-3", "N-301"), ("AN-3", "N-302"), ("AN-3", "N-303")],
    "AN-5": [("AN-5", "N-501"), ("AN-5", "N-502"),
             ("N-501", "N-511"), ("N-501", "N-512")],
    "AN-7": [("AN-7", "N-701"), ("AN-7", "N-702"),
             ("AN-7", "N-703"), ("AN-7", "N-704")],
}


# =============================================================================
# helpers
# =============================================================================

def label_bars(ax, bars, fmt="{:.0f}", dy=0.6, fontsize=7.6, skip_zero=False):
    """
    Direct value labels. Two of the three series colors sit below 3:1 contrast
    on the ggplot surface, so the palette's relief rule requires either visible
    labels or a table view -- this provides the former, and the .txt dumps the
    latter.
    """
    for b in bars:
        h = b.get_height()
        if skip_zero and h == 0:
            continue
        ax.text(b.get_x() + b.get_width() / 2, h + dy, fmt.format(h),
                ha="center", va="bottom", fontsize=fontsize, color=INK_SOFT)


def grouped_bars(ax, categories, series_values, width=0.26):
    """Grouped bars with one bar per variant. Returns {variant: bar_container}."""
    x = np.arange(len(categories))
    n = len(series_values)
    out = {}
    for i, (name, vals) in enumerate(series_values.items()):
        off = (i - (n - 1) / 2) * width
        out[name] = ax.bar(x + off, vals, width * 0.92, label=name,
                           color=SERIES[name], edgecolor="none", zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    return out


def pct(new, old):
    return 0.0 if not old else 100.0 * (old - new) / old


# =============================================================================
# figures
# =============================================================================

def fig_aggregate(m: Model):
    """Grouped bar -- the headline comparison, on the like-for-like leaf set."""
    common = m.common_leaves()
    freq = [lf for lf in common if lf.is_frequency]
    cond = [lf for lf in common if lf.is_condition]

    cats = [f"Frequency leaves\n(n={len(freq)})",
            f"Condition leaves\n(n={len(cond)})",
            f"Common set\n(n={len(common)})"]
    vals = {v: [m.total(v, freq), m.total(v, cond), m.total(v, common)]
            for v in m.variant_names}

    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    bars = grouped_bars(ax, cats, vals)
    for c in bars.values():
        label_bars(ax, c, dy=3)

    ax.set_ylabel("Aggregate leaf risk")
    ax.set_title("Aggregate leaf risk by variant, common 47-leaf set")
    ax.legend(loc="upper left", ncols=3)
    ax.set_ylim(0, max(vals[C.BASELINE]) * 1.18)

    med_only = m.variant_only_leaves("Mediated")
    note = (
        "Frequency-leaf risk is constant by construction: the architecture does not change how often an event occurs, so the entire\n"
        f"variant delta lives in the condition leaves. Condition-leaf reduction: observational {pct(m.total('Observational', cond), m.total(C.BASELINE, cond)):.1f}%, "
        f"mediated {pct(m.total('Mediated', cond), m.total(C.BASELINE, cond)):.1f}%.\n"
        f"Excluded here: {len(med_only)} leaves that exist only under the mediated variant and carry "
        f"{m.total('Mediated', med_only)} points of introduced risk (see scores_summary.txt)."
    )
    return C.finish(fig, ax, OUTPUT_DIR / "fig01_aggregate_risk_bar.png", note)


def fig_tree_risk(m: Model):
    """Grouped bar -- aggregate risk per tree."""
    trees = m.trees
    vals = {v: [m.tree_total(t, v) for t in trees] for v in m.variant_names}
    cats = [f"{t}\n(n={len(m.leaves_in(t))})" for t in trees]

    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    bars = grouped_bars(ax, cats, vals)
    for c in bars.values():
        label_bars(ax, c, dy=2, skip_zero=True)

    ax.set_ylabel("Aggregate leaf risk")
    ax.set_title("Aggregate leaf risk by attack tree and variant")
    ax.legend(loc="upper right", ncols=3)
    ax.set_ylim(0, max(max(v) for v in vals.values()) * 1.18)

    note = ("Sum of leaf risk over leaves assigned to each tree. A leaf shared by two trees counts once in each, so tree totals do not\n"
            "sum to the grand total. AN-7 is zero at baseline and observational because its leaves presuppose a mediating service to fail.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig02_tree_risk_bar.png", note)


def fig_tree_delta(m: Model):
    """Diverging horizontal bar -- change against baseline, per tree."""
    variants = [v for v in m.variant_names if v != C.BASELINE]
    trees = m.trees
    fig, axes = plt.subplots(1, len(variants), figsize=(10.4, 4.2), sharex=True)
    if len(variants) == 1:
        axes = [axes]

    def present(tree, variant):
        """Does this tree have any leaf scored under this variant?"""
        return any(lf.present(variant) for lf in m.leaves_in(tree))

    allv = []
    for v in variants:
        allv += [m.tree_total(t, v) - m.tree_total(t, C.BASELINE)
                 for t in trees if present(t, v) or present(t, C.BASELINE)]
    lim = max(abs(min(allv)), abs(max(allv))) * 1.34 or 1

    absent = []
    for ax, v in zip(axes, variants):
        y = np.arange(len(trees))
        for i, t in enumerate(trees):
            # A tree with no leaves under either variant is NOT a zero change --
            # it is not applicable. Drawing a zero bar would assert "no effect"
            # where the honest statement is "does not exist yet".
            if not present(t, v) and not present(t, C.BASELINE):
                absent.append((t, v))
                ax.text(0, i, "  not applicable - tree absent under both",
                        va="center", ha="left", fontsize=7.6, style="italic",
                        color=INK_MUTED)
                continue
            d = m.tree_total(t, v) - m.tree_total(t, C.BASELINE)
            col = DIV_ZERO if d == 0 else (DIV_GOOD if d < 0 else DIV_BAD)
            ax.barh(i, d, 0.6, color=col, edgecolor="none", zorder=3)
            off = lim * 0.025
            ax.text(d + (off if d >= 0 else -off), i, f"{d:+d}" if d else "0",
                    va="center", ha="left" if d >= 0 else "right",
                    fontsize=8, color=INK_SOFT)
        ax.set_yticks(y)
        ax.set_yticklabels(trees)
        ax.invert_yaxis()
        ax.axvline(0, color=INK_SOFT, lw=1.1, zorder=4)
        ax.set_xlim(-lim, lim)
        ax.set_title(f"{v} vs {C.BASELINE}", fontsize=10.5)
        ax.set_xlabel("Change in aggregate leaf risk")

    fig.suptitle("Change in tree-level risk against baseline", y=1.02,
                 fontsize=12, fontweight="bold", color=INK)
    note = ("Blue is a reduction, red an increase, grey no change. AN-7 increases under the mediated variant because the architecture\n"
            "introduces a service that can fail -- a real cost of the design, not an artefact of the scoring."
            + ("\nWhere a tree exists under neither variant it is marked not-applicable rather than drawn as a zero bar, which would "
               "assert\nno effect where the honest statement is that the tree does not exist yet." if absent else ""))
    return C.finish(fig, axes, OUTPUT_DIR / "fig03_tree_delta_bar.png", note)


def fig_leaf_dumbbell(m: Model):
    """
    Dot plot -- every leaf, baseline through mediated. The leaf-level
    against-baseline view, and the densest single figure in the set.
    """
    leaves = sorted(m.leaves,
                    key=lambda lf: (-(lf.risk[C.BASELINE] or -1),
                                    -(lf.risk["Mediated"] or -1), lf.id))
    y = np.arange(len(leaves))

    fig, ax = plt.subplots(figsize=(9.6, 15.0))

    # Shade rows for leaves that do not exist at baseline. Without this a lone
    # small marker is ambiguous: it could mean all three variants agree, or
    # that only one of them scores the leaf at all.
    absent_rows = [i for i, lf in enumerate(leaves) if not lf.present(C.BASELINE)]
    for i in absent_rows:
        ax.axhspan(i - 0.5, i + 0.5, color="#d6d5cf", alpha=0.55, zorder=0, lw=0)

    # connector first, so markers sit on top
    for i, lf in enumerate(leaves):
        a, b = lf.risk[C.BASELINE], lf.risk["Mediated"]
        if a is not None and b is not None and a != b:
            ax.plot([a, b], [i, i], color="#bfbeb8", lw=1.5, zorder=2,
                    solid_capstyle="round")

    # The x-axis has only five possible values, so variants coincide constantly
    # and equal-size markers would hide each other entirely. Markers are drawn
    # largest-first in variant order and nest: a single dot means all three
    # agree, concentric rings show which ones do. Size here is draw order, not
    # magnitude.
    sizes = [150, 70, 26]
    for v, s in zip(m.variant_names, sizes):
        pts = [(lf.risk[v], i) for i, lf in enumerate(leaves) if lf.present(v)]
        if pts:
            ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=s,
                       color=SERIES[v], label=v, zorder=4,
                       edgecolors="#ffffff", linewidths=1.1)

    ax.set_yticks(y)
    ax.set_yticklabels(
        [f"{lf.id}  {lf.short(42)}" for lf in leaves], fontsize=6.9)
    ax.invert_yaxis()
    ax.set_xticks(C.BAND_LADDER)
    ax.set_xlabel("Residual risk score")
    ax.set_xlim(-0.7, 10.7)
    ax.set_ylim(len(leaves) - 0.4, -0.6)
    ax.set_title("Leaf-level residual risk by variant, ranked by baseline risk")
    ax.legend(loc="lower right", ncols=1, markerscale=0.8)
    ax.grid(axis="y", lw=0.4)

    note = (f"Markers nest largest-to-smallest in variant order; size is draw order, not magnitude. On an unshaded row a lone small green\n"
            f"dot means all three variants agree -- either a frequency leaf, constant by construction, or a condition leaf no variant moves.\n"
            f"The {len(absent_rows)} shaded rows are leaves with no baseline score at all: the AN-7 leaves presuppose a mediating service to fail, so they\n"
            f"exist only under the mediated variant and their single marker is the only score there is.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig04_leaf_dumbbell_dot.png", note)


def fig_leaf_delta(m: Model):
    """Dot plot -- per-leaf change against baseline, only leaves that move."""
    variants = [v for v in m.variant_names if v != C.BASELINE]
    movers = [lf for lf in m.leaves
              if lf.present(C.BASELINE)
              and any(lf.present(v) and lf.risk[v] != lf.risk[C.BASELINE] for v in variants)]
    movers.sort(key=lambda lf: (lf.risk["Mediated"] - lf.risk[C.BASELINE]
                                if lf.present("Mediated") else 0, lf.id))
    y = np.arange(len(movers))

    fig, ax = plt.subplots(figsize=(9.0, max(4.0, 0.30 * len(movers) + 1.6)))
    ax.axvline(0, color=INK_SOFT, lw=1.1, zorder=4)
    for i, lf in enumerate(movers):
        ds = [lf.risk[v] - lf.risk[C.BASELINE] for v in variants if lf.present(v)]
        if ds:
            ax.plot([min(ds + [0]), max(ds + [0])], [i, i],
                    color="#bfbeb8", lw=1.4, zorder=2, solid_capstyle="round")
    for v in variants:
        pts = [(lf.risk[v] - lf.risk[C.BASELINE], i)
               for i, lf in enumerate(movers) if lf.present(v)]
        ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=48,
                   color=SERIES[v], label=f"{v} vs {C.BASELINE}", zorder=4,
                   edgecolors="#ffffff", linewidths=1.0)

    ax.set_yticks(y)
    ax.set_yticklabels([f"{lf.id}  {lf.short(40)}" for lf in movers], fontsize=7.2)
    ax.invert_yaxis()
    ax.set_xlabel("Change in residual risk against baseline")
    ax.set_title(f"Per-leaf change against baseline ({len(movers)} leaves that move)")
    # outside the axes: inside, it lands on the lowest rows
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.055 - 2.2 / max(len(movers), 1)),
              ncols=2)
    ax.grid(axis="y", lw=0.4)

    still = len([lf for lf in m.leaves if lf.present(C.BASELINE)]) - len(movers)
    note = (f"{still} of the {len([lf for lf in m.leaves if lf.present(C.BASELINE)])} leaves scored at baseline do not move under any variant and are omitted.\n"
            "A leaf can improve in status without moving here: Table I-2 returns the same risk at likelihood 10 and likelihood 5 when\n"
            "impact is Moderate, so a partial control on a Moderate-impact leaf is numerically invisible. Read this beside fig06.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig05_leaf_delta_dot.png", note)


def fig_coverage(m: Model):
    """Stacked bar -- condition-leaf status counts. The breadth measure."""
    variants = m.variant_names
    counts = {v: Counter(lf.status[v] for lf in m.leaves
                         if lf.is_condition and lf.status[v] in C.MEDIATION_STATUS_ORDER)
              for v in variants}

    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    x = np.arange(len(variants))
    bottom = np.zeros(len(variants))
    for st in C.MEDIATION_STATUS_ORDER:
        vals = np.array([counts[v].get(st, 0) for v in variants], dtype=float)
        ax.bar(x, vals, 0.54, bottom=bottom, label=st,
               color=C.MEDIATION_STATUS_FILL[st], edgecolor="#ffffff", linewidth=2.0, zorder=3)
        for xi, (v0, b0) in enumerate(zip(vals, bottom)):
            if v0 > 0:
                ax.text(xi, b0 + v0 / 2, f"{int(v0)}", ha="center", va="center",
                        fontsize=8.5,
                        color="#ffffff" if st == "Unaddressed" else INK)
        bottom += vals

    ax.set_xticks(x)
    ax.set_xticklabels([f"{v}\n(n={int(sum(counts[v].values()))})" for v in variants])
    ax.set_ylabel("Condition leaves")
    ax.set_title("Condition-leaf control coverage by variant")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncols=3)

    note = ("Counted over condition leaves only; frequency leaves have no control status. Report this beside the risk totals: the\n"
            "observational variant moves nine leaves to Partial for a far smaller change in score, and neither measure alone is honest.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig06_coverage_stacked_bar.png", note)


def fig_cumulative(m: Model):
    """Line plot -- cumulative risk across leaves ranked by baseline risk."""
    leaves = sorted([lf for lf in m.leaves if lf.present(C.BASELINE)],
                    key=lambda lf: (-lf.risk[C.BASELINE], lf.id))
    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    x = np.arange(1, len(leaves) + 1)
    for v in m.variant_names:
        cum = np.cumsum([lf.risk[v] if lf.present(v) else 0 for lf in leaves])
        ax.plot(x, cum, label=f"{v} ({int(cum[-1])})", color=SERIES[v], zorder=3)
        ax.annotate(f"{int(cum[-1])}", (x[-1], cum[-1]),
                    textcoords="offset points", xytext=(6, 0),
                    va="center", fontsize=8.5, color=INK_SOFT)

    ax.set_xlabel("Leaves, ranked by baseline risk (highest first)")
    ax.set_ylabel("Cumulative residual risk")
    ax.set_title("Cumulative risk across ranked leaves")
    ax.legend(loc="upper left")
    ax.set_xlim(1, len(leaves) + 3)

    half = m.total(C.BASELINE, leaves) / 2
    cumb = np.cumsum([lf.risk[C.BASELINE] for lf in leaves])
    k = int(np.searchsorted(cumb, half) + 1)
    note = (f"Ranking is fixed by baseline risk so the three curves stay comparable. Half of all baseline risk sits in the top {k} "
            f"leaves of {len(leaves)}.\nWhere the gap between a variant curve and the baseline curve stops widening, that variant is not reaching that part of the\n"
            "model; the steepest separation marks where it does the most work.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig07_cumulative_risk_line.png", note)


def fig_feature_attribution(m: Model):
    """Horizontal bar -- risk reduction attributable to each solution feature."""
    red = defaultdict(int)
    cnt = Counter()
    for lf in m.leaves:
        if not lf.feature:
            continue
        cnt[lf.feature] += 1
        if lf.present(C.BASELINE) and lf.present("Mediated"):
            red[lf.feature] += lf.risk[C.BASELINE] - lf.risk["Mediated"]
    if not red:
        return None

    # red[f] is already baseline-minus-mediated, so a reduction is positive.
    feats = sorted(red, key=lambda f: red[f])
    vals = [red[f] for f in feats]

    fig, ax = plt.subplots(figsize=(8.8, max(3.4, 0.46 * len(feats) + 1.8)))
    y = np.arange(len(feats))
    ax.barh(y, vals, 0.62, color=C.SEQ_BLUE[2], edgecolor="none", zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels([f"{f}  ({cnt[f]})" for f in feats], fontsize=8.5)
    for yy, xx in zip(y, vals):
        ax.text(xx + max(vals) * 0.012, yy, f"{int(xx)}", va="center",
                fontsize=8.2, color=INK_SOFT)
    ax.set_xlabel("Risk reduction against baseline (mediated variant)")
    ax.set_title("Risk reduction attributable to each solution feature")
    ax.set_xlim(0, max(vals) * 1.12)

    unmapped = [lf.id for lf in m.leaves
                if lf.is_condition and not lf.feature and lf.present("Mediated")]
    nobase = sorted({lf.feature for lf in m.leaves
                     if lf.feature and not lf.present(C.BASELINE)} - set(red))
    note = ("Leaf count in parentheses. A leaf credits its whole reduction to its single mapped feature, so these do not decompose a\n"
            "joint effect -- where two features both bear on a leaf, the matrix records only one.\n"
            + (f"Absent because every leaf they address exists only under the mediated variant, leaving no baseline to reduce against: "
               f"{', '.join(nobase)}.\n" if nobase else "")
            + (f"Condition leaves left unmapped under the mediated variant: {', '.join(unmapped)}." if unmapped else ""))
    return C.finish(fig, ax, OUTPUT_DIR / "fig08_feature_attribution_bar.png", note)


def fig_risk_class(m: Model):
    """Grouped bar -- risk by risk class."""
    classes = sorted({rc for lf in m.leaves for rc in lf.risk_classes})
    vals = {v: [sum(lf.risk[v] for lf in m.leaves
                    if rc in lf.risk_classes and lf.present(v))
                for rc in classes]
            for v in m.variant_names}

    fig, ax = plt.subplots(figsize=(9.2, 4.8))
    bars = grouped_bars(ax, classes, vals, width=0.27)
    for c in bars.values():
        label_bars(ax, c, dy=1.6, fontsize=7.0, skip_zero=True)
    ax.set_ylabel("Aggregate leaf risk")
    ax.set_xlabel("Risk class")
    ax.set_title("Aggregate leaf risk by risk class and variant")
    ax.legend(loc="upper right", ncols=3)
    ax.set_ylim(0, max(max(v) for v in vals.values()) * 1.16)

    note = ("A leaf mapped to two risk classes counts in both, so these columns do not sum to the grand total. Use this to find classes\n"
            "the architecture leaves untouched, not to apportion total risk.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig09_riskclass_bar.png", note)


def fig_propagation(m: Model):
    """Grouped bar -- gate-propagated root values. Requires the edge table."""
    if not m.has_edges:
        return None
    trees = [t for t in m.trees if t in m.node_by_id]
    raw = {v: [m.propagate(t, v).get(t) for t in trees] for v in m.variant_names}

    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    x = np.arange(len(trees))
    width = 0.26
    n = len(m.variant_names)
    absent = []
    for i, v in enumerate(m.variant_names):
        off = (i - (n - 1) / 2) * width
        for j, t in enumerate(trees):
            val = raw[v][j]
            if val is None:
                # Not a zero root -- the tree has nothing scored under this
                # variant. A zero bar would read as "no risk" rather than
                # "does not exist", which is a different claim entirely.
                absent.append((t, v))
                continue
            ax.bar(x[j] + off, val, width * 0.92, color=SERIES[v], zorder=3,
                   label=v if j == 0 or all(raw[v][k] is None for k in range(j)) else None)
            ax.text(x[j] + off, val + 0.18, f"{val:.0f}", ha="center", va="bottom",
                    fontsize=7.6, color=INK_SOFT)
    for t, v in absent:
        j = trees.index(t)
        i = m.variant_names.index(v)
        off = (i - (n - 1) / 2) * width
        ax.text(x[j] + off, 0.18, "n/a", ha="center", va="bottom", fontsize=7.0,
                style="italic", color=INK_MUTED, rotation=90)

    ax.set_xticks(x)
    ax.set_xticklabels(trees)
    ax.set_ylabel("Propagated root risk")
    ax.set_title("Gate-propagated root risk by tree and variant")
    ax.legend(loc="upper right", ncols=3)
    ax.set_ylim(0, 11.6)
    ax.set_yticks(C.BAND_LADDER)

    crit = []
    for t in trees:
        cc0 = m.critical_child(t, C.BASELINE)
        cc1 = m.critical_child(t, "Mediated")
        if cc0 and cc1 and cc0[0] != cc1[0]:
            crit.append(f"{t} ({cc0[0]} -> {cc1[0]})")
    note = ("OR gates take MAX (the easiest available path), AND gates MIN (the weakest necessary link) -- ordinal bands do not support\n"
            "probability arithmetic (Mauw & Oostdijk 2005). One effective control under an AND gate collapses the whole branch, so root\n"
            "values fall quickly; read this with the aggregate and coverage measures, never alone. 'n/a' marks a tree with nothing\n"
            "scored under that variant, which is not the same as a root of zero.\n"
            + (f"The branch setting the root changes between baseline and mediated in: {', '.join(crit)} -- the control shifts which path\n"
               "is easiest, rather than closing the goal." if crit else ""))
    return C.finish(fig, ax, OUTPUT_DIR / "fig10_tree_propagation_bar.png", note)


# =============================================================================
# text output
# =============================================================================

def write_summary(m: Model) -> list[str]:
    common = m.common_leaves()
    freq = [lf for lf in common if lf.is_frequency]
    cond = [lf for lf in common if lf.is_condition]
    med_only = m.variant_only_leaves("Mediated")

    L = []
    w = L.append
    w("=" * 78)
    w("CONTROL TRACEABILITY MATRIX -- EVALUATION SUMMARY")
    w("=" * 78)
    w(f"source    : {m.workbook_path.name}")
    w(f"leaves    : {len(m.leaves)}  ({sum(lf.is_frequency for lf in m.leaves)} frequency, "
      f"{sum(lf.is_condition for lf in m.leaves)} condition)")
    w(f"nodes     : {len(m.nodes)}  ({len(m.roots)} roots, "
      f"{sum(n.is_gate for n in m.nodes)} gates, {sum(n.is_leaf for n in m.nodes)} leaf nodes)")
    w(f"trees     : {', '.join(m.trees)}")
    w(f"edge table: {'loaded (' + str(len(m.edges)) + ' edges)' if m.has_edges else 'ABSENT -- propagated tree scores unavailable'}")
    w("")

    w("-" * 78)
    w("AGGREGATE LEAF RISK -- COMMON LEAF SET")
    w("-" * 78)
    w(f"The only like-for-like comparison. {len(common)} leaves scored under every variant;")
    w(f"{len(med_only)} further leaves exist only under the mediated variant and are reported")
    w("separately rather than mixed in.")
    w("")
    rows = [(f"frequency leaves (n={len(freq)})", freq),
            (f"condition leaves (n={len(cond)})", cond),
            (f"COMMON SET (n={len(common)})", common)]
    W = 36                                  # label column width
    w(f"  {'component':<{W}}" + "".join(f"{v:>15}" for v in m.variant_names))
    for label, pool in rows:
        w(f"  {label:<{W}}" + "".join(f"{m.total(v, pool):>15}" for v in m.variant_names))
    w("")
    w(f"  {'reduction against baseline':<{W}}" + "".join(f"{v:>15}" for v in m.variant_names))
    for label, pool in rows:
        b = m.total(C.BASELINE, pool)
        w(f"  {label:<{W}}" +
          "".join(f"{'--':>15}" if v == C.BASELINE
                  else f"{pct(m.total(v, pool), b):>14.1f}%"
                  for v in m.variant_names))
    w("")
    w(f"  risk introduced by the mediated architecture : {m.total('Mediated', med_only)}")
    w(f"    across {len(med_only)} leaves that exist only under it "
      f"({sum(lf.is_frequency for lf in med_only)} frequency, {sum(lf.is_condition for lf in med_only)} condition)")
    w(f"  mediated all-in total                        : {m.total('Mediated', common)} + "
      f"{m.total('Mediated', med_only)} = {m.total('Mediated')}")
    w("")
    w("  CAUTION. Do not compare the all-in mediated total against the baseline total:")
    w(f"  they cover different leaf populations ({len(m.leaves)} against {len(common)}). The naive subtraction")
    w(f"  reads {pct(m.total('Mediated'), m.total(C.BASELINE)):.1f}%, which understates the architecture and hides the introduced risk.")
    w("")

    w("-" * 78)
    w("AGGREGATE LEAF RISK -- BY TREE")
    w("-" * 78)
    w(f"  {'tree':<8}{'leaves':>7}{'Baseline':>10}{'Observational':>15}{'Mediated':>10}   reduction")
    for t in m.trees:
        b = m.tree_total(t, C.BASELINE)
        o = m.tree_total(t, "Observational")
        d = m.tree_total(t, "Mediated")
        red = f"{pct(d, b):.1f}%" if b else "n/a (baseline 0)"
        w(f"  {t:<8}{len(m.leaves_in(t)):>7}{b:>10}{o:>15}{d:>10}   {red}")
    w("")

    w("-" * 78)
    w("CONDITION-LEAF COVERAGE")
    w("-" * 78)
    w(f"  {'variant':<16}" + "".join(f"{s:>22}" for s in C.MEDIATION_STATUS_ORDER))
    for v in m.variant_names:
        c = Counter(lf.status[v] for lf in m.leaves if lf.is_condition)
        w(f"  {v:<16}" + "".join(f"{c.get(s, 0):>22}" for s in C.MEDIATION_STATUS_ORDER))
    w("")
    w("  Report coverage beside the risk totals. Table I-2 returns the same value at")
    w("  likelihood 10 and likelihood 5 when impact is Moderate, so a partial control on")
    w("  a Moderate-impact leaf changes status without changing score.")
    w("")

    # leaves that never move
    variants = [v for v in m.variant_names if v != C.BASELINE]
    stuck = [lf for lf in m.leaves if lf.present(C.BASELINE)
             and all(lf.present(v) and lf.risk[v] == lf.risk[C.BASELINE] for v in variants)]
    stuck_cond = [lf for lf in stuck if lf.is_condition]
    w("-" * 78)
    w("LEAVES NO VARIANT MOVES")
    w("-" * 78)
    w(f"  {len(stuck)} of {len([lf for lf in m.leaves if lf.present(C.BASELINE)])} leaves scored at baseline hold the same risk under every variant.")
    w(f"  {len(stuck) - len(stuck_cond)} are frequency leaves, constant by construction. The {len(stuck_cond)} CONDITION leaves below")
    w("  are the residual the architecture does not reach, and belong in the discussion:")
    w("")
    for lf in sorted(stuck_cond, key=lambda x: (-x.risk[C.BASELINE], x.id)):
        w(f"    {lf.id}  risk {lf.risk[C.BASELINE]:>2}  {lf.cond_type or '-':<9} "
          f"{'[' + ', '.join(lf.trees) + ']':<14} {lf.short(44)}")
    w("")

    top = sorted([lf for lf in m.leaves if lf.present(C.BASELINE)],
                 key=lambda lf: (-lf.risk[C.BASELINE], lf.id))[:10]
    w("-" * 78)
    w("TOP TEN LEAVES BY BASELINE RISK")
    w("-" * 78)
    for lf in top:
        d = (lf.risk["Mediated"] - lf.risk[C.BASELINE]) if lf.present("Mediated") else None
        w(f"  {lf.id}  {lf.risk[C.BASELINE]:>2} -> {lf.risk['Mediated'] if lf.present('Mediated') else '--':>2}"
          f"  ({d:+d})" if d is not None else
          f"  {lf.id}  {lf.risk[C.BASELINE]:>2} -> --      ")
    w("")
    w("  Any frequency leaf here is outside the architecture's scope by design and needs")
    w("  a procedural or enterprise-IT recommendation rather than a software feature.")
    w("")

    red = defaultdict(int)
    for lf in m.leaves:
        if lf.feature and lf.present(C.BASELINE) and lf.present("Mediated"):
            red[lf.feature] += lf.risk[C.BASELINE] - lf.risk["Mediated"]
    w("-" * 78)
    w("RISK REDUCTION BY SOLUTION FEATURE (MEDIATED VARIANT)")
    w("-" * 78)
    for f in sorted(red, key=lambda x: -red[x]):
        n = sum(1 for lf in m.leaves if lf.feature == f)
        w(f"  {red[f]:>5}   {n:>2} lea{'f ' if n == 1 else 'ves'}   {f}")
    nobase = sorted({lf.feature for lf in m.leaves
                     if lf.feature and not lf.present(C.BASELINE)} - set(red))
    if nobase:
        w("")
        w("  Not listed, because every leaf they address exists only under the mediated")
        w("  variant and so has no baseline to reduce against:")
        for f in nobase:
            ids = [lf.id for lf in m.leaves if lf.feature == f]
            w(f"          {f}  ({', '.join(ids)})")
        w("  These features are not ineffective -- they address risk the architecture")
        w("  itself introduces, which is accounted for as introduced risk above.")
    w("")

    conf = Counter(str(lf.confidence) for lf in m.leaves if lf.feature)
    w("-" * 78)
    w("SOLUTION EFFECT CONFIDENCE")
    w("-" * 78)
    for k, n in conf.most_common():
        w(f"  {n:>3}   {k}")
    w("")
    w("  Every mapped leaf currently reads the same value, so this column is not yet")
    w("  discriminating. It becomes load-bearing once bench measurement separates")
    w("  demonstrated effects from asserted ones.")
    w("")
    return L


def write_leaf_table(m: Model) -> list[str]:
    L = []
    w = L.append
    w("=" * 170)
    w("LEAF-LEVEL SCORES")
    w("=" * 170)
    w("delta columns are against the baseline variant; negative is a risk reduction.")
    w("'--' means the leaf does not exist under that variant.")
    w("")
    hdr = (f"{'ID':<7}{'type':<11}{'cond role':<10}{'trees':<14}{'classes':<16}"
           f"{'freq':>5}{'loai':>5}{'OL':>4}{'imp':>5}")
    for v in m.variant_names:
        hdr += f"{v[:4] + ' risk':>11}"
    hdr += f"{'d obs':>7}{'d med':>7}  feature"
    w(hdr)
    w("-" * 170)
    for lf in m.leaves:
        row = (f"{lf.id:<7}{lf.type:<11}{(lf.cond_type or '-'):<10}"
               f"{','.join(lf.trees):<14}{','.join(lf.risk_classes):<16}"
               f"{lf.freq if lf.freq is not None else '--':>5}"
               f"{lf.loai if lf.loai is not None else '--':>5}"
               f"{lf.ol if lf.ol is not None else '--':>4}"
               f"{lf.impact if lf.impact is not None else '--':>5}")
        for v in m.variant_names:
            row += f"{lf.risk[v] if lf.present(v) else '--':>11}"
        for v in ("Observational", "Mediated"):
            if lf.present(v) and lf.present(C.BASELINE):
                row += f"{lf.risk[v] - lf.risk[C.BASELINE]:>+7}"
            else:
                row += f"{'--':>7}"
        row += f"  {lf.feature or ''}"
        w(row)
    w("-" * 170)
    tot = f"{'TOTAL':<7}{'':<11}{'':<10}{'':<14}{'':<16}{'':>5}{'':>5}{'':>4}{'':>5}"
    for v in m.variant_names:
        tot += f"{m.total(v):>11}"
    w(tot)
    w("")
    w("Per-leaf status by variant")
    w("-" * 170)
    w(f"{'ID':<7}" + "".join(f"{v:<24}" for v in m.variant_names))
    for lf in m.leaves:
        w(f"{lf.id:<7}" + "".join(f"{(lf.status[v] or 'N/A'):<24}" for v in m.variant_names))
    return L


def write_tree_table(m: Model) -> list[str]:
    L = []
    w = L.append
    w("=" * 78)
    w("TREE-LEVEL SCORES")
    w("=" * 78)
    w("")
    w("(a) AGGREGATE -- sum of leaf risk over leaves assigned to each tree.")
    w("    Measures total exposure carried by the tree. A leaf shared between two")
    w("    trees counts once in each, so these do not sum to the grand total.")
    w("")
    w(f"  {'tree':<8}{'leaves':>7}" + "".join(f"{v:>15}" for v in m.variant_names))
    for t in m.trees:
        w(f"  {t:<8}{len(m.leaves_in(t)):>7}" +
          "".join(f"{m.tree_total(t, v):>15}" for v in m.variant_names))
    w("")
    w("  change against baseline (negative is a risk reduction)")
    for t in m.trees:
        b = m.tree_total(t, C.BASELINE)
        parts = []
        for v in m.variant_names[1:]:
            d = m.tree_total(t, v) - b
            # signed percentage, so it agrees with the sign of the absolute change
            parts.append(f"{v}: {d:+d}" + (f" ({100.0 * d / b:+.1f}%)" if b else ""))
        w(f"    {t:<8}" + "   ".join(parts))
    w("")
    for t in m.trees:
        w(f"  {t} -- {m.node_by_id[t].label if t in m.node_by_id else '(no root node row)'}")
        w(f"     leaves: {', '.join(lf.id for lf in m.leaves_in(t))}")
    w("")

    w("(b) PROPAGATED -- MIN/MAX through the AND/OR gates to the root.")
    w("    Measures the easiest available path rather than total exposure.")
    w("")
    if not m.has_edges:
        w("    NOT AVAILABLE. The workbook records no parent/child relationships:")
        w(f"    the '{C.SHEET_TREE}' sheet lists {len(m.nodes)} node rows ({len(m.roots)} roots,")
        w(f"    {sum(n.is_gate for n in m.nodes)} gates, {sum(n.is_leaf for n in m.nodes)} leaves) with their gate types, but nothing says which")
        w("    node is whose child -- and the leaf matrix records only which TREE a leaf")
        w("    belongs to, not which GATE.")
        w("")
        w("    To enable it, add a worksheet named exactly:")
        w(f"        {C.SHEET_EDGES}")
        w("    with the columns:")
        w("        " + " | ".join(C.EDGE_COLUMNS))
        w("    One row per edge. A pre-filled template has been written to")
        w("    attack_tree_edges_TEMPLATE.csv in this folder -- the gate hierarchy is")
        w("    already populated from the node labels; the leaf rows need a parent.")
        w("    Re-run this script afterwards and propagated scores appear here and in")
        w("    fig10_tree_propagation_bar.png.")
        return L

    for t in m.trees:
        if t not in m.node_by_id:
            continue
        w(f"  {t}  ({m.node_by_id[t].gate} root)")
        for v in m.variant_names:
            p = m.propagate(t, v)
            cc = m.critical_child(t, v)
            crit = f"   critical child: {cc[0]} at {cc[1]}" if cc else ""
            w(f"    {v:<16} root = {p.get(t) if p.get(t) is not None else '--'}{crit}")
        w("")
    w("  Full node values")
    w("  " + "-" * 60)
    for t in m.trees:
        if t not in m.node_by_id:
            continue
        w(f"  {t}")
        vals = {v: m.propagate(t, v) for v in m.variant_names}
        ids = sorted(vals[C.BASELINE], key=lambda n: (not n.startswith("N"), n))
        w(f"    {'node':<9}" + "".join(f"{v[:4]:>7}" for v in m.variant_names) + "  label")
        for nid in ids:
            lab = (m.node_by_id[nid].label if nid in m.node_by_id
                   else (m.by_id[nid].desc if nid in m.by_id else ""))
            w(f"    {nid:<9}" +
              "".join(f"{vals[v].get(nid) if vals[v].get(nid) is not None else '--':>7}"
                      for v in m.variant_names) + f"  {lab[:62]}")
        w("")
    return L


def write_validation(m: Model) -> list[str]:
    L = []
    w = L.append
    w("=" * 78)
    w("VALIDATION REPORT")
    w("=" * 78)
    w("Every scored cell recomputed from the NIST SP 800-30 Rev. 1 matrices in")
    w("core.py. A clean run means the workbook's arithmetic is internally")
    w("consistent; it does not validate the band ASSIGNMENTS, which are judgments.")
    w("")
    errs = []

    for lf in m.leaves:
        # G-5 on frequency leaves
        if lf.is_frequency and None not in (lf.freq, lf.loai, lf.ol):
            exp = C.assess_overall_likelihood(lf.freq, lf.loai)
            if exp != lf.ol:
                errs.append(f"{lf.id}: G-5({lf.freq},{lf.loai}) = {exp}, workbook says {lf.ol}")
        # per-variant cells
        for v in m.variant_names:
            st, lk, rk = lf.status[v], lf.likelihood[v], lf.risk[v]
            if st is None:
                if lk is not None or rk is not None:
                    errs.append(f"{lf.id} [{v}]: status N/A but likelihood={lk} risk={rk}")
                continue
            if lk is None or rk is None:
                errs.append(f"{lf.id} [{v}]: status '{st}' but likelihood={lk} risk={rk}")
                continue
            if lf.impact is None:
                errs.append(f"{lf.id}: no impact value")
                continue
            exp = C.assess_risk(lk, lf.impact)
            if exp != rk:
                errs.append(f"{lf.id} [{v}]: I-2({lk},{lf.impact}) = {exp}, workbook says {rk}")
            if lf.is_condition and st in C.MEDIATION_STATUS_LIKELIHOOD and lk != C.MEDIATION_STATUS_LIKELIHOOD[st]:
                errs.append(f"{lf.id} [{v}]: status '{st}' implies likelihood "
                            f"{C.MEDIATION_STATUS_LIKELIHOOD[st]}, workbook says {lk}")
            if lf.is_frequency and st == C.MEDIATION_STATUS_CONSTANT and lf.ol is not None and lk != lf.ol:
                errs.append(f"{lf.id} [{v}]: constant frequency leaf, likelihood {lk} "
                            f"but overall likelihood {lf.ol}")
    w(f"scored-cell checks : {'PASS -- 0 disagreements' if not errs else str(len(errs)) + ' DISAGREEMENTS'}")
    for e in errs:
        w(f"    {e}")
    w("")

    # structure cross-checks
    w("-" * 78)
    w("CROSS-REFERENCE CHECKS")
    w("-" * 78)
    struct_leaves = {n.id for n in m.nodes if n.is_leaf}
    matrix_leaves = set(m.by_id)
    only_struct = sorted(struct_leaves - matrix_leaves)
    only_matrix = sorted(matrix_leaves - struct_leaves)
    w(f"leaf nodes in '{C.SHEET_TREE}' : {len(struct_leaves)}")
    w(f"rows in '{C.SHEET_LEAF}'       : {len(matrix_leaves)}")
    w(f"  in structure but not scored  : {', '.join(only_struct) if only_struct else 'none'}")
    w(f"  scored but not in structure  : {', '.join(only_matrix) if only_matrix else 'none'}")
    w("")
    unknown = sorted({t for lf in m.leaves for t in lf.trees} - set(m.roots))
    w(f"trees referenced by leaves but having no Root node row: "
      f"{', '.join(unknown) if unknown else 'none'}")
    w("")
    nofeat = [lf.id for lf in m.leaves if lf.is_condition and not lf.feature]
    w(f"condition leaves with no mapped solution feature ({len(nofeat)}):")
    w(f"  {', '.join(nofeat) if nofeat else 'none'}")
    w("")
    noconf = [lf.id for lf in m.leaves if lf.feature and lf.confidence is None]
    w(f"mapped leaves with no effect-confidence value ({len(noconf)}):")
    w(f"  {', '.join(noconf) if noconf else 'none'}")
    w("")
    dupdesc = [d for d, n in Counter(lf.desc.lower() for lf in m.leaves).items() if n > 1]
    w(f"duplicate leaf descriptions: {len(dupdesc)}")
    for d in dupdesc:
        w(f"  {[lf.id for lf in m.leaves if lf.desc.lower() == d]}  {d[:70]}")
    w("")

    w("-" * 78)
    w("LOOKUP-TABLE ORIENTATION")
    w("-" * 78)
    w("The 'Scoring Scales & Logic' worksheet renders G-5 and I-2 with their row")
    w("labels ascending (Very Low -> Very High) while the cell values run the other")
    w("way. Read literally, that sheet says likelihood Very High with impact Very")
    w("High yields risk Low. The matrices in core.py are the corrected")
    w("orientation, and they reproduce every scored cell above exactly -- so the")
    w("DATA is right and only the displayed tables are mislabelled. Fix the sheet")
    w("before reproducing those tables in the report.")
    w("")
    w("Also in that sheet:")
    w("  - G-4 gives Very High and High the same description ('almost certain').")
    w("    High should read 'highly likely'.")
    w("  - the block labelled 'TABLE I-3' is a copy of the impact scale (H-3),")
    w("    not the non-adversarial risk matrix.")
    w("  - I-2's axis caption reads 'Likelihood of Event Resulting in Adverse")
    w("    Impacts'; I-2 combines overall likelihood with IMPACT.")
    return L


def write_edge_template(m: Model):
    """
    Emit one row per edge the model needs, so the gate propagation can be
    switched on by filling in a single column.

    The first four columns are the schema the loader reads. The two leading-
    underscore columns are scaffolding -- delete them once the parents are
    filled, or leave them; the loader ignores any column it does not need.

    Gate edges are pre-filled from the node labels and the N-1xx numbering,
    which make the hierarchy unambiguous. Leaf placement is NOT inferable from
    anything in the workbook, so those rows carry a blank parent and the
    candidate gates for that leaf's tree alongside.

    Prefer build_edges.py, which derives the whole sheet from the ASCII trees.
    This template is the fallback for when no drawing is available.
    """
    path = OUTPUT_DIR / "attack_tree_edges_TEMPLATE.csv"
    cols = list(C.EDGE_COLUMNS) + ["_candidate_parents", "_label"]

    with path.open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(cols)
        for tree in m.trees:
            gate_edges = INFERRED_GATE_EDGES.get(tree, [])
            # pre-filled gate hierarchy
            order = Counter()
            for parent, child in gate_edges:
                order[parent] += 1
                lab = m.node_by_id[child].label if child in m.node_by_id else ""
                wr.writerow([tree, parent, child, order[parent],
                             "(inferred from labels - verify)", lab])
            # candidate parents for this tree: the root plus every gate in it
            cands = [tree] + [c for _, c in gate_edges]
            cand_txt = " ".join(cands)
            for lf in m.leaves_in(tree):
                wr.writerow([tree, "", lf.id, "", cand_txt, lf.desc])

    return path


def main():
    C.apply_style()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    m = Model()

    written = []
    for fn in (fig_aggregate, fig_tree_risk, fig_tree_delta, fig_leaf_dumbbell,
               fig_leaf_delta, fig_coverage, fig_cumulative,
               fig_feature_attribution, fig_risk_class, fig_propagation):
        p = fn(m)
        if p:
            written.append(p)

    for name, builder in (("scores_summary.txt", write_summary),
                          ("scores_leaf_level.txt", write_leaf_table),
                          ("scores_tree_level.txt", write_tree_table),
                          ("validation_report.txt", write_validation)):
        p = OUTPUT_DIR / name
        p.write_text("\n".join(builder(m)) + "\n")
        written.append(p)

    if not m.has_edges:
        written.append(write_edge_template(m))

    print(f"workbook : {m.workbook_path}")
    print(f"output   : {OUTPUT_DIR}")
    print(f"leaves   : {len(m.leaves)}   trees: {', '.join(m.trees)}")
    print(f"totals   : " + "   ".join(
        f"{v} {m.total(v, m.common_leaves())}" for v in m.variant_names) +
        f"   (common {len(m.common_leaves())}-leaf set)")
    if not m.has_edges:
        print("note     : no edge table -- propagated tree scores skipped; "
              "template written")
    print()
    for p in written:
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
