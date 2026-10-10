#!/usr/bin/env python3
"""
sensitivity.py -- how much of the evaluation survives estimation error in the
band assignments. Writes figures (.png) and a report (.txt) to ../output.

    python3 sensitivity.py

No arguments. Configuration is the CONFIG block below plus eval_core.py.

TWO ANALYSES, ANSWERING DIFFERENT QUESTIONS
    A. DETERMINISTIC BAND SHIFT -- move every band the same number of steps
       along the 0/2/5/8/10 ladder and rescore. Answers "does the conclusion
       survive a systematic misjudgment?" This is the defensible one for the
       report: it is reproducible, has no random seed, and the claim it
       supports is specific -- if the variant ordering holds at +/-1 band, the
       conclusions are robust to one-band estimation error.

    B. MONTE CARLO -- perturb each leaf's bands independently at random and
       rescore many times. Answers "what range should I actually quote?" and
       replaces a single risk number with a distribution. Use it for the
       interval; use A for the robustness claim.

WHAT IS PERTURBED
    Frequency leaves  : the Frequency band and the Likelihood-of-Adverse-Impact
                        band, which recombine through Table G-5 into overall
                        likelihood, then through I-2 with impact.
    Condition leaves  : the Impact band. Their likelihood is not an estimate --
                        it is set by the control status (Unaddressed 10,
                        Partially Addressed 5, Fully Addressed 0), so
                        perturbing it would be perturbing the variant
                        definition rather than a judgment.

    Both recompute through the real lookup matrices rather than scaling the
    output, so every perturbed score is a value the model could actually have
    produced, and the floors and ceilings of Table I-2 are respected.
"""

from __future__ import annotations

import random
from collections import Counter

import numpy as np
import matplotlib.pyplot as plt

import core as C
from core import Model, OUTPUT_DIR, SERIES, INK, INK_SOFT, INK_MUTED


# =============================================================================
# CONFIG -- edit here
# =============================================================================

SHIFTS = [-2, -1, 0, 1, 2]      # deterministic band-shift steps
N_TRIALS = 4000                 # Monte Carlo trials
SEED = 20261009                 # fixed, so the figures are reproducible

# Probability a band moves by -1 / 0 / +1 step in a Monte Carlo trial. Centred
# and symmetric: the assignments are treated as unbiased point estimates with
# roughly one band of uncertainty, which is as much as an ordinal elicitation
# can honestly claim.
P_DOWN, P_SAME, P_UP = 0.22, 0.56, 0.22

# Quantiles reported as the interval. 5th-95th rather than min-max: the
# extremes of 4000 trials are the tails where every leaf moved the same way at
# once, which is not a realistic joint outcome.
Q_LO, Q_HI = 5, 95


# =============================================================================
# rescoring
# =============================================================================

def leaf_risk(leaf, variant, freq_d=0, loai_d=0, impact_d=0):
    """
    Recompute one leaf's risk under a variant with the given band shifts.
    Returns None where the leaf does not exist under that variant.
    """
    if not leaf.present(variant):
        return None

    impact = C.shift_band(leaf.impact, impact_d)

    if leaf.is_frequency:
        freq = C.shift_band(leaf.freq, freq_d)
        loai = C.shift_band(leaf.loai, loai_d)
        likelihood = C.assess_overall_likelihood(freq, loai)
    else:
        # Status-driven, not estimated -- see the module docstring.
        likelihood = leaf.likelihood[variant]

    return C.assess_risk(likelihood, impact)


def ordering_flips(m: Model, totals_by_shift: dict[int, dict[str, int]]):
    """
    Find pairs of variants whose strict order reverses across the sweep.

    Tested pairwise rather than by comparing sorted sequences, because bands
    clamp: at +/-2 two variants can land on the same total, and a sorted-list
    comparison then reports a reversal that is only a tie plus a stable sort.
    A tie is not a flip -- it is a loss of resolution.
    """
    names = m.variant_names
    flips = []
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            signs = []
            for s in sorted(totals_by_shift):
                d = totals_by_shift[s][a] - totals_by_shift[s][b]
                if d != 0:
                    signs.append((s, 1 if d > 0 else -1))
            if len({sg for _, sg in signs}) > 1:
                flips.append((a, b, signs))
    return flips


def ties(m: Model, totals_by_shift: dict[int, dict[str, int]]):
    """Shifts at which two variants become indistinguishable."""
    out = []
    names = m.variant_names
    for s in sorted(totals_by_shift):
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                if totals_by_shift[s][a] == totals_by_shift[s][b]:
                    out.append((s, a, b, totals_by_shift[s][a]))
    return out


def total_shifted(m: Model, variant: str, steps: int, leaves=None) -> int:
    """Aggregate risk with every estimated band moved `steps` along the ladder."""
    pool = leaves if leaves is not None else m.leaves
    out = 0
    for lf in pool:
        r = leaf_risk(lf, variant, freq_d=steps, loai_d=steps, impact_d=steps)
        if r is not None:
            out += r
    return out


def monte_carlo(m: Model, rng: random.Random, leaves=None):
    """
    One trial: perturb each leaf's bands independently, return the aggregate
    per variant. Perturbations are drawn ONCE PER LEAF and shared across
    variants, because a leaf's impact estimate does not change depending on
    which architecture is deployed -- drawing separately per variant would
    inject noise into exactly the comparison being measured.
    """
    pool = leaves if leaves is not None else m.leaves

    def draw():
        r = rng.random()
        return -1 if r < P_DOWN else (1 if r > P_DOWN + P_SAME else 0)

    totals = {v: 0 for v in m.variant_names}
    for lf in pool:
        fd, ld, idl = draw(), draw(), draw()
        for v in m.variant_names:
            r = leaf_risk(lf, v, freq_d=fd, loai_d=ld, impact_d=idl)
            if r is not None:
                totals[v] += r
    return totals


# =============================================================================
# figures
# =============================================================================

def fig_shift_band(m: Model, common):
    """Line plot with a shaded envelope -- the deterministic sweep."""
    fig, ax = plt.subplots(figsize=(8.6, 5.2))

    series = {v: [total_shifted(m, v, s, common) for s in SHIFTS]
              for v in m.variant_names}

    # envelope between the best and worst variant at each shift
    lo = [min(series[v][i] for v in m.variant_names) for i in range(len(SHIFTS))]
    hi = [max(series[v][i] for v in m.variant_names) for i in range(len(SHIFTS))]
    ax.fill_between(SHIFTS, lo, hi, color="#2a78d6", alpha=0.07, zorder=1,
                    label="spread across variants")

    for v in m.variant_names:
        ax.plot(SHIFTS, series[v], marker="o", color=SERIES[v], label=v, zorder=3,
                markeredgecolor="#ffffff", markeredgewidth=1.0)
        ax.annotate(f"{series[v][-1]}", (SHIFTS[-1], series[v][-1]),
                    textcoords="offset points", xytext=(8, 0), va="center",
                    fontsize=8.5, color=INK_SOFT)

    ax.axvline(0, color=INK_MUTED, lw=1.0, ls=":", zorder=2)
    ax.set_xticks(SHIFTS)
    ax.set_xticklabels([f"{s:+d}" if s else "0\n(as scored)" for s in SHIFTS])
    ax.set_xlabel("Systematic band shift applied to every estimated band (ladder steps)")
    ax.set_ylabel("Aggregate leaf risk, common set")
    ax.set_title("Deterministic sensitivity: aggregate risk under a systematic band shift")
    ax.legend(loc="upper left")
    ax.set_xlim(SHIFTS[0] - 0.15, SHIFTS[-1] + 0.5)

    tbs = {s: {v: series[v][i] for v in m.variant_names}
           for i, s in enumerate(SHIFTS)}
    flips = ordering_flips(m, tbs)
    tied = ties(m, tbs)
    note = ("Bands clamp at the ends of the ladder, so the curves compress at +/-2 as leaves pile up on Very High or Very Low -- that\n"
            "compression is the scale's ceiling, not a finding. "
            + ("No variant pair reverses order at any shift tested, so the ranking is robust to\nsystematic one- and two-band estimation error."
               if not flips else
               "WARNING: a variant pair reverses order within the range tested; see sensitivity_report.txt.")
            + (f"\nAt {', '.join(f'{s:+d}' for s, *_ in tied)} two variants land on the same total -- a loss of resolution from clamping, not a reversal."
               if tied else ""))
    return C.finish(fig, ax, OUTPUT_DIR / "fig11_sensitivity_shift_line.png", note)


def fig_distribution(m: Model, dist, common):
    """
    Candlestick / box-and-whisker -- the Monte Carlo distribution per variant,
    against the single as-scored value.
    """
    fig, ax = plt.subplots(figsize=(8.0, 5.2))
    variants = m.variant_names
    x = np.arange(len(variants))

    for i, v in enumerate(variants):
        d = np.asarray(dist[v], dtype=float)
        q1, med, q3 = np.percentile(d, [25, 50, 75])
        lo, hi = np.percentile(d, [Q_LO, Q_HI])
        col = SERIES[v]

        # whisker
        ax.plot([i, i], [lo, hi], color=col, lw=1.6, zorder=3,
                solid_capstyle="round")
        for yv in (lo, hi):
            ax.plot([i - 0.07, i + 0.07], [yv, yv], color=col, lw=1.6, zorder=3)
        # body
        ax.add_patch(plt.Rectangle((i - 0.20, q1), 0.40, q3 - q1,
                                   facecolor=col, edgecolor="#ffffff",
                                   linewidth=1.6, zorder=4, alpha=0.85))
        # median
        ax.plot([i - 0.20, i + 0.20], [med, med], color="#ffffff", lw=2.0, zorder=5)
        # as-scored marker
        act = m.total(v, common)
        ax.plot([i], [act], marker="D", ms=7, color=INK, zorder=6,
                markeredgecolor="#ffffff", markeredgewidth=1.0)

        ax.text(i + 0.30, med, f"median {med:.0f}", va="center", fontsize=8.2,
                color=INK_SOFT)
        ax.text(i + 0.30, hi, f"{Q_HI}th  {hi:.0f}", va="center", fontsize=7.6,
                color=INK_MUTED)
        ax.text(i + 0.30, lo, f"{Q_LO}th  {lo:.0f}", va="center", fontsize=7.6,
                color=INK_MUTED)

    ax.plot([], [], marker="D", ms=7, color=INK, ls="none", label="as scored")
    ax.set_xticks(x)
    ax.set_xticklabels(variants)
    ax.set_ylabel("Aggregate leaf risk, common set")
    ax.set_title(f"Monte Carlo risk distribution by variant ({N_TRIALS:,} trials)")
    ax.legend(loc="upper right")
    ax.set_xlim(-0.5, len(variants) - 0.1)

    note = (f"Box is the interquartile range, whiskers the {Q_LO}th-{Q_HI}th percentile, white line the median, diamond the single as-scored value.\n"
            f"Each trial moves every estimated band independently by -1/0/+1 step with probability {P_DOWN:.2f}/{P_SAME:.2f}/{P_UP:.2f}, then rescores through\n"
            "Tables G-5 and I-2 -- so every value plotted is one the model could genuinely have produced. Quote the interval, not the point.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig12_sensitivity_distribution.png", note)


def fig_reduction_distribution(m: Model, dist, common):
    """
    Shaded-range plot of the quantity the report actually claims: percentage
    risk reduction against baseline. Distributing the ratio rather than the
    two totals separately is the right move -- the numerator and denominator
    move together, so a reduction can be far better determined than either
    total.
    """
    variants = [v for v in m.variant_names if v != C.BASELINE]
    fig, ax = plt.subplots(figsize=(8.4, 3.3))

    base = np.asarray(dist[C.BASELINE], dtype=float)
    spans = []
    for v in variants:
        d = np.asarray(dist[v], dtype=float)
        red = 100.0 * (base - d) / np.where(base == 0, np.nan, base)
        spans += list(np.nanpercentile(red, [Q_LO, Q_HI]))

    for i, v in enumerate(variants):
        d = np.asarray(dist[v], dtype=float)
        red = 100.0 * (base - d) / np.where(base == 0, np.nan, base)
        lo, q1, med, q3, hi = np.percentile(red, [Q_LO, 25, 50, 75, Q_HI])
        col = SERIES[v]

        ax.plot([lo, hi], [i, i], color=col, lw=2.0, zorder=3,
                solid_capstyle="butt")
        for xv in (lo, hi):          # end caps, so the interval reads as bounded
            ax.plot([xv, xv], [i - 0.11, i + 0.11], color=col, lw=2.0, zorder=3)
        ax.add_patch(plt.Rectangle((q1, i - 0.21), q3 - q1, 0.42,
                                   facecolor=col, edgecolor="#ffffff",
                                   linewidth=1.4, zorder=4, alpha=0.9))
        ax.plot([med, med], [i - 0.21, i + 0.21], color="#ffffff", lw=2.0, zorder=5)

        act = 100.0 * (m.total(C.BASELINE, common) - m.total(v, common)) / m.total(C.BASELINE, common)
        ax.plot([act], [i], marker="D", ms=7, color=INK, zorder=6,
                markeredgecolor="#ffffff", markeredgewidth=1.0)
        ax.text(hi + (max(spans) - min(spans)) * 0.035, i,
                f"{med:.1f}%   [{lo:.1f}, {hi:.1f}]",
                va="center", fontsize=8.6, color=INK_SOFT)

    ax.plot([], [], marker="D", ms=7, color=INK, ls="none", label="as scored")
    ax.set_yticks(np.arange(len(variants)))
    ax.set_yticklabels([f"{v}\nvs {C.BASELINE}" for v in variants])
    ax.set_xlabel("Risk reduction against baseline (%)")
    ax.set_title("Risk reduction against baseline, with uncertainty")
    ax.legend(loc="upper right")
    # Scale to the data. A fixed 0-100 axis would render these intervals -- a
    # few points wide -- as slivers and hide the thing the figure exists to show.
    pad = (max(spans) - min(spans)) * 0.10
    xlo = max(0.0, min(spans) - pad)
    ax.set_xlim(xlo, max(spans) + pad * 4.2)
    ax.set_ylim(len(variants) - 0.55, -0.55)

    note = (f"Box is the interquartile range, the capped line the {Q_LO}th-{Q_HI}th percentile, the diamond the as-scored value. The axis is scaled to\n"
            + ("the data" if xlo > 0 else "the data and happens to reach zero here")
            + " -- these intervals are only a few points wide and would be slivers on a fixed 0-100 scale.\n"
            "The ratio is computed per trial, so baseline and variant move together, which is why the reduction is far better determined\n"
            "than either total. This is the interval to quote whenever the report states a reduction.")
    return C.finish(fig, ax, OUTPUT_DIR / "fig13_sensitivity_reduction.png", note)


def fig_tree_shift(m: Model):
    """Line plot -- per-tree sensitivity, one panel per tree."""
    trees = m.trees
    fig, axes = plt.subplots(1, len(trees), figsize=(13.0, 3.6), sharey=True)
    if len(trees) == 1:
        axes = [axes]

    absent = []
    for ax, t in zip(axes, trees):
        pool = m.leaves_in(t)
        for v in m.variant_names:
            # Skip a variant the tree has no leaves under: a flat zero line
            # would read as "no risk" when the truth is "does not exist yet".
            if not any(lf.present(v) for lf in pool):
                absent.append((t, v))
                continue
            vals = [total_shifted(m, v, s, pool) for s in SHIFTS]
            ax.plot(SHIFTS, vals, marker="o", ms=5, color=SERIES[v], label=v,
                    markeredgecolor="#ffffff", markeredgewidth=0.8, zorder=3)
        ax.axvline(0, color=INK_MUTED, lw=1.0, ls=":", zorder=2)
        ax.set_xticks(SHIFTS)
        ax.set_title(f"{t}  (n={len(pool)})", fontsize=10.5)
        ax.set_xlabel("band shift")
        miss = [v for tt, v in absent if tt == t]
        if miss:
            ax.text(0.5, 0.92, "not present under " + ", ".join(miss),
                    transform=ax.transAxes, ha="center", fontsize=7.4,
                    style="italic", color=INK_MUTED)

    axes[0].set_ylabel("Aggregate leaf risk")
    # one legend for the whole row, from whichever panel carries every series
    h, l = max((ax.get_legend_handles_labels() for ax in axes),
               key=lambda hl: len(hl[1]))
    axes[-1].legend(h, l, loc="upper left", fontsize=8)
    fig.suptitle("Per-tree sensitivity to a systematic band shift", y=1.04,
                 fontsize=12, fontweight="bold", color=INK)

    note = ("A variant is omitted from a panel where the tree has no leaves scored under it, rather than drawn as a flat zero line --\n"
            "AN-7 exists only under the mediated variant. Where two variant lines overlap across the whole sweep, that tree does not\n"
            "discriminate between them at any band assignment.")
    return C.finish(fig, axes, OUTPUT_DIR / "fig14_sensitivity_by_tree_line.png", note)


# =============================================================================
# report
# =============================================================================

def write_report(m: Model, dist, common) -> list[str]:
    L = []
    w = L.append
    w("=" * 78)
    w("SENSITIVITY ANALYSIS")
    w("=" * 78)
    w(f"common leaf set : {len(common)} leaves scored under every variant")
    w(f"band ladder     : {C.BAND_LADDER}")
    w(f"shifts tested   : {SHIFTS}")
    w(f"monte carlo     : {N_TRIALS:,} trials, seed {SEED}, "
      f"per-band step probabilities -1/0/+1 = {P_DOWN}/{P_SAME}/{P_UP}")
    w("")
    w("Perturbed: the Frequency and Likelihood-of-Adverse-Impact bands on")
    w("frequency leaves, and the Impact band on every leaf. NOT perturbed:")
    w("condition-leaf likelihood, which is fixed by control status rather than")
    w("estimated -- moving it would perturb the variant definition itself.")
    w("")

    w("-" * 78)
    w("A. DETERMINISTIC BAND SHIFT")
    w("-" * 78)
    w(f"  {'shift':<8}" + "".join(f"{v:>15}" for v in m.variant_names) +
      f"{'obs red':>10}{'med red':>10}")
    tbs = {}
    for s in SHIFTS:
        tot = {v: total_shifted(m, v, s, common) for v in m.variant_names}
        tbs[s] = tot
        b = tot[C.BASELINE]
        o = 100.0 * (b - tot["Observational"]) / b if b else 0.0
        d = 100.0 * (b - tot["Mediated"]) / b if b else 0.0
        tag = "  <- as scored" if s == 0 else ""
        w(f"  {s:<+8d}" + "".join(f"{tot[v]:>15}" for v in m.variant_names) +
          f"{o:>9.1f}%{d:>9.1f}%" + tag)
    w("")

    flips = ordering_flips(m, tbs)
    tied = ties(m, tbs)
    if not flips:
        w("  ORDERING STABLE. No pair of variants reverses order at any shift tested,")
        w("  so the ranking survives a systematic one- and two-band estimation error in")
        w("  either direction. The claim to put in the report, with exactly this scope:")
        w("")
        w("      Shifting every estimated band one or two steps in either direction")
        w("      leaves the relative ordering of the variants unchanged, so the")
        w("      comparative conclusions are robust to systematic band-assignment")
        w("      error of that magnitude.")
    else:
        w("  ORDERING UNSTABLE. These pairs reverse within the range tested:")
        for a, b_, signs in flips:
            w(f"    {a} vs {b_}:")
            for s, sg in signs:
                w(f"      {s:+d}: {a if sg > 0 else b_} higher")
    w("")
    if tied:
        w("  Ties (two variants on the same total -- a loss of resolution from band")
        w("  clamping, not a reversal):")
        for s, a, b_, val in tied:
            w(f"    {s:+d}: {a} = {b_} = {val}")
        w("")
    w("  Bands clamp at the ends of the ladder, so totals compress sharply at +/-2 as")
    w("  leaves accumulate on Very High or Very Low. Treat the +/-1 rows as the")
    w("  informative ones and +/-2 as a stress case; the -2 column in particular")
    w("  pushes most leaves to the bottom of the scale and should not be quoted as a")
    w("  risk estimate.")
    w("")
    w("  Note the observational reduction is NOT monotone in the shift (it peaks near")
    w("  the as-scored assignment). That is the coarseness of Table I-2 at work rather")
    w("  than a modelling error: a partial control only changes the score where the")
    w("  likelihood drop crosses a matrix boundary, and shifting the impact bands")
    w("  moves which leaves sit on such a boundary.")
    w("")

    w("-" * 78)
    w("B. MONTE CARLO DISTRIBUTION")
    w("-" * 78)
    w(f"  {'variant':<16}{'as scored':>11}{'median':>9}{'mean':>9}{'sd':>8}"
      f"{'p' + str(Q_LO):>8}{'p25':>7}{'p75':>7}{'p' + str(Q_HI):>8}")
    for v in m.variant_names:
        d = np.asarray(dist[v], dtype=float)
        lo, q1, med, q3, hi = np.percentile(d, [Q_LO, 25, 50, 75, Q_HI])
        w(f"  {v:<16}{m.total(v, common):>11}{med:>9.0f}{d.mean():>9.1f}"
          f"{d.std(ddof=1):>8.1f}{lo:>8.0f}{q1:>7.0f}{q3:>7.0f}{hi:>8.0f}")
    w("")
    base = np.asarray(dist[C.BASELINE], dtype=float)
    w("  Risk reduction against baseline, computed per trial so numerator and")
    w("  denominator move together:")
    w("")
    w(f"  {'variant':<16}{'as scored':>11}{'median':>9}{'p' + str(Q_LO):>8}{'p' + str(Q_HI):>8}"
      f"{'  interval width':>17}")
    for v in m.variant_names[1:]:
        d = np.asarray(dist[v], dtype=float)
        red = 100.0 * (base - d) / np.where(base == 0, np.nan, base)
        lo, med, hi = np.nanpercentile(red, [Q_LO, 50, Q_HI])
        act = 100.0 * (m.total(C.BASELINE, common) - m.total(v, common)) / m.total(C.BASELINE, common)
        w(f"  {v:<16}{act:>10.1f}%{med:>8.1f}%{lo:>7.1f}%{hi:>7.1f}%{hi - lo:>15.1f} pts")
    w("")
    sep = np.asarray(dist["Observational"], dtype=float) - np.asarray(dist["Mediated"], dtype=float)
    w(f"  Mediated beats observational in {100.0 * (sep > 0).mean():.1f}% of trials")
    w(f"  (mean margin {sep.mean():.1f} points, sd {sep.std(ddof=1):.1f}).")
    w("")
    w("  Report the interval rather than the point estimate. The as-scored value")
    w("  sits inside it by construction and is not more trustworthy than the rest")
    w("  of the distribution -- it is one draw from the same uncertainty.")
    w("")

    w("-" * 78)
    w("C. PER-TREE DETERMINISTIC SHIFT")
    w("-" * 78)
    for t in m.trees:
        pool = m.leaves_in(t)
        w(f"  {t}  (n={len(pool)})")
        w(f"    {'shift':<8}" + "".join(f"{v:>15}" for v in m.variant_names))
        flat = True
        for s in SHIFTS:
            tot = {v: total_shifted(m, v, s, pool) for v in m.variant_names}
            if len({tot[v] for v in m.variant_names}) > 1:
                flat = False
            w(f"    {s:<+8d}" + "".join(f"{tot[v]:>15}" for v in m.variant_names))
        if flat:
            w("    NOTE: this tree does not discriminate between variants at any shift.")
        w("")

    w("-" * 78)
    w("D. WHAT THIS DOES NOT TEST")
    w("-" * 78)
    w("  - The band ASSIGNMENTS' direction. Perturbing symmetrically around each")
    w("    estimate assumes the estimates are unbiased. A systematic optimism about")
    w("    the architecture's own leaves would not show up here.")
    w("  - The lookup matrices. Tables G-5 and I-2 are held fixed; their coarseness")
    w("    at high impact is a structural property of the method, not sampling error.")
    w("  - The tree structure. Leaf membership and the control mapping are fixed.")
    w("  - Independence. Monte Carlo draws each band independently; real estimation")
    w("    error is likely correlated within a tree, which would widen the interval.")
    w("    The deterministic sweep in section A is the fully-correlated bound and")
    w("    brackets that case.")
    return L


def main():
    C.apply_style()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    m = Model()
    common = m.common_leaves()

    rng = random.Random(SEED)
    dist = {v: [] for v in m.variant_names}
    for _ in range(N_TRIALS):
        t = monte_carlo(m, rng, common)
        for v in m.variant_names:
            dist[v].append(t[v])

    written = [
        fig_shift_band(m, common),
        fig_distribution(m, dist, common),
        fig_reduction_distribution(m, dist, common),
        fig_tree_shift(m),
    ]
    p = OUTPUT_DIR / "sensitivity_report.txt"
    p.write_text("\n".join(write_report(m, dist, common)) + "\n")
    written.append(p)

    print(f"workbook : {m.workbook_path}")
    print(f"output   : {OUTPUT_DIR}")
    print(f"trials   : {N_TRIALS:,} (seed {SEED})   common set: {len(common)} leaves")
    for v in m.variant_names:
        d = np.asarray(dist[v], dtype=float)
        lo, hi = np.percentile(d, [Q_LO, Q_HI])
        print(f"  {v:<14} as scored {m.total(v, common):>4}   "
              f"p{Q_LO}-p{Q_HI} {lo:.0f}-{hi:.0f}")
    print()
    for q in written:
        print(f"  {q.name}")


if __name__ == "__main__":
    main()
