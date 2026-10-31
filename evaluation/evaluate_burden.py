#!/usr/bin/env python3
"""
Description: Ingest the Fabrication Workflow Burden workbook, score it, and
write infographics (.png) plus raw score dumps (.txt) to ./output. When the
Control Traceability Matrix is also present, write the risk-burden comparison
that needs both.

Usage:
    python3 evaluate_burden.py

Usage Note:
    No arguments. Paths, column names and thresholds live in core_burden.py;
    palette and style come from core_risk.py, so this renders as one system
    with evaluate_risk.py.

WHAT THIS PRODUCES
    figB01_workflow_time_bar.png    total elapsed time by workflow and variant
    figB02_burden_ratio_dot.png     elapsed time relative to baseline
    figB03_steps_switches_bar.png   operator steps and context switches
    figB04_bypass_pressure_bar.png  Bypass Pressure Ratio by workflow
    figB05_trial_spread_dot.png     every trial behind every median

    figC01_risk_vs_burden_scatter.png   variant-level cost against benefit

    burden_summary.txt              headline numbers and verdicts
    burden_by_workflow.txt          full per-workflow, per-variant table
    risk_burden_comparison.txt      the joined analysis, with its caveats

SCOPE OF THE MEASUREMENT
    Four directly observed measures, no task model and no predicted time.
    Elapsed time is wall clock for the whole run and therefore includes
    unattended equipment time where a workflow has any: W6 spends most of its
    duration waiting for the printer to flash. Absolute durations are
    comparable WITHIN a workflow across variants, which is what every ratio
    here rests on, and not BETWEEN workflows of different character.
"""

from __future__ import annotations

import statistics as st
from collections import defaultdict

import numpy as np
import matplotlib.pyplot as plt

import core_risk as C
import core_burden as B
from core_risk import OUTPUT_DIR, SERIES, DIV_GOOD, DIV_ZERO, INK, INK_SOFT, INK_MUTED
from core_burden import (BurdenModel, SANCTIONED, BYPASS, VERDICT_FILL, verdict,
                         BURDEN_OK, BURDEN_HIGH, BPR_OK, BPR_HIGH,
                         T_ELAPSED, T_STEPS, T_SWITCH, T_CARRY, MEASURE_LABEL)

# W6 is split out of the headline time figure because its duration is an order
# of magnitude larger than the desk workflows and would flatten them. The split
# is presentational; every ratio is computed on the full set.
LONG_RUNNING = {"W6"}


# =============================================================================
# helpers
# =============================================================================

def grouped_bars(ax, categories, series_values, width=0.26, fmt="{:.0f}",
                 pad_frac=0.02):
    """Grouped bars, one per variant. None is drawn as an 'n/a' mark."""
    x = np.arange(len(categories))
    n = len(series_values)
    top = max((v for col in series_values.values() for v in col if v is not None),
              default=1.0)
    pad = top * pad_frac
    for i, (name, vals) in enumerate(series_values.items()):
        off = (i - (n - 1) / 2) * width
        ax.bar(x + off, [0 if v is None else v for v in vals], width * 0.92,
               label=name, color=SERIES[name], edgecolor="none", zorder=3)
        for j, v in enumerate(vals):
            if v is None:
                ax.text(x[j] + off, pad, "n/a", ha="center", va="bottom",
                        fontsize=6.6, style="italic", color=INK_MUTED, rotation=90)
            else:
                ax.text(x[j] + off, v + pad, fmt.format(v), ha="center",
                        va="bottom", fontsize=7.3, color=INK_SOFT)
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    return top


# =============================================================================
# burden figures
# =============================================================================

def fig_workflow_time(m: BurdenModel):
    """Grouped bar -- total elapsed time by workflow and variant."""
    short = [w for w in m.operator_workflows() if w.id not in LONG_RUNNING]
    long_ = [w for w in m.operator_workflows() if w.id in LONG_RUNNING]
    admin = m.admin_workflows()
    panels = [(short, "Operator workflows"),
              (long_, "Includes equipment wait"),
              (admin, "Administrative")]
    panels = [(p, t) for p, t in panels if p]

    fig, axes = plt.subplots(
        1, len(panels), figsize=(11.0, 4.6),
        gridspec_kw={"width_ratios": [max(len(p), 1) for p, _ in panels]})
    if len(panels) == 1:
        axes = [axes]

    for ax, (pool, title) in zip(axes, panels):
        vals = {v: [m.med(w.id, v, T_ELAPSED) for w in pool] for v in m.variant_names}
        top = grouped_bars(ax, [w.id for w in pool], vals, fmt="{:.0f}")
        ax.set_ylim(0, top * 1.22)
        ax.set_title(title, fontsize=10)
    axes[0].set_ylabel(MEASURE_LABEL[T_ELAPSED])
    axes[0].legend(loc="upper left", ncols=1, fontsize=7.8)

    fig.suptitle("Total Elapsed Time by Workflow and Variant", y=1.02,
                 fontsize=12, fontweight="bold", color=INK)

    note = ("Median of five measured trials per cell. Panels carry independent vertical scales because W6 runs an order of magnitude\n"
            "longer than the desk workflows -- most of its duration is the printer flashing, which the operator waits through rather than\n"
            "works through. Elapsed time is comparable WITHIN a workflow across variants, which is what every ratio in this evaluation\n"
            "rests on, and not between workflows of different character. W7 has no baseline: the workflow exists only once there is a\n"
            "mediating service to be unavailable.")
    return C.finish(fig, axes, OUTPUT_DIR / "figB01_workflow_time_bar.png", note)


def fig_burden_ratio(m: BurdenModel):
    """Dot plot -- elapsed time relative to baseline, against the thresholds."""
    wfs = [w for w in m.operator_workflows() if m.ratio(w.id, "Mediated") is not None]
    if not wfs:
        return None

    fig, ax = plt.subplots(figsize=(9.0, max(3.6, 0.52 * len(wfs) + 2.0)))
    hi = max(2.7, max(m.ratio(w.id, "Mediated") for w in wfs) * 1.14)
    lo = 0.6
    ax.axvspan(lo, BURDEN_OK, color=VERDICT_FILL["Acceptable"], alpha=0.22, zorder=0, lw=0)
    ax.axvspan(BURDEN_OK, BURDEN_HIGH, color=VERDICT_FILL["Marginal"], alpha=0.22, zorder=0, lw=0)
    ax.axvspan(BURDEN_HIGH, hi, color=VERDICT_FILL["High"], alpha=0.22, zorder=0, lw=0)
    ax.axvline(1.0, color=INK_SOFT, lw=1.2, zorder=4)

    y = np.arange(len(wfs))
    for i, w in enumerate(wfs):
        rs = [m.ratio(w.id, v) for v in ("Observational", "Mediated")]
        rs = [r for r in rs if r is not None]
        if len(rs) > 1:
            ax.plot([min(rs), max(rs)], [i, i], color="#bfbeb8", lw=1.5,
                    zorder=2, solid_capstyle="round")
    for v in ("Observational", "Mediated"):
        pts = [(m.ratio(w.id, v), i) for i, w in enumerate(wfs)
               if m.ratio(w.id, v) is not None]
        ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=62,
                   color=SERIES[v], label=v, zorder=4,
                   edgecolors="#ffffff", linewidths=1.1)
    for i, w in enumerate(wfs):
        r = m.ratio(w.id, "Mediated")
        ax.text(r + (hi - lo) * 0.012, i, f"{r:.2f}x", va="center",
                fontsize=7.8, color=INK_SOFT)

    ax.set_yticks(y)
    ax.set_yticklabels([f"{w.id}  {w.name[:34]}" for w in wfs], fontsize=8.2)
    ax.invert_yaxis()
    ax.set_xlim(lo, hi)
    ax.set_xlabel("Total elapsed time relative to baseline (1.0 = no change)")
    ax.set_title("Workflow Burden Against Baseline, by Variant")
    ax.legend(loc="lower right", ncols=2)

    med = m.variant_median_ratio("Mediated")
    note = (f"Bands are the acceptance thresholds fixed before collection: acceptable to {BURDEN_OK:g}x, marginal to {BURDEN_HIGH:g}x, high burden\n"
            f"beyond. The vertical rule is parity with baseline. Median across operator workflows: {med:.2f}x.\n"
            "Observational should sit on the rule in every workflow -- it imposes no workflow change by design, and the laboratory\n"
            "segmentation applies the baseline forward policy to it unchanged. A departure would mean mediation had leaked into the\n"
            "observational build, not that observing costs time.")
    return C.finish(fig, ax, OUTPUT_DIR / "figB02_burden_ratio_dot.png", note)


def fig_steps_switches(m: BurdenModel):
    """Grouped bar -- the two count measures, side by side."""
    wfs = m.operator_workflows()
    measures = [(T_STEPS, "Operator Steps"), (T_SWITCH, "Context Switches")]
    if not m.carries_derived:
        measures.append((T_CARRY, "Working-Memory Carries"))

    fig, axes = plt.subplots(1, len(measures), figsize=(5.3 * len(measures), 4.3))
    if len(measures) == 1:
        axes = [axes]

    for ax, (measure, title) in zip(axes, measures):
        vals = {v: [m.med(w.id, v, measure) for w in wfs] for v in m.variant_names}
        top = grouped_bars(ax, [w.id for w in wfs], vals, width=0.26,
                           fmt="{:.0f}", pad_frac=0.015)
        ax.set_title(title, fontsize=10.5)
        ax.set_ylabel("Count per run")
        ax.set_ylim(0, top * 1.24)
    axes[0].legend(loc="upper left", ncols=1, fontsize=7.8)

    fig.suptitle("Operator Steps and Context Switches by Workflow and Variant",
                 y=1.02, fontsize=12, fontweight="bold", color=INK)

    tb = m.totals(C.BASELINE, T_STEPS)
    tm = m.totals("Mediated", T_STEPS)
    sb = m.totals(C.BASELINE, T_SWITCH)
    sm = m.totals("Mediated", T_SWITCH)
    note = (f"Counted over the workflows measurable under both variants, mediation adds {tm - tb:.0f} steps ({tb:.0f} to {tm:.0f}) and "
            f"{sm - sb:.0f} context\nswitches ({sb:.0f} to {sm:.0f}). Steps and switches are counted from the recorded run against the step lists in the "
            "workflow sheet,\nso they are observations rather than estimates, and they are the measures a reader can reproduce without "
            "timing anything.")
    if m.carries_derived:
        note += ("\nWorking-memory carries are omitted: in this workbook the column is a calculated field, steps minus switches minus one, "
                 "and\ncarries no information beyond the two measures already plotted. See burden_summary.txt.")
    return C.finish(fig, axes, OUTPUT_DIR / "figB03_steps_switches_bar.png", note)


def fig_bypass_pressure(m: BurdenModel):
    """Bar -- Bypass Pressure Ratio against its thresholds."""
    rows = [(w, m.bpr(w.id)) for w in m.workflows if m.bpr(w.id) is not None]
    if not rows:
        return None

    fig, ax = plt.subplots(figsize=(8.4, 4.6))
    x = np.arange(len(rows))
    cols = [VERDICT_FILL[verdict(r, BPR_OK, BPR_HIGH)] for _w, r in rows]
    bars = ax.bar(x, [r for _w, r in rows], 0.5, color=cols, edgecolor="none", zorder=3)
    for b, (_w, r) in zip(bars, rows):
        ax.text(b.get_x() + b.get_width() / 2, r + 0.035, f"{r:.2f}x",
                ha="center", va="bottom", fontsize=8.4, color=INK_SOFT)

    ax.axhline(1.0, color=INK_SOFT, lw=1.2, zorder=4)
    ax.axhline(BPR_OK, color=VERDICT_FILL["Marginal"], lw=1.3, ls="--", zorder=4)
    top = max(max(r for _w, r in rows) * 1.25, BPR_OK * 1.2)
    ax.text(len(rows) - 0.45, BPR_OK + 0.03, f"marginal above {BPR_OK:g}x",
            fontsize=7.2, color=INK_MUTED, ha="right")
    ax.text(len(rows) - 0.45, 1.02, "parity with the bypass", fontsize=7.2,
            color=INK_MUTED, ha="right")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{w.id}\n{w.name[:20]}" for w, _ in rows])
    ax.set_ylabel("Sanctioned path / least-resistance path")
    ax.set_title("Bypass Pressure Ratio by Workflow (Mediated Variant)")
    ax.set_ylim(0, top)

    below = [w.id for w, r in rows if r < 1.0]
    note = ("How much more time the sanctioned path costs than the quickest route available to an operator working around the control.\n"
            + (f"Below the solid rule the sanctioned path is the QUICKER one and there is no incentive to bypass it: {', '.join(below)}.\n"
               if below else "")
            + "Read alongside availability rather than alone: under the mediated ruleset the network bypass is denied, so the quickest\n"
              "route is physical access to the equipment. Pressure and availability are different questions, and Degraded-Mode Operation\n"
              "exists to cover the gap between them.")
    return C.finish(fig, ax, OUTPUT_DIR / "figB04_bypass_pressure_bar.png", note)


def fig_trial_spread(m: BurdenModel):
    """Dot plot -- every trial behind every median, on a log scale."""
    keys = sorted([k for k in m.cells if k[2] == SANCTIONED],
                  key=lambda k: (k[0], m.variant_names.index(k[1])
                                 if k[1] in m.variant_names else 9))
    fig, ax = plt.subplots(figsize=(9.0, max(4.0, 0.30 * len(keys) + 1.8)))
    for i, k in enumerate(keys):
        c = m.cells[k]
        vals = c.values(T_ELAPSED)
        jitter = (np.random.default_rng(i).random(len(vals)) - 0.5) * 0.26
        ax.scatter(vals, [i] * len(vals) + jitter, s=26, alpha=0.75,
                   color=SERIES.get(k[1], DIV_ZERO), zorder=3,
                   edgecolors="#ffffff", linewidths=0.6)
        q = c.iqr(T_ELAPSED)
        if q and q[0] != q[1]:
            ax.plot(q, [i, i], color=INK_SOFT, lw=2.2, zorder=4, alpha=0.5,
                    solid_capstyle="butt")
        ax.scatter([c.median(T_ELAPSED)], [i], marker="|", s=240, color=INK,
                   zorder=5, linewidths=1.5)

    ax.set_xscale("log")
    ax.set_yticks(np.arange(len(keys)))
    ax.set_yticklabels([f"{k[0]}  {k[1]}" for k in keys], fontsize=7.6)
    ax.invert_yaxis()
    ax.set_xlabel("Total elapsed time (s), one point per trial — log scale")
    ax.set_title("Trial Spread by Workflow and Variant (sanctioned path)")
    ax.grid(axis="y", lw=0.4)

    ns = {m.cells[k].n for k in keys}
    note = (f"Vertical rule is the median, the bar the interquartile range, each dot one measured trial "
            f"(n={min(ns)}-{max(ns)} per cell). The axis is\nlogarithmic because durations span more than an order of magnitude; "
            "equal spacing would compress every desk workflow into one\ncolumn. Medians are reported throughout rather than means: "
            "five trials will not support a mean and one slow run would move it.\nBypass-path cells are omitted and appear in figB04.")
    return C.finish(fig, ax, OUTPUT_DIR / "figB05_trial_spread_dot.png", note)


# =============================================================================
# risk-burden comparison -- needs both workbooks
# =============================================================================

def fig_risk_vs_burden(m: BurdenModel, risk):
    """Scatter -- the variant-level comparison, which is the headline."""
    common = risk.common_leaves()
    base = risk.total(C.BASELINE, common)

    pts = []
    for v in m.variant_names:
        burden = m.variant_median_ratio(v) or 1.0
        red = 100.0 * (base - risk.total(v, common)) / base
        intro = risk.total(v, risk.variant_only_leaves(v))
        pts.append((v, burden, red, intro))

    fig, ax = plt.subplots(figsize=(7.8, 5.6))
    for v, burden, red, intro in pts:
        ax.scatter([burden], [red], s=150 + 7.0 * intro, color=SERIES[v], zorder=4,
                   edgecolors="#ffffff", linewidths=1.4, label=v)
        ax.annotate(f"{v}\n{red:.1f}% at {burden:.2f}x"
                    + (f"\n+{intro:.0f} pts introduced" if intro else ""),
                    (burden, red), textcoords="offset points", xytext=(14, -6),
                    fontsize=8.2, color=INK_SOFT, va="top")

    ax.axvline(1.0, color=INK_SOFT, lw=1.1, zorder=2)
    ax.axhline(0.0, color=INK_SOFT, lw=1.1, zorder=2)
    hi = max(2.8, max(p[1] for p in pts) * 1.3)
    for edge, lab, col in ((BURDEN_OK, "marginal", VERDICT_FILL["Marginal"]),
                           (BURDEN_HIGH, "high burden", VERDICT_FILL["High"])):
        if edge < hi:
            ax.axvline(edge, color=col, lw=1.2, ls="--", zorder=2)
            ax.text(edge, -2.0, f" {lab} ({edge:g}x)", fontsize=7.2, color=INK_MUTED)

    ax.set_xlabel("Median workflow burden relative to baseline (elapsed time)")
    ax.set_ylabel("Risk reduction against baseline, common leaf set (%)")
    ax.set_title("Risk Reduction Against Workflow Burden, by Variant")
    ax.set_xlim(0.85, hi)
    ax.set_ylim(-6, max(p[2] for p in pts) * 1.25)

    note = ("Marker area grows with the risk the variant INTRODUCES, so a large marker has bought its reduction partly by creating new\n"
            "exposure. Benefit is measured on the common leaf set, the only like-for-like comparison. Cost is the median ratio across\n"
            "operator workflows, which weights every workflow equally; real run frequencies differ, and weighting by them would change\n"
            "the picture. Read this as a template for the comparison rather than as a deployment decision.")
    return C.finish(fig, ax, OUTPUT_DIR / "figC01_risk_vs_burden_scatter.png", note)


# =============================================================================
# text output
# =============================================================================

def write_summary(m: BurdenModel, risk) -> list[str]:
    L, w = [], None
    L = []
    w = L.append
    w("=" * 78)
    w("FABRICATION WORKFLOW BURDEN -- EVALUATION SUMMARY")
    w("=" * 78)
    w(f"source     : {m.workbook_path.name}")
    w(f"trials     : {m.trial_count} measured across {len(m.cells)} cells")
    if m.unmeasured:
        w(f"             {m.unmeasured} row(s) skipped with no elapsed time recorded")
    w(f"workflows  : {len(m.operator_workflows())} operator, {len(m.admin_workflows())} administrative")
    w(f"timing     : {', '.join(sorted(m.sources)) if m.sources else 'not recorded'}")
    w(f"measures   : {', '.join(MEASURE_LABEL[x] for x in m.reportable_measures)}")
    nonfunc = [f"{x.id} ({x.status})" for x in m.workflows if not x.functional]
    if nonfunc:
        w(f"NOT FULLY FUNCTIONAL under mediation: {'; '.join(nonfunc)}")
    w("")

    if m.carries_derived:
        w("!" * 78)
        w("WORKING-MEMORY CARRIES IS A CALCULATED COLUMN, NOT A MEASUREMENT")
        w("!" * 78)
        w("  In every row of this workbook:")
        w("")
        w("      Working Memory Carries = Operator Steps - Context Switches - 1")
        w("")
        w("  That is arithmetic on two columns already recorded, so the column")
        w("  adds no information. Worse, it is perfectly correlated with step")
        w("  count and therefore moves the WRONG WAY: any variant that adds steps")
        w("  is reported as adding carries. The reason to count carries at all is")
        w("  that they and step count can move in OPPOSITE directions -- a design")
        w("  that adds mechanical actions while removing what the operator has to")
        w("  hold in their head. A derived column cannot show that.")
        w("")
        w("  This evaluation therefore reports three measures, not four, and")
        w("  omits carries from every figure and table.")
        w("")
        w("  To restore it, count carries independently per trial: an item of")
        w("  information the operator must retain from one step to a later,")
        w("  NON-ADJACENT step with nothing on screen holding it for them -- a")
        w("  filename chosen early and typed later, a version number worked out")
        w("  from timestamps, a hash compared by eye across two windows. Replace")
        w("  the formula with those counts and this warning disappears.")
        w("")

    w("-" * 78)
    w("OPERATOR BURDEN -- MEDIAN TOTAL ELAPSED TIME")
    w("-" * 78)
    w(f"  {'wf':<5}{'workflow':<34}" + "".join(f"{v[:12]:>13}" for v in m.variant_names)
      + f"{'obs x':>8}{'med x':>8}  verdict")
    for x in m.operator_workflows():
        row = f"  {x.id:<5}{x.name[:33]:<34}"
        for v in m.variant_names:
            t = m.med(x.id, v, T_ELAPSED)
            row += f"{(f'{t:.0f}s' if t is not None else '--'):>13}"
        for v in ("Observational", "Mediated"):
            r = m.ratio(x.id, v)
            row += f"{(f'{r:.2f}' if r is not None else '--'):>8}"
        row += f"  {verdict(m.ratio(x.id, 'Mediated'), BURDEN_OK, BURDEN_HIGH)}"
        w(row)
    w("")
    mr = m.variant_median_ratio("Mediated")
    orr = m.variant_median_ratio("Observational")
    w(f"  median mediated burden ratio      : {mr:.2f}x   "
      f"{verdict(mr, BURDEN_OK, BURDEN_HIGH)}")
    w(f"  median observational burden ratio : {orr:.2f}x")
    w("")
    w("  The observational figure is a VALIDITY CHECK, not a result. That variant")
    w("  imposes no workflow change by design and the laboratory segmentation")
    w("  applies the baseline forward policy to it unchanged, so it should read")
    w("  1.00. A departure would mean mediation had leaked into that build.")
    obs = [m.ratio(x.id, "Observational") for x in m.operator_workflows()]
    obs = [r for r in obs if r is not None]
    off = max(abs(r - 1.0) for r in obs) if obs else 0.0
    w(f"  Largest observational departure from parity: {off:.2f}  "
      f"({'within trial noise' if off < 0.10 else 'INVESTIGATE'})")
    w("")

    w("-" * 78)
    w("OPERATOR BURDEN -- STEP AND SWITCH COUNTS")
    w("-" * 78)
    w(f"  {'wf':<5}" + "".join(f"{'steps ' + v[:4]:>13}" for v in m.variant_names)
      + "".join(f"{'switch ' + v[:4]:>14}" for v in m.variant_names))
    for x in m.operator_workflows():
        row = f"  {x.id:<5}"
        for meas, wid in ((T_STEPS, 13), (T_SWITCH, 14)):
            for v in m.variant_names:
                val = m.med(x.id, v, meas)
                row += f"{(f'{val:.0f}' if val is not None else '--'):>{wid}}"
        w(row)
    w("")
    for meas, label in ((T_STEPS, "steps"), (T_SWITCH, "context switches")):
        b, o, d = (m.totals(v, meas) for v in m.variant_names)
        w(f"  {label:<18} summed over the like-for-like set: "
          f"baseline {b:.0f}, observational {o:.0f}, mediated {d:.0f}  "
          f"({d - b:+.0f})")
    w("")
    w("  Counted over workflows measurable under both baseline and the variant,")
    w("  so the totals compare like with like. W7 is excluded: it has no baseline.")
    w("")

    if m.admin_workflows():
        w("-" * 78)
        w("ADMINISTRATIVE BURDEN")
        w("-" * 78)
        w(f"  {'wf':<5}{'workflow':<34}" + "".join(f"{v[:12]:>13}" for v in m.variant_names))
        for x in m.admin_workflows():
            row = f"  {x.id:<5}{x.name[:33]:<34}"
            for v in m.variant_names:
                t = m.med(x.id, v, T_ELAPSED)
                row += f"{(f'{t:.0f}s' if t is not None else '--'):>13}"
            w(row)
        a1 = m.wf_by_id.get("A1")
        if a1:
            o, d = m.med("A1", "Observational"), m.med("A1", "Mediated")
            if o and d:
                w("")
                w(f"  A1 under mediation takes {d / o:.2f} times as long as under observation")
                w(f"  ({100 * (1 - d / o):.0f}% quicker per finding). The observational variant has no")
                w("  authorization records to reconcile against, so each finding is")
                w("  adjudicated by hand; the mediated variant presents a settled verdict.")
        w("")
        w("  Administrative burden is reported per instance, not per week. Finding")
        w("  VOLUME was not instrumented in this collection, so the per-week load")
        w("  cannot be derived -- state the per-instance cost and say that volume")
        w("  is future work rather than multiplying by an assumed rate.")
        w("")

    rows = [(x, m.bpr(x.id)) for x in m.workflows if m.bpr(x.id) is not None]
    if rows:
        w("-" * 78)
        w("BYPASS PRESSURE")
        w("-" * 78)
        for x, r in rows:
            w(f"  {x.id:<5}{x.name[:40]:<42}{r:>6.2f}x   {verdict(r, BPR_OK, BPR_HIGH)}")
        below = [x.id for x, r in rows if r < 1.0]
        w("")
        w("  Sanctioned elapsed time over the quickest route available to an")
        w("  operator working around the control.")
        if below:
            w(f"  Below parity -- the sanctioned path is QUICKER than bypassing it: "
              f"{', '.join(below)}")
        w("  Report alongside availability: under the mediated ruleset the network")
        w("  bypass is denied, so the quickest route is physical.")
        w("")

    w("-" * 78)
    w("ACCEPTANCE THRESHOLDS")
    w("-" * 78)
    w(f"  Elapsed time ratio   acceptable <= {BURDEN_OK:g}x   high burden > {BURDEN_HIGH:g}x")
    w(f"  Bypass Pressure      acceptable <= {BPR_OK:g}x   high burden > {BPR_HIGH:g}x")
    w("  Fixed before data collection and recorded in core_burden.py.")
    w("")
    return L


def write_by_workflow(m: BurdenModel) -> list[str]:
    L = []
    w = L.append
    cols = m.reportable_measures
    w("=" * 110)
    w("PER-WORKFLOW BURDEN DETAIL")
    w("=" * 110)
    w("Median of measured trials; interquartile range in brackets for elapsed time.")
    w("")
    hdr = f"{'wf':<5}{'variant':<15}{'path':<12}{'n':>3}{'elapsed s':>22}"
    for c in cols:
        if c != T_ELAPSED:
            hdr += f"{MEASURE_LABEL[c][:14]:>16}"
    w(hdr)
    w("-" * 110)
    for x in m.workflows:
        for v in m.variant_names:
            for p in (SANCTIONED, BYPASS):
                c = m.cell(x.id, v, p)
                if not c:
                    continue
                q = c.iqr(T_ELAPSED)
                el = (f"{c.median(T_ELAPSED):.0f} [{q[0]:.0f}-{q[1]:.0f}]"
                      if q else f"{c.median(T_ELAPSED):.0f}")
                row = f"{x.id:<5}{v:<15}{p:<12}{c.n:>3}{el:>22}"
                for meas in cols:
                    if meas == T_ELAPSED:
                        continue
                    val = c.median(meas)
                    row += f"{(f'{val:.0f}' if val is not None else '--'):>16}"
                w(row)
        w("")
    w("-" * 110)
    if m.carries_derived:
        w("Working-memory carries omitted: calculated column, not a measurement.")
        w("See burden_summary.txt.")
    return L


def write_comparison(m: BurdenModel, risk) -> list[str]:
    L = []
    w = L.append
    w("=" * 78)
    w("RISK REDUCTION AGAINST WORKFLOW BURDEN")
    w("=" * 78)
    if risk is None:
        w("NOT AVAILABLE. The Control Traceability Matrix could not be loaded, so")
        w("there is no benefit side to join against. Place it at:")
        w(f"    {C.WORKBOOK}")
        w("and re-run.")
        return L

    common = risk.common_leaves()
    base = risk.total(C.BASELINE, common)
    freq = sum(lf.risk[C.BASELINE] for lf in common if lf.is_frequency)
    w(f"benefit source : {risk.workbook_path.name}")
    w(f"cost source    : {m.workbook_path.name}")
    w("")

    w("-" * 78)
    w("VARIANT LEVEL")
    w("-" * 78)
    w(f"  {'variant':<16}{'risk removed':>14}{'reduction':>12}{'introduced':>12}"
      f"{'burden':>10}{'verdict':>12}")
    for v in m.variant_names:
        removed = base - risk.total(v, common)
        red = 100.0 * removed / base
        intro = risk.total(v, risk.variant_only_leaves(v))
        b = m.variant_median_ratio(v) or 1.0
        w(f"  {v:<16}{removed:>14.0f}{red:>11.1f}%{intro:>12.0f}{b:>9.2f}x"
          f"{verdict(b, BURDEN_OK, BURDEN_HIGH):>12}")
    w("")
    w(f"  Risk reduction is measured on the {len(common)}-leaf common set, the only")
    w("  like-for-like comparison. 'Introduced' is risk that exists only under")
    w("  that variant and is reported separately rather than netted off.")
    w("")
    w(f"  CEILING. Frequency leaves carry {freq:.0f} of the {base:.0f} baseline points "
      f"({100 * freq / base:.1f}%)")
    w("  and are constant by construction: no software control alters how often a")
    w("  threat event arises. The greatest reduction any variant could achieve on")
    w(f"  this model is therefore {100 * (base - freq) / base:.1f}%.")
    med_red = 100.0 * (base - risk.total("Mediated", common)) / base
    w(f"  The mediated variant's {med_red:.1f}% is "
      f"{100 * med_red / (100 * (base - freq) / base):.0f}% of the reachable risk.")
    w("")

    a1_o, a1_m = m.med("A1", "Observational"), m.med("A1", "Mediated")
    if a1_o and a1_m:
        w("-" * 78)
        w("THE ASYMMETRY WORTH REPORTING")
        w("-" * 78)
        o_red = base - risk.total("Observational", common)
        d_red = base - risk.total("Mediated", common)
        w(f"  The mediated variant removes {d_red / o_red:.1f} times the risk of the observational")
        w(f"  variant. It costs more operator time per run "
          f"({m.variant_median_ratio('Mediated'):.2f}x against")
        w(f"  {m.variant_median_ratio('Observational'):.2f}x) and LESS administrative time per finding")
        w(f"  ({a1_m:.0f}s against {a1_o:.0f}s, {100 * (1 - a1_m / a1_o):.0f}% quicker).")
        w("")
        w("  The two variants therefore do not sit on a single cost axis. The")
        w("  observational variant is free at the operator's console and expensive")
        w("  for whoever reads its findings; the mediated variant is the reverse.")
        w("  A recommendation that cites only operator burden would favour the")
        w("  variant that removes less than a sixth as much risk.")
        w("")

    w("-" * 78)
    w("WHAT THIS COMPARISON CANNOT SUPPORT")
    w("-" * 78)
    w("  - Workflows are weighted equally. They are not equally frequent, and")
    w("    weighting by observed run rates would change the picture: a 1.5x cost")
    w("    on a quarterly firmware update is not a 1.5x cost on daily job")
    w("    submission.")
    w("  - Risk points are ordinal. The difference between two totals orders")
    w("    them; it does not make one twice the other.")
    w("  - Burden is single-operator expert steady-state and therefore a LOWER")
    w("    bound. A novice or a time-pressured operator performs worse.")
    w("  - Elapsed time includes unattended equipment wait where a workflow has")
    w("    any, so absolute durations are comparable within a workflow across")
    w("    variants and not between workflows.")
    w("  - This is a template for the comparison, demonstrated on one laboratory")
    w("    instance. It is evidence that the method works and that the")
    w("    architecture is worth developing, not a deployment decision.")
    return L


def main():
    C.apply_style()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    m = BurdenModel()
    risk = B.load_risk_model()

    written = []
    for fn in (fig_workflow_time, fig_burden_ratio, fig_steps_switches,
               fig_bypass_pressure, fig_trial_spread):
        p = fn(m)
        if p:
            written.append(p)
    if risk is not None:
        p = fig_risk_vs_burden(m, risk)
        if p:
            written.append(p)

    for name, builder, args in (
            ("burden_summary.txt", write_summary, (m, risk)),
            ("burden_by_workflow.txt", write_by_workflow, (m,)),
            ("risk_burden_comparison.txt", write_comparison, (m, risk))):
        p = OUTPUT_DIR / name
        p.write_text("\n".join(builder(*args)) + "\n")
        written.append(p)

    print(f"burden workbook : {m.workbook_path}")
    print(f"risk workbook   : {risk.workbook_path if risk else 'NOT LOADED -- comparison skipped'}")
    print(f"output          : {OUTPUT_DIR}")
    print(f"trials          : {m.trial_count} across {len(m.cells)} cells")
    print(f"median burden   : mediated {m.variant_median_ratio('Mediated'):.2f}x "
          f"against baseline (elapsed time)")
    if m.carries_derived:
        print("WARNING         : working-memory carries is a calculated column and "
              "has been omitted; see burden_summary.txt")
    print()
    for p in written:
        print(f"  {p.name}")


if __name__ == "__main__":
    main()
