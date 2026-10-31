#!/usr/bin/env python3
"""
core_burden.py -- loader and model for the Fabrication Workflow Burden workbook.

Mirrors core_risk.py for the Control Traceability Matrix: this module owns
paths, column names and the data model; evaluate_burden.py owns the figures.
Styling, palette and finish() come from core_risk.py so both evaluations render
as one system.

SCOPE

    Four measures, two sheets, no modelling:

        Total Elapsed Time (s)   wall clock, start of the first operator
                                 action to completion of the last
        Operator Steps           discrete operator actions
        Context Switches         changes of application, device or location
        Working Memory Carries   information carried across non-adjacent steps

    There is deliberately no task model, no predicted time, no operator
    constants and no decomposition of wait time. The research question is
    whether a conditional architecture reduces risk at a tolerable cost, not
    how human performance decomposes. Four directly observed measures answer
    the first question and can be reproduced by anyone with a stopwatch and
    the workflow list.

WHAT THIS MODEL IS CAREFUL ABOUT

    Medians, not means. Five trials per cell will not support a mean, and one
    slow trial would move it. Spread is the interquartile range.

    Sanctioned and bypass paths stay apart. Bypass rows exist only to compute
    the Bypass Pressure Ratio; averaging them into a variant would mix the
    control with the thing it is meant to displace.

    Operator and administrative workflows stay apart. They load different
    people, and a combined total would hide the asymmetry between them.

    Ratios are against the SAME workflow at baseline, never a pooled total,
    which would be dominated by whichever workflow runs longest.
"""

from __future__ import annotations

import statistics as st
from pathlib import Path

import openpyxl

import core_risk as C

# PATHS
BURDEN_WORKBOOK = C.SCRIPT_DIR / "input" / "Fabrication Workflow Burden.xlsx"

# WORKBOOK SHEET NAMES
SHEET_WORKFLOWS = "Defined Workflow List"
SHEET_TRIALS = "Workflow Burden Trial Results"

# COLUMN NAMES: workflow list
W_ID = "Workflow ID"
W_NAME = "Workflow Name"
W_STATUS = "Mediated Variant Functionality Status"
W_CLASS = "Workflow Class"
W_BYPASS = "Bypass Path Measured Under"
W_RISKCLASS = "Risk Classes"
W_TREES = "Attack Trees"
W_FEATURES = "Solution Features Exercised"

# COLUMN NAMES: trial results
T_ID, T_DATE, T_SESSION, T_ORDER = (
    "Trial ID", "Trial Date", "Session ID", "Order in Session")
T_WF, T_VARIANT, T_PATH = "Workflow ID", "Variant", "Path"
T_STEPS = "Operator Steps"
T_ELAPSED = "Total Elapsed Time (s)"
T_SWITCH = "Context Switches"
T_CARRY = "Working Memory Carries"
T_SOURCE = "Timing Source"
MEASURES = [T_STEPS, T_ELAPSED, T_SWITCH, T_CARRY]

# Readable labels for figure axes and table headers.
MEASURE_LABEL = {
    T_ELAPSED: "Total elapsed time (s)",
    T_STEPS: "Operator steps",
    T_SWITCH: "Context switches",
    T_CARRY: "Working-memory carries",
}

SANCTIONED, BYPASS = "Sanctioned", "Bypass"
OPERATOR_CLASS, ADMIN_CLASS = "Operator", "Administrative"

# ACCEPTANCE THRESHOLDS
# Hardcoded here rather than read from a worksheet: with the criteria sheet
# removed there is nowhere else for them to live, and two bands on two measures
# do not justify a sheet of their own. Fixed before data collection.
BURDEN_OK, BURDEN_HIGH = 1.5, 2.5     # elapsed time, ratio against baseline
BPR_OK, BPR_HIGH = 2.0, 4.0           # bypass pressure ratio

VERDICT_FILL = {"Acceptable": C.MEDIATION_STATUS_FILL["Fully Addressed"],
                "Marginal": C.MEDIATION_STATUS_FILL["Partially Addressed"],
                "High": C.MEDIATION_STATUS_FILL["Unaddressed"],
                "n/a": C.DIV_ZERO}


def verdict(value: float | None, ok: float, high: float) -> str:
    """Acceptable / Marginal / High for a lower-is-better measure."""
    if value is None:
        return "n/a"
    if value <= ok:
        return "Acceptable"
    return "High" if value > high else "Marginal"


def _num(v):
    """A cell as a float, or None. Blank, text and 'N/A' all become None."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s or s.upper() == "N/A":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _split_semis(v) -> list[str]:
    if v is None:
        return []
    return [p.strip() for p in str(v).replace("\n", " ").split(";") if p.strip()]


class Workflow:
    """One row of the Defined Workflow List."""

    __slots__ = ("id", "name", "status", "wf_class", "bypass_under",
                 "risk_classes", "trees", "features", "applicable")

    def __init__(self, rec: dict):
        self.id = str(rec[W_ID]).strip()
        self.name = str(rec.get(W_NAME) or "").strip()
        self.status = str(rec.get(W_STATUS) or "").strip()
        self.wf_class = str(rec.get(W_CLASS) or "").strip()
        self.bypass_under = str(rec.get(W_BYPASS) or "").strip()
        self.risk_classes = C._split_list(rec.get(W_RISKCLASS))
        self.trees = C._split_list(rec.get(W_TREES))
        self.features = _split_semis(rec.get(W_FEATURES))
        self.applicable = {
            name: str(rec.get(f"{name} Applicable") or "").strip().lower() == "yes"
            for name, *_ in C.VARIANTS}

    @property
    def is_operator(self) -> bool:
        return self.wf_class == OPERATOR_CLASS

    @property
    def is_admin(self) -> bool:
        return self.wf_class == ADMIN_CLASS

    @property
    def functional(self) -> bool:
        return self.status.strip().lower().startswith("functional")

    def __repr__(self):
        return f"<Workflow {self.id} {self.wf_class}>"


class Cell:
    """The measured trials for one (workflow, variant, path)."""

    __slots__ = ("workflow_id", "variant", "path", "trials")

    def __init__(self, workflow_id, variant, path):
        self.workflow_id, self.variant, self.path = workflow_id, variant, path
        self.trials: list[dict] = []

    @property
    def n(self) -> int:
        return len(self.trials)

    def values(self, measure: str) -> list[float]:
        return [t[measure] for t in self.trials if t.get(measure) is not None]

    def median(self, measure: str) -> float | None:
        v = self.values(measure)
        return st.median(v) if v else None

    def iqr(self, measure: str) -> tuple[float, float] | None:
        v = sorted(self.values(measure))
        if not v:
            return None
        if len(v) < 4:
            return (v[0], v[-1])
        q = st.quantiles(v, n=4, method="inclusive")
        return (q[0], q[2])

    def __repr__(self):
        return f"<Cell {self.workflow_id}/{self.variant}/{self.path} n={self.n}>"


class BurdenModel:
    """The loaded burden workbook."""

    def __init__(self, workbook: Path = BURDEN_WORKBOOK):
        if not workbook.exists():
            raise SystemExit(
                f"\nburden workbook not found:\n  {workbook}\n\n"
                f"Place it there, or edit BURDEN_WORKBOOK in core_burden.py.\n")
        wb = openpyxl.load_workbook(workbook, data_only=True)
        self.workbook_path = workbook

        hdr, body = C._load_sheet_rows(wb, SHEET_WORKFLOWS)
        if hdr is None:
            raise SystemExit(f"worksheet '{SHEET_WORKFLOWS}' not found in {workbook}")
        self.workflows = [Workflow(dict(zip(hdr, r))) for r in body if r and r[0]]
        self.wf_by_id = {w.id: w for w in self.workflows}

        hdr, body = C._load_sheet_rows(wb, SHEET_TRIALS)
        if hdr is None:
            raise SystemExit(f"worksheet '{SHEET_TRIALS}' not found in {workbook}")
        self.cells: dict[tuple, Cell] = {}
        self.trial_count = 0
        self.unmeasured = 0
        self.sources: set[str] = set()
        rows_for_check: list[dict] = []
        for r in body:
            rec = dict(zip(hdr, r))
            wf = rec.get(T_WF)
            if not wf:
                continue
            vals = {k: _num(rec.get(k)) for k in MEASURES}
            if vals[T_ELAPSED] is None:
                self.unmeasured += 1
                continue
            src = rec.get(T_SOURCE)
            if src:
                self.sources.add(str(src).strip())
            key = (str(wf).strip(), str(rec.get(T_VARIANT) or "").strip(),
                   str(rec.get(T_PATH) or SANCTIONED).strip())
            self.cells.setdefault(key, Cell(*key)).trials.append(vals)
            self.trial_count += 1
            rows_for_check.append(vals)

        self.carries_derived = self._carries_are_derived(rows_for_check)
        self._check_measured()

    @staticmethod
    def _carries_are_derived(rows: list[dict]) -> bool:
        """
        Is the carries column an independent observation, or arithmetic?

        The workbook has carried a calculated column

            Working Memory Carries = Operator Steps - Context Switches - 1

        which is not a measurement. It is a restatement of two columns already
        recorded, perfectly correlated with step count, so it cannot show
        anything those two do not already show -- and it moves the WRONG way:
        a variant that adds steps is reported as adding carries, when the
        reason to count carries at all is that the two can move in opposite
        directions.

        Detected rather than assumed, so a workbook where the column is
        genuinely coded by hand is used normally.
        """
        usable = [r for r in rows if None not in
                  (r.get(T_CARRY), r.get(T_STEPS), r.get(T_SWITCH))]
        if not usable:
            return False
        return all(r[T_CARRY] == r[T_STEPS] - r[T_SWITCH] - 1 for r in usable)

    def _check_measured(self) -> None:
        if self.trial_count:
            return
        raise SystemExit(
            f"\nno measured trials found in '{SHEET_TRIALS}'.\n\n"
            f"  workbook: {self.workbook_path}\n\n"
            f"Every row is blank in '{T_ELAPSED}'. Fill the trials and re-run.\n")

    # -- accessors ----------------------------------------------------------

    @property
    def variant_names(self) -> list[str]:
        return [v[0] for v in C.VARIANTS]

    @property
    def reportable_measures(self) -> list[str]:
        """The measures that carry independent information."""
        m = [T_ELAPSED, T_STEPS, T_SWITCH]
        if not self.carries_derived:
            m.append(T_CARRY)
        return m

    def operator_workflows(self) -> list[Workflow]:
        return [w for w in self.workflows if w.is_operator]

    def admin_workflows(self) -> list[Workflow]:
        return [w for w in self.workflows if w.is_admin]

    def cell(self, wf: str, variant: str, path: str = SANCTIONED) -> Cell | None:
        return self.cells.get((wf, variant, path))

    def med(self, wf: str, variant: str, measure: str = T_ELAPSED,
            path: str = SANCTIONED) -> float | None:
        c = self.cell(wf, variant, path)
        return c.median(measure) if c else None

    def iqr(self, wf: str, variant: str, measure: str = T_ELAPSED,
            path: str = SANCTIONED):
        c = self.cell(wf, variant, path)
        return c.iqr(measure) if c else None

    def ratio(self, wf: str, variant: str,
              measure: str = T_ELAPSED) -> float | None:
        """Against the same workflow at baseline. None when either side is absent."""
        b = self.med(wf, C.BASELINE, measure)
        v = self.med(wf, variant, measure)
        if not b or v is None:
            return None
        return v / b

    def delta(self, wf: str, variant: str, measure: str) -> float | None:
        b = self.med(wf, C.BASELINE, measure)
        v = self.med(wf, variant, measure)
        return None if b is None or v is None else v - b

    def bpr(self, wf: str, variant: str = "Mediated") -> float | None:
        """
        Bypass Pressure Ratio: sanctioned elapsed time over the least-resistance
        path available to an operator working around the control.

        Below 1.0 the sanctioned path is the quicker one and there is no
        pressure to bypass at all.
        """
        s = self.med(wf, variant, T_ELAPSED, SANCTIONED)
        b = self.med(wf, variant, T_ELAPSED, BYPASS)
        if s is None or not b:
            return None
        return s / b

    def variant_median_ratio(self, variant: str,
                             measure: str = T_ELAPSED) -> float | None:
        """Median burden ratio across the operator workflows."""
        rs = [self.ratio(w.id, variant, measure) for w in self.operator_workflows()]
        rs = [r for r in rs if r is not None]
        return st.median(rs) if rs else None

    def totals(self, variant: str, measure: str,
               workflows=None) -> float | None:
        """
        Summed median across workflows measurable under BOTH this variant and
        baseline, so the totals are like-for-like.
        """
        pool = workflows if workflows is not None else self.operator_workflows()
        vals = [self.med(w.id, variant, measure) for w in pool
                if self.med(w.id, C.BASELINE, measure) is not None
                and self.med(w.id, variant, measure) is not None]
        return sum(vals) if vals else None


def load_risk_model():
    """
    The Control Traceability Matrix, or None.

    The risk-burden comparison needs both workbooks. The burden evaluation
    stands on its own when the matrix is absent, so this never raises; the
    comparison is skipped and the summary says so.
    """
    try:
        return C.Model()
    except SystemExit:
        return None
    except Exception:
        return None
