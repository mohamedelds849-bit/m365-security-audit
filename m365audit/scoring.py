"""Risk scoring (0-100, LOWER IS BETTER), same formula as ad-security-audit. See docs/SCORING.md.

    points(finding)  = SEVERITY_POINTS[severity]          (independent of the object count)
    category score   = min(100, sum of points of the findings in that category)
    global score     = round(0.5 * max(category scores) + 0.5 * mean(category scores))

Why not the plain maximum like PingCastle? With the max alone, fixing every category except
one leaves the global score unchanged, which hides real progress in a before/after view.
Why not the plain mean? One catastrophic category (e.g. privileged accounts) must weigh
heavily: half of the global score follows the worst category.
"""
from __future__ import annotations

from .engine import CATEGORIES

SEVERITY_POINTS = {"critical": 40, "high": 20, "medium": 10, "low": 5}
CATEGORY_CAP = 100
LEVELS = [(20, "faible"), (50, "modéré"), (75, "élevé"), (100, "critique")]


def level(score: int) -> str:
    for upper, name in LEVELS:
        if score <= upper:
            return name
    return LEVELS[-1][1]


def score(findings) -> dict:
    cats = {c: 0 for c in CATEGORIES}
    for f in findings:
        cats[f.category] += SEVERITY_POINTS[f.severity]
    cats = {c: min(CATEGORY_CAP, v) for c, v in cats.items()}
    values = list(cats.values())
    global_score = round(0.5 * max(values) + 0.5 * (sum(values) / len(values)))
    counts = {s: 0 for s in SEVERITY_POINTS}
    for f in findings:
        counts[f.severity] += 1
    return {
        "global": global_score,
        "level": level(global_score),
        "categories": cats,
        "severity_counts": counts,
        "formula": "global = round(0.5*max(catégories) + 0.5*moyenne(catégories)); "
                   "catégorie = min(100, Σ points); critical=40 high=20 medium=10 low=5",
    }
