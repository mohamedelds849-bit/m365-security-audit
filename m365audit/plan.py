"""Prioritised remediation plan: quick wins / 30 days / 90 days.

Each check declares an `effort` bucket. Inside a bucket, findings are sorted by severity
then id, so the most dangerous easy fixes come first.
"""
from __future__ import annotations

from .engine import EFFORTS, SEVERITIES


def build_plan(findings) -> list[dict]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    plan = []
    for bucket, label in EFFORTS.items():
        items = sorted((f for f in findings if f.effort == bucket),
                       key=lambda f: (order[f.severity], f.id))
        plan.append({
            "bucket": bucket,
            "label": label,
            "actions": [{"id": f.id, "severity": f.severity, "title": f.title,
                         "action": f.remediation, "affected": f.affected} for f in items],
        })
    return plan
