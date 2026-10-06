"""Check plugin base class, registry and runner.

A check is a small class: metadata (id, title, severity, category, references...) plus an
`evaluate()` method that returns a list of evidence strings. Empty list = check passes.
Modules in `m365audit/checks/` are imported automatically, so adding a check means adding a
class decorated with `@register` - nothing else to wire.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = {
    "access": "Accès conditionnel et MFA",
    "privileged": "Rôles à privilèges",
    "accounts": "Comptes, invités et mots de passe",
    "apps": "Applications et consentement OAuth",
    "collab": "Messagerie et collaboration",
    "logging": "Journalisation et supervision",
}
EFFORTS = {
    "quick": "Quick wins (< 1 semaine)",
    "30d": "Sous 30 jours",
    "90d": "Sous 90 jours",
}
MAX_EVIDENCE = 25

_REGISTRY: list[type["Check"]] = []


class Check:
    id: str = ""
    title: str = ""
    severity: str = "medium"
    category: str = "accounts"
    effort: str = "30d"
    why: str = ""
    remediation: str = ""
    references: list[str] = []
    license_note: str = ""  # licence dependency (Entra ID P1 / P2), shown in the report
    # list of (technique id, name); names checked against ATT&CK v19.2 on 2026-10-05
    mitre: list[tuple[str, str]] = []

    def evaluate(self, t, cfg) -> list[str]:  # pragma: no cover - interface
        raise NotImplementedError


def register(cls: type[Check]) -> type[Check]:
    for attr in ("id", "title", "why", "remediation"):
        if not getattr(cls, attr):
            raise ValueError(f"{cls.__name__}: attribut '{attr}' vide")
    if not cls.references:
        raise ValueError(f"{cls.id}: au moins une référence est obligatoire")
    if cls.severity not in SEVERITIES:
        raise ValueError(f"{cls.id}: sévérité inconnue {cls.severity}")
    if cls.category not in CATEGORIES:
        raise ValueError(f"{cls.id}: catégorie inconnue {cls.category}")
    if cls.effort not in EFFORTS:
        raise ValueError(f"{cls.id}: effort inconnu {cls.effort}")
    if any(c.id == cls.id for c in _REGISTRY):
        raise ValueError(f"identifiant de contrôle en double: {cls.id}")
    _REGISTRY.append(cls)
    return cls


def all_checks() -> list[Check]:
    from . import checks as pkg
    for mod in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"{pkg.__name__}.{mod.name}")
    return [cls() for cls in sorted(_REGISTRY, key=lambda c: c.id)]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    effort: str
    why: str
    remediation: str
    references: list[str]
    mitre: list[dict]
    license_note: str = ""
    evidence: list[str] = field(default_factory=list)
    affected: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "category": self.category, "effort": self.effort, "affected": self.affected,
            "evidence": self.evidence, "why": self.why, "remediation": self.remediation,
            "references": self.references, "mitre": self.mitre,
            "license_note": self.license_note,
        }


def run_checks(t, cfg, checks: list[Check] | None = None) -> list[Finding]:
    findings = []
    for chk in checks if checks is not None else all_checks():
        evidence = chk.evaluate(t, cfg)
        if not evidence:
            continue
        shown = evidence[:MAX_EVIDENCE]
        if len(evidence) > MAX_EVIDENCE:
            shown.append(f"... et {len(evidence) - MAX_EVIDENCE} autre(s)")
        findings.append(Finding(
            id=chk.id, title=chk.title, severity=chk.severity, category=chk.category,
            effort=chk.effort, why=chk.why, remediation=chk.remediation,
            references=list(chk.references),
            mitre=[{"id": i, "name": n} for i, n in chk.mitre],
            license_note=chk.license_note, evidence=shown, affected=len(evidence),
        ))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.id))
    return findings
