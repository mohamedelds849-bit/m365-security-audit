"""Render detection alerts as console text, JSON or standalone HTML (escaped, strict CSP)."""
from __future__ import annotations

import json

from .. import __version__
from ..report import SEV_FR, e, foot, head
from .rules import DETECTIONS, SEV_ORDER


def build_detection_report(alerts, signins_src: str, audit_src: str, n_signins: int,
                           n_audit: int) -> dict:
    counts = {s: 0 for s in SEV_ORDER}
    for a in alerts:
        counts[a.severity] += 1
    return {
        "tool": "m365-security-audit detect",
        "version": __version__,
        "sources": {"signins": signins_src, "audit": audit_src},
        "events": {"signins": n_signins, "audit": n_audit},
        "rules_run": [d.id for d in DETECTIONS],
        "severity_counts": counts,
        "alerts": [a.to_dict() for a in alerts],
        "disclaimer": "Détections hors ligne sur journaux synthétiques ; seuils pédagogiques, "
                      "à ajuster sur des données réelles (voir docs/DETECTIONS.md).",
    }


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def render_console(report: dict) -> str:
    c = report["severity_counts"]
    lines = [
        f"m365-security-audit detect {report['version']}",
        f"Événements : {report['events']['signins']} connexions ({report['sources']['signins']}), "
        f"{report['events']['audit']} événements d'audit ({report['sources']['audit']})",
        f"Règles : {', '.join(report['rules_run'])}",
        "",
        f"{len(report['alerts'])} alerte(s) : {c['critical']} critique(s), {c['high']} élevée(s), "
        f"{c['medium']} moyenne(s), {c['low']} faible(s)",
        "",
    ]
    for a in report["alerts"]:
        mitre = ",".join(m["id"] for m in a["mitre"])
        lines.append(f"[{a['severity'].upper():<8}] {a['time']} {a['rule']} {a['user']} - "
                     f"{a['summary']} ({mitre})")
        for ev in a["evidence"]:
            lines.append(f"               - {ev}")
    if not report["alerts"]:
        lines.append("Aucune alerte.")
    return "\n".join(lines)


def render_html(report: dict) -> str:
    out = [head("Détections M365 - journaux de connexion et d'audit")]
    out.append("<h1>Détections sur journaux Entra ID / Exchange</h1>")
    out.append(f'<p class="mute">{report["events"]["signins"]} connexions '
               f'(<code>{e(report["sources"]["signins"])}</code>), {report["events"]["audit"]} '
               f'événements d\'audit (<code>{e(report["sources"]["audit"])}</code>). '
               f'{e(report["disclaimer"])}</p>')
    c = report["severity_counts"]
    out.append(f'<div class="card score"><div><div class="big">{len(report["alerts"])}</div>'
               f'<div>alerte(s)</div></div><div>{c["critical"]} critique(s), {c["high"]} élevée(s), '
               f'{c["medium"]} moyenne(s), {c["low"]} faible(s)</div></div>')
    if not report["alerts"]:
        out.append('<p class="ok">Aucune alerte.</p>')
    for a in report["alerts"]:
        mitre = ", ".join(f"{m['id']} {m['name']}" for m in a["mitre"])
        out.append(f'<div class="card"><span class="sev {e(a["severity"])}">{e(SEV_FR[a["severity"]])}</span> '
                   f'<b>{e(a["rule"])} - {e(a["title"])}</b><br><span class="mute">{e(a["time"])} - '
                   f'{e(a["user"])} - {e(a["summary"])}</span><ul>')
        out += [f"<li>{e(x)}</li>" for x in a["evidence"]]
        out.append(f"</ul><p><b>Premières actions :</b> {e(a['triage'])}</p>"
                   f'<p class="mute"><b>MITRE ATT&amp;CK :</b> {e(mitre)}<br><b>Requête KQL '
                   f'équivalente :</b> docs/KQL.md#{e(a["kql"])}</p></div>')
    out.append(foot(report["version"]))
    return "".join(out)
