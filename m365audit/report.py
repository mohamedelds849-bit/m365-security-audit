"""Build the audit result and render it as console text, JSON or standalone HTML.

The HTML report has no external resource (no CDN, no script) and a strict
Content-Security-Policy. Every value coming from the export goes through html.escape().
"""
from __future__ import annotations

import json
from html import escape

from . import __version__
from .engine import CATEGORIES, EFFORTS
from .plan import build_plan
from .scoring import score

SEV_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}


def build_report(t, findings, source: str, checks_run: int) -> dict:
    return {
        "tool": "m365-security-audit",
        "version": __version__,
        "source": source,
        "tenant": t.tenant["defaultDomain"],
        "tenantName": t.tenant["displayName"],
        "exportedAt": t.exported_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "licences": {"entraIdP1": t.tenant["entraIdP1"], "entraIdP2": t.tenant["entraIdP2"]},
        "inventory": {"users": len(t.users),
                      "guests": sum(1 for u in t.users if u["userType"] == "Guest"),
                      "caPolicies": len(t.ca_policies),
                      "roleAssignments": len(t.role_assignments),
                      "applications": len(t.applications), "domains": len(t.domains)},
        "checks_run": checks_run,
        "score": score(findings),
        "findings": [f.to_dict() for f in findings],
        "plan": build_plan(findings),
    }


def to_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------- console
def render_console(report: dict) -> str:
    s, inv = report["score"], report["inventory"]
    lic = report["licences"]
    lines = [
        f"m365-security-audit {report['version']} - tenant {report['tenant']} "
        f"(export du {report['exportedAt']})",
        f"Inventaire : {inv['users']} utilisateurs dont {inv['guests']} invités, "
        f"{inv['caPolicies']} stratégie(s) d'accès conditionnel, {inv['roleAssignments']} "
        f"attribution(s) de rôle, {inv['applications']} application(s)",
        f"Licences : Entra ID P1 = {'oui' if lic['entraIdP1'] else 'non'}, "
        f"P2 = {'oui' if lic['entraIdP2'] else 'non'}",
        "",
        f"SCORE DE RISQUE GLOBAL : {s['global']}/100 ({s['level']}) - plus bas = meilleur",
    ]
    for cat, val in s["categories"].items():
        bar = "#" * (val // 5) + "." * (20 - val // 5)
        lines.append(f"  {CATEGORIES[cat]:<36} [{bar}] {val:>3}")
    c = s["severity_counts"]
    lines += ["", f"{len(report['findings'])} constat(s) sur {report['checks_run']} contrôles : "
              f"{c['critical']} critique(s), {c['high']} élevé(s), {c['medium']} moyen(s), "
              f"{c['low']} faible(s)", ""]
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper():<8}] {f['id']:<12} {f['title']}  ({f['affected']})")
        for ev in f["evidence"][:3]:
            lines.append(f"               - {ev}")
        if len(f["evidence"]) > 3:
            lines.append("               - ... voir le rapport JSON/HTML")
    lines += ["", "PLAN DE REMÉDIATION"]
    for b in report["plan"]:
        ids = ", ".join(a["id"] for a in b["actions"]) or "rien"
        lines.append(f"  {b['label']:<28} {ids}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2430;--mute:#5b6577;--line:#dde1e7;
--crit:#9b1c1c;--high:#c2410c;--med:#a16207;--low:#2563eb;--ok:#15803d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:28px 0 10px}
.mute{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:16px;margin:10px 0;overflow-wrap:anywhere}
.score{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.big{font-size:3rem;font-weight:700;line-height:1}
table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;border-bottom:1px solid var(--line);
text-align:left;vertical-align:top}th{font-size:.85rem;color:var(--mute);font-weight:600}
.bar{height:10px;background:#e8ebef;border-radius:5px;overflow:hidden;min-width:120px}
.bar span{display:block;height:100%;background:var(--high)}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:.8rem;font-weight:600}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}
.low{background:var(--low)}.ok{color:var(--ok)}.neg{color:var(--ok)}.pos{color:var(--crit)}
ul{margin:6px 0 6px 20px;padding:0}code{font-size:.9em}
details summary{cursor:pointer;font-weight:600}
@media print{details{display:block}details>*{display:block}}
footer{margin-top:32px;font-size:.85rem;color:var(--mute)}
"""
HEAD = ('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'">'
        '<title>{title}</title><style>' + CSS + '</style></head><body><main>')
FOOT = ('<footer>Généré par m365-security-audit {version}. Analyse hors ligne d\'un export ou '
        'de journaux ; aucune connexion au tenant. Données de démonstration synthétiques '
        '(AgriSouss SARL, entreprise fictive).</footer></main></body></html>')


def e(x) -> str:
    return escape(str(x), quote=True)


def head(title: str) -> str:
    # str.replace, not str.format: the CSS contains braces
    return HEAD.replace("{title}", e(title))


def foot(version: str) -> str:
    return FOOT.replace("{version}", e(version))


def bar(val: int) -> str:
    return f'<div class="bar"><span style="width:{max(0, min(100, int(val)))}%"></span></div>'


def render_html(report: dict) -> str:
    s = report["score"]
    out = [head(f"Audit M365 - {report['tenant']}")]
    out.append(f"<h1>Audit de configuration Microsoft 365 / Entra ID - {e(report['tenant'])}</h1>")
    out.append(f'<p class="mute">{e(report["tenantName"])} - export du {e(report["exportedAt"])} - '
               f'source <code>{e(report["source"])}</code> - {report["checks_run"]} contrôles '
               f'exécutés - Entra ID P1 : {"oui" if report["licences"]["entraIdP1"] else "non"}, '
               f'P2 : {"oui" if report["licences"]["entraIdP2"] else "non"}</p>')
    out.append('<div class="card score"><div><div class="big">'
               f'{s["global"]}<span class="mute" style="font-size:1rem">/100</span></div>'
               f'<div>Risque <b>{e(s["level"])}</b> (plus bas = meilleur)</div></div><table>')
    for cat, val in s["categories"].items():
        out.append(f"<tr><td>{e(CATEGORIES[cat])}</td><td>{bar(val)}</td><td>{val}</td></tr>")
    out.append(f'</table></div><p class="mute">Formule : {e(s["formula"])}</p>')

    out.append("<h2>Plan de remédiation priorisé</h2>")
    for b in report["plan"]:
        out.append(f'<div class="card"><b>{e(b["label"])}</b>')
        if not b["actions"]:
            out.append('<p class="ok">Aucune action.</p></div>')
            continue
        out.append("<table><tr><th>Contrôle</th><th>Sévérité</th><th>Action</th></tr>")
        for a in b["actions"]:
            out.append(f'<tr><td>{e(a["id"])}<br><span class="mute">{e(a["title"])}</span></td>'
                       f'<td><span class="sev {e(a["severity"])}">{e(SEV_FR[a["severity"]])}</span></td>'
                       f'<td>{e(a["action"])}</td></tr>')
        out.append("</table></div>")

    out.append(f"<h2>Constats ({len(report['findings'])})</h2>")
    if not report["findings"]:
        out.append('<p class="ok">Aucun constat : tous les contrôles sont conformes.</p>')
    for f in report["findings"]:
        mitre = ", ".join(f"{m['id']} {m['name']}" for m in f["mitre"]) or "aucun mapping direct"
        out.append(f'<div class="card"><span class="sev {e(f["severity"])}">'
                   f'{e(SEV_FR[f["severity"]])}</span> <b>{e(f["id"])} - {e(f["title"])}</b> '
                   f'<span class="mute">({f["affected"]} élément(s), {e(EFFORTS[f["effort"]])})</span>')
        out.append("<details open><summary>Preuves</summary><ul>")
        out += [f"<li>{e(x)}</li>" for x in f["evidence"]]
        out.append("</ul></details>")
        out.append(f"<p><b>Pourquoi c'est important :</b> {e(f['why'])}</p>")
        out.append(f"<p><b>Remédiation :</b> {e(f['remediation'])}</p>")
        if f["license_note"]:
            out.append(f"<p class=\"mute\"><b>Licence :</b> {e(f['license_note'])}</p>")
        out.append("<p class=\"mute\"><b>Références :</b> " + " ; ".join(e(r) for r in f["references"])
                   + f"<br><b>MITRE ATT&amp;CK :</b> {e(mitre)}</p></div>")
    out.append(foot(report["version"]))
    return "".join(out)
