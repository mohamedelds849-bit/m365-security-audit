"""Before / after comparison of two audit reports (e.g. vulnerable vs hardened tenant export)."""
from __future__ import annotations

from .engine import CATEGORIES
from .report import bar as _bar, e, foot, head


def compare(before: dict, after: dict) -> dict:
    b_ids = {f["id"]: f for f in before["findings"]}
    a_ids = {f["id"]: f for f in after["findings"]}
    cats = {}
    for c in CATEGORIES:
        bv, av = before["score"]["categories"][c], after["score"]["categories"][c]
        cats[c] = {"before": bv, "after": av, "delta": av - bv}
    return {
        "same_tenant": before["tenant"].lower() == after["tenant"].lower(),
        "before": {"source": before["source"], "global": before["score"]["global"],
                   "level": before["score"]["level"]},
        "after": {"source": after["source"], "global": after["score"]["global"],
                  "level": after["score"]["level"]},
        "delta": after["score"]["global"] - before["score"]["global"],
        "categories": cats,
        "fixed": sorted(set(b_ids) - set(a_ids)),
        "new": sorted(set(a_ids) - set(b_ids)),
        "remaining": sorted(set(a_ids) & set(b_ids)),
        "titles": {i: (b_ids.get(i) or a_ids.get(i))["title"] for i in sorted(set(a_ids) | set(b_ids))},
    }


def render_compare_console(c: dict) -> str:
    sign = lambda v: f"{v:+d}"
    lines = [
        f"AVANT : {c['before']['global']}/100 ({c['before']['level']})  <- {c['before']['source']}",
        f"APRÈS : {c['after']['global']}/100 ({c['after']['level']})  <- {c['after']['source']}",
        f"DELTA : {sign(c['delta'])} points (négatif = amélioration)", "",
    ]
    if not c["same_tenant"]:
        lines.insert(0, "ATTENTION : les deux exports ne concernent pas le même tenant.")
    for cat, v in c["categories"].items():
        lines.append(f"  {CATEGORIES[cat]:<36} {v['before']:>3} -> {v['after']:>3}  ({sign(v['delta'])})")
    lines += ["", f"Corrigés ({len(c['fixed'])}) : " + (", ".join(c["fixed"]) or "aucun"),
              f"Restants ({len(c['remaining'])}) : " + (", ".join(c["remaining"]) or "aucun"),
              f"Nouveaux ({len(c['new'])}) : " + (", ".join(c["new"]) or "aucun")]
    return "\n".join(lines)


def render_compare_html(c: dict, version: str) -> str:
    out = [head("Comparaison avant / après")]
    out.append("<h1>Comparaison avant / après remédiation</h1>")
    if not c["same_tenant"]:
        out.append('<p class="pos"><b>Attention : les deux exports ne concernent pas le même tenant.</b></p>')
    out.append('<div class="card score">')
    for key, name in (("before", "Avant"), ("after", "Après")):
        out.append(f'<div><div class="mute">{name} - <code>{e(c[key]["source"])}</code></div>'
                   f'<div class="big">{c[key]["global"]}</div><div>{e(c[key]["level"])}</div></div>')
    cls = "neg" if c["delta"] <= 0 else "pos"
    out.append(f'<div><div class="mute">Delta</div><div class="big {cls}">{c["delta"]:+d}</div>'
               f'<div>négatif = amélioration</div></div></div>')
    out.append("<table><tr><th>Catégorie</th><th>Avant</th><th>Après</th><th>Delta</th></tr>")
    for cat, v in c["categories"].items():
        out.append(f"<tr><td>{e(CATEGORIES[cat])}</td><td>{_bar(v['before'])}{v['before']}</td>"
                   f"<td>{_bar(v['after'])}{v['after']}</td><td>{v['delta']:+d}</td></tr>")
    out.append("</table>")
    for key, name in (("fixed", "Corrigés"), ("remaining", "Restants"), ("new", "Nouveaux")):
        out.append(f"<h2>{name} ({len(c[key])})</h2><ul>")
        out += [f"<li>{e(i)} - {e(c['titles'][i])}</li>" for i in c[key]]
        out.append("</ul>")
    out.append(foot(version))
    return "".join(out)

