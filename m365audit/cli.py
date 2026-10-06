"""Command-line interface.

    python -m m365audit audit   EXPORT.json [--json OUT] [--html OUT] [--config CFG] [--fail-on SEV]
    python -m m365audit compare BEFORE.json AFTER.json [--json OUT] [--html OUT]
    python -m m365audit detect  --signins S.jsonl --audit A.jsonl [--json OUT] [--html OUT] [--fail-on SEV]
    python -m m365audit list-checks | list-detections
    python -m m365audit generate [--out DIR]

Exit codes: 0 = OK, 1 = findings / alerts at or above --fail-on, 2 = invalid input / config.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .compare import compare, render_compare_console, render_compare_html
from .config import ConfigError, load_config
from .engine import SEVERITIES, all_checks, run_checks
from .model import SchemaError, load_export
from .report import build_report, render_console, render_html, to_json


def _write(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def audit_file(path: str, cfg: dict) -> dict:
    t = load_export(path)
    checks = all_checks()
    findings = run_checks(t, cfg, checks)
    return build_report(t, findings, os.path.basename(path), len(checks))


def detect_files(signins_path: str, audit_path: str, cfg: dict) -> dict:
    from .detect.model import read_jsonl
    from .detect.report import build_detection_report
    from .detect.rules import run_detections
    signins = read_jsonl(signins_path, "signin")
    audit = read_jsonl(audit_path, "audit")
    alerts = run_detections(signins, audit, cfg)
    return build_detection_report(alerts, os.path.basename(signins_path),
                                  os.path.basename(audit_path), len(signins), len(audit))


def _fails(items, threshold: str | None) -> bool:
    if not threshold:
        return False
    limit = SEVERITIES.index(threshold)
    return any(SEVERITIES.index(i["severity"]) <= limit for i in items)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="m365audit", description="Audit hors ligne d'un export de "
                                "configuration Microsoft 365 / Entra ID et détections sur journaux.")
    p.add_argument("--version", action="version", version=f"m365-security-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="auditer un export JSON de configuration")
    a.add_argument("export")
    a.add_argument("--config", help="fichier YAML de seuils (surcharge config/default.yaml)")
    a.add_argument("--json", dest="json_out", help="écrire le résultat JSON")
    a.add_argument("--html", dest="html_out", help="écrire le rapport HTML autonome")
    a.add_argument("--quiet", action="store_true", help="pas de résumé console")
    a.add_argument("--fail-on", choices=SEVERITIES,
                   help="code retour 1 si un constat de cette sévérité (ou plus) existe")

    c = sub.add_parser("compare", help="comparer deux exports (avant / après)")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument("--config")
    c.add_argument("--json", dest="json_out")
    c.add_argument("--html", dest="html_out")

    d = sub.add_parser("detect", help="lancer les détections sur des journaux JSON lines")
    d.add_argument("--signins", required=True, help="journaux de connexion (.jsonl)")
    d.add_argument("--audit", required=True, help="événements d'audit Exchange / Entra (.jsonl)")
    d.add_argument("--config")
    d.add_argument("--json", dest="json_out")
    d.add_argument("--html", dest="html_out")
    d.add_argument("--quiet", action="store_true")
    d.add_argument("--fail-on", choices=SEVERITIES)

    sub.add_parser("list-checks", help="lister les contrôles de configuration")
    sub.add_parser("list-detections", help="lister les détections")
    g = sub.add_parser("generate", help="régénérer les données synthétiques AgriSouss")
    g.add_argument("--out", default="data")
    return p


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "list-checks":
            for chk in all_checks():
                mitre = ",".join(t for t, _ in chk.mitre) or "-"
                print(f"{chk.id:<13} {chk.severity:<8} {chk.category:<10} {mitre:<22} {chk.title}")
            return 0
        if args.cmd == "list-detections":
            from .detect.rules import DETECTIONS
            for det in DETECTIONS:
                mitre = ",".join(t for t, _ in det.mitre)
                print(f"{det.id:<8} {det.severity:<8} {mitre:<30} {det.title}")
            return 0
        if args.cmd == "generate":
            from .detect.synthetic import write_all as write_logs
            from .synthetic import write_all
            for path in write_all(args.out) + write_logs(os.path.join(args.out, "logs")):
                print(f"écrit : {path}")
            return 0
        cfg = load_config(args.config)
        if args.cmd == "audit":
            report = audit_file(args.export, cfg)
            if not args.quiet:
                print(render_console(report))
            if args.json_out:
                _write(args.json_out, to_json(report))
            if args.html_out:
                _write(args.html_out, render_html(report))
            return 1 if _fails(report["findings"], args.fail_on) else 0
        if args.cmd == "compare":
            before, after = audit_file(args.before, cfg), audit_file(args.after, cfg)
            result = compare(before, after)
            print(render_compare_console(result))
            if args.json_out:
                _write(args.json_out, json.dumps(result, ensure_ascii=False, indent=2))
            if args.html_out:
                _write(args.html_out, render_compare_html(result, __version__))
            return 0
        if args.cmd == "detect":
            from .detect import report as drep
            report = detect_files(args.signins, args.audit, cfg)
            if not args.quiet:
                print(drep.render_console(report))
            if args.json_out:
                _write(args.json_out, drep.to_json(report))
            if args.html_out:
                _write(args.html_out, drep.render_html(report))
            return 1 if _fails(report["alerts"], args.fail_on) else 0
    except (SchemaError, ConfigError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 2
    return 2  # pragma: no cover
