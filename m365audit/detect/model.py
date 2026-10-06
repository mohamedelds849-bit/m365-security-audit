"""Load and validate JSON-lines log files (see docs/SCHEMA.md, part B).

Two simplified, flattened log formats inspired by the Microsoft Sentinel tables:
- sign-ins  (SigninLogs):              one Entra ID interactive sign-in per line
- audit     (OfficeActivity / AuditLogs): one Exchange or Entra ID audit event per line

The field names are simplified on purpose (flat, camelCase); docs/KQL.md shows how each one
maps to the real table columns. Every line is validated; an error names the file line.
"""
from __future__ import annotations

import json
import os

from ..model import SchemaError, parse_date

MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_LINES = 2_000_000

SIGNIN_FIELDS = {
    "time": "date", "userPrincipalName": str, "ipAddress": str, "clientAppUsed": str,
    "resultType": int, "country": str, "city": str, "latitude": float, "longitude": float,
    "appDisplayName": str,
}
SIGNIN_REQUIRED = {"time", "userPrincipalName", "ipAddress", "resultType"}
AUDIT_FIELDS = {"time": "date", "workload": str, "operation": str, "userId": str,
                "clientIP": str, "parameters": dict}
AUDIT_REQUIRED = {"time", "workload", "operation", "userId"}
WORKLOADS = {"Exchange", "AzureActiveDirectory", "SharePoint", "MicrosoftTeams"}

RESULT_SUCCESS = 0
RESULT_BAD_PASSWORD = 50126   # Invalid username or password
RESULT_LOCKED = 50053         # Account locked (smart lockout) / malicious IP blocked
RESULT_MFA_FAILED = 500121    # Authentication failed during strong authentication request


def _validate(obj, fields, required, where):
    if not isinstance(obj, dict):
        raise SchemaError(f"{where}: objet JSON attendu")
    missing = sorted(k for k in required if obj.get(k) is None)
    if missing:
        raise SchemaError(f"{where}: champ(s) obligatoire(s) manquant(s) {missing}")
    out = {}
    for name, ftype in fields.items():
        value = obj.get(name)
        if value is None:
            out[name] = None if ftype in ("date", float, dict) else ("" if ftype is str else None)
            continue
        loc = f"{where}.{name}"
        if ftype == "date":
            out[name] = parse_date(value, loc)
        elif ftype is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaError(f"{loc}: entier attendu, reçu {value!r}")
            out[name] = value
        elif ftype is float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SchemaError(f"{loc}: nombre attendu, reçu {value!r}")
            out[name] = float(value)
        elif not isinstance(value, ftype):
            raise SchemaError(f"{loc}: type {ftype.__name__} attendu, reçu {type(value).__name__}")
        else:
            out[name] = value
    return out


def _check_signin(s, where):
    lat, lon = s["latitude"], s["longitude"]
    if (lat is None) != (lon is None):
        raise SchemaError(f"{where}: latitude et longitude vont ensemble")
    if lat is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise SchemaError(f"{where}: coordonnées hors plage ({lat}, {lon})")


def _check_audit(a, where):
    if a["workload"] not in WORKLOADS:
        raise SchemaError(f"{where}.workload: valeur inconnue {a['workload']!r}")
    if a["parameters"] is None:
        a["parameters"] = {}


def read_jsonl(path: str, kind: str) -> list[dict]:
    """Read a .jsonl file of `kind` 'signin' or 'audit'. Events come back sorted by time
    (stable: file order breaks ties), so detections never depend on file ordering."""
    fields, required, extra = ((SIGNIN_FIELDS, SIGNIN_REQUIRED, _check_signin) if kind == "signin"
                               else (AUDIT_FIELDS, AUDIT_REQUIRED, _check_audit))
    name = os.path.basename(path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SchemaError(f"fichier introuvable ou illisible: {path}") from exc
    if size > MAX_FILE_BYTES:
        raise SchemaError(f"{name}: fichier trop volumineux ({size} octets)")
    events = []
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            for n, line in enumerate(fh, 1):
                if n > MAX_LINES:
                    raise SchemaError(f"{name}: plus de {MAX_LINES} lignes")
                if not line.strip():
                    continue
                where = f"{name}:{n}"
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SchemaError(f"{where}: JSON invalide ({exc.msg})") from exc
                ev = _validate(obj, fields, required, where)
                extra(ev, where)
                ev["_line"] = n
                events.append(ev)
    except UnicodeDecodeError as exc:
        raise SchemaError(f"{name}: le fichier n'est pas encodé en UTF-8") from exc
    events.sort(key=lambda e: (e["time"], e["_line"]))
    return events
