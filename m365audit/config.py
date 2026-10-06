"""Load thresholds from YAML (config/default.yaml, optionally overridden by --config)."""
from __future__ import annotations

import copy
import os

import yaml

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "config", "default.yaml")
STR_LISTS = ("privileged_roles", "high_privilege_permissions", "weak_auth_methods",
             "legacy_client_apps")


class ConfigError(ValueError):
    pass


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _read_yaml(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)  # safe_load: never instantiate arbitrary objects
    except OSError as exc:
        raise ConfigError(f"configuration illisible: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide dans {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: la racine doit être un dictionnaire")
    return data


def _positive_numbers(section: dict, name: str) -> None:
    if not isinstance(section, dict):
        raise ConfigError(f"{name}: dictionnaire attendu")
    for key, value in section.items():
        if isinstance(value, list):
            if not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{name}.{key}: liste de chaînes attendue")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ConfigError(f"{name}.{key}: nombre positif attendu, reçu {value!r}")


def load_config(path: str | None = None) -> dict:
    cfg = _read_yaml(DEFAULT_PATH)
    if path:
        cfg = _merge(cfg, _read_yaml(path))
    _positive_numbers(cfg.get("thresholds", {}), "thresholds")
    _positive_numbers(cfg.get("detections", {}), "detections")
    for key in STR_LISTS:
        value = cfg.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{key}: liste de chaînes attendue")
    th = cfg.get("thresholds", {})
    if th.get("min_global_admins", 0) > th.get("max_global_admins", 0):
        raise ConfigError("thresholds.min_global_admins doit être <= max_global_admins")
    return cfg
