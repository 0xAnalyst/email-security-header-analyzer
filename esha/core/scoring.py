"""Risk-score configuration.

The defaults reproduce ESHA's built-in scoring. Override them with a JSON file
(``ESHA_CONFIG=/path/esha.json``, or ``esha.json`` in the working directory)
and/or the ``ESHA_WEIGHTS`` environment variable, which wins over the file::

    {
      "severity_weights": {"critical": 40, "high": 25, "medium": 12, "low": 4},
      "rule_weights": {"ESHA-105": 4, "ESHA-304": 0},
      "thresholds": {"high": 60, "medium": 25},
      "critical_floor": 80,
      "disabled_rules": ["ESHA-209"]
    }

    ESHA_WEIGHTS="high=30,ESHA-304=0,threshold.high=70,critical_floor=90"

A finding scores its rule weight if one is set in ``rule_weights``, otherwise
the rule's built-in weight when the finding has the rule's default severity,
otherwise the weight of its severity. ``info`` and ``pass`` count 0 unless a
rule weight says otherwise. The total is capped at 100; any critical finding
lifts it to at least ``critical_floor``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .rules import BY_ID, SEVERITIES, Rule

DEFAULT_SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0, "pass": 0}


class ConfigError(ValueError):
    pass


@dataclass
class ScoringConfig:
    severity_weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_WEIGHTS))
    rule_weights: dict[str, int] = field(default_factory=dict)
    high: int = 60
    medium: int = 25
    critical_floor: int | None = 80
    disabled_rules: frozenset[str] = frozenset()
    sources: tuple[str, ...] = ()

    def points(self, rule: Rule, severity: str) -> int:
        if rule.id in self.rule_weights:
            return self.rule_weights[rule.id]
        if rule.weight is not None and severity == rule.severity:
            return rule.weight
        return self.severity_weights.get(severity, 0)

    def level(self, value: int) -> tuple[str, str]:
        if value >= self.high:
            return "high", "High risk"
        if value >= self.medium:
            return "medium", "Suspicious"
        return "low", "Low risk"

    def describe(self) -> dict:
        return {"sources": list(self.sources) or ["built-in defaults"],
                "severity_weights": dict(self.severity_weights), "rule_weights": dict(self.rule_weights),
                "thresholds": {"high": self.high, "medium": self.medium}, "critical_floor": self.critical_floor,
                "disabled_rules": sorted(self.disabled_rules)}


def _int(value, what: str, lo: int = 0, hi: int = 100) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{what} must be a whole number, got {value!r}") from None
    if isinstance(value, bool) or not lo <= n <= hi or (isinstance(value, float) and value != n):
        raise ConfigError(f"{what} must be a whole number from {lo} to {hi}, got {value!r}")
    return n


def _rule_id(rid: str, what: str) -> str:
    rid = str(rid).strip().upper()
    if rid not in BY_ID:
        raise ConfigError(f"{what}: unknown rule {rid!r} (run `python -m esha rules` for the list)")
    return rid


def _apply(cfg: ScoringConfig, data: dict, source: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a JSON object")
    known = {"severity_weights", "rule_weights", "thresholds", "critical_floor", "disabled_rules"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{source}: unknown setting(s) {', '.join(sorted(unknown))}")
    for sev, w in (data.get("severity_weights") or {}).items():
        if sev not in SEVERITIES:
            raise ConfigError(f"{source}: unknown severity {sev!r} (use {', '.join(SEVERITIES)})")
        cfg.severity_weights[sev] = _int(w, f"{source}: severity_weights.{sev}")
    for rid, w in (data.get("rule_weights") or {}).items():
        cfg.rule_weights[_rule_id(rid, source)] = _int(w, f"{source}: rule_weights.{rid}")
    th = data.get("thresholds") or {}
    if set(th) - {"high", "medium"}:
        raise ConfigError(f"{source}: thresholds only takes 'high' and 'medium'")
    if "high" in th:
        cfg.high = _int(th["high"], f"{source}: thresholds.high", 1)
    if "medium" in th:
        cfg.medium = _int(th["medium"], f"{source}: thresholds.medium", 1)
    if "critical_floor" in data:
        cf = data["critical_floor"]
        cfg.critical_floor = None if cf is None else _int(cf, f"{source}: critical_floor")
    if "disabled_rules" in data:
        dr = data["disabled_rules"]
        if not isinstance(dr, list):
            raise ConfigError(f"{source}: disabled_rules must be a list of rule IDs")
        cfg.disabled_rules = frozenset(_rule_id(r, source) for r in dr)


def _parse_env(value: str) -> dict:
    """``high=30,ESHA-304=0,threshold.high=70,critical_floor=90,disable=ESHA-209``"""
    data: dict = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ConfigError(f"ESHA_WEIGHTS: expected key=value, got {item!r}")
        key, val = (x.strip() for x in item.split("=", 1))
        k = key.lower()
        if k in SEVERITIES:
            data.setdefault("severity_weights", {})[k] = val
        elif k.startswith("threshold."):
            data.setdefault("thresholds", {})[k.split(".", 1)[1]] = val
        elif k == "critical_floor":
            data["critical_floor"] = None if val.lower() in ("none", "off") else val
        elif k == "disable":
            data.setdefault("disabled_rules", []).append(val)
        elif k.startswith("esha-"):
            data.setdefault("rule_weights", {})[key] = val
        else:
            raise ConfigError(f"ESHA_WEIGHTS: unknown key {key!r}")
    return data


def load(env: dict | None = None, cwd: Path | None = None) -> ScoringConfig:
    env = os.environ if env is None else env
    cfg = ScoringConfig()
    sources = []
    path = env.get("ESHA_CONFIG")
    if path:
        p = Path(path).expanduser()
        if not p.is_file():
            raise ConfigError(f"ESHA_CONFIG points to {p}, which does not exist")
    else:
        p = (cwd or Path.cwd()) / "esha.json"
        p = p if p.is_file() else None
    if p is not None:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ConfigError(f"{p}: {e}") from None
        _apply(cfg, data, str(p))
        sources.append(str(p))
    if env.get("ESHA_WEIGHTS"):
        _apply(cfg, _parse_env(env["ESHA_WEIGHTS"]), "ESHA_WEIGHTS")
        sources.append("ESHA_WEIGHTS")
    if cfg.medium > cfg.high:
        raise ConfigError(f"thresholds: medium ({cfg.medium}) must not be above high ({cfg.high})")
    cfg.sources = tuple(sources)
    return cfg


_current: ScoringConfig | None = None


def get_config() -> ScoringConfig:
    global _current
    if _current is None:
        _current = load()
    return _current


def set_config(cfg: ScoringConfig | None) -> None:
    """Replace the active configuration (None reloads from the environment next time)."""
    global _current
    _current = cfg
