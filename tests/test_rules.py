import json
import re
from pathlib import Path

import pytest

from esha.__main__ import main, rules_markdown
from esha.core import analyze
from esha.core.rules import ATTACK, BY_ID, SEVERITIES, all_rules
from esha.core.scoring import ConfigError, ScoringConfig, load

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "tests" / "samples"
RANGES = {"0": "authentication", "1": "identity", "2": "routing", "3": "message", "4": "content", "5": "spam",
          "6": "enrichment", "9": "input"}


def sample_reports():
    for f in sorted(SAMPLES.rglob("*.eml")):
        yield f.name, analyze(f.read_text(), from_file=True)


# ---------------------------------------------------------------- registry
def test_rule_ids_are_stable_format_and_in_their_range():
    for r in all_rules():
        assert re.fullmatch(r"ESHA-\d{3}", r.id), r.id
        assert r.severity in SEVERITIES and all(s in SEVERITIES for s in r.also)
        assert all(t in ATTACK for t in r.attack), (r.id, r.attack)
        assert r.description, r.id
        hundreds = r.id[5]
        assert RANGES[hundreds] == r.category or (hundreds == "3" and r.category == "message"), (r.id, r.category)


def test_risky_rules_have_remediation_advice():
    for r in all_rules():
        if r.severity in ("critical", "high"):
            assert r.remediation, f"{r.id} needs remediation advice"


def test_rules_doc_is_up_to_date():
    doc = (ROOT / "docs" / "RULES.md").read_text()
    assert doc.strip() == rules_markdown().strip(), "run: python -m esha rules --markdown > docs/RULES.md"


def test_every_finding_carries_rule_metadata():
    for name, r in sample_reports():
        for f in r["findings"]:
            rule = BY_ID[f["rule_id"]]
            assert f["category"] == rule.category
            assert f["severity"] in rule.severities, (name, f)
            assert isinstance(f["weight"], int) and f["description"] and "attack" in f
            assert f["id"], "the legacy slug id is still present"


def test_score_is_sum_of_finding_weights():
    for name, r in sample_reports():
        total = min(100, sum(f["weight"] for f in r["findings"]))
        if not any(f["severity"] == "critical" for f in r["findings"]):
            assert r["score"]["value"] == total, name


def test_cli_rules_json(capsys):
    assert main(["rules", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {d["id"] for d in data} == set(BY_ID)


# ------------------------------------------------------------------ config
def test_default_config_reproduces_builtin_scoring():
    cfg = ScoringConfig()
    assert cfg.severity_weights == {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0, "pass": 0}
    assert (cfg.high, cfg.medium, cfg.critical_floor) == (60, 25, 80)


def test_config_file_and_env(tmp_path):
    (tmp_path / "esha.json").write_text(json.dumps({
        "severity_weights": {"low": 1}, "rule_weights": {"ESHA-304": 0}, "thresholds": {"high": 70},
        "disabled_rules": ["esha-209"]}))
    cfg = load(env={"ESHA_WEIGHTS": "high=30, ESHA-002=50, threshold.medium=20, critical_floor=off"}, cwd=tmp_path)
    assert cfg.severity_weights["low"] == 1 and cfg.severity_weights["high"] == 30
    assert cfg.rule_weights == {"ESHA-304": 0, "ESHA-002": 50}
    assert (cfg.high, cfg.medium, cfg.critical_floor) == (70, 20, None)
    assert cfg.disabled_rules == {"ESHA-209"}
    assert cfg.sources[-1] == "ESHA_WEIGHTS"


@pytest.mark.parametrize("env,match", [
    ({"ESHA_WEIGHTS": "ESHA-999=3"}, "unknown rule"),
    ({"ESHA_WEIGHTS": "high=abc"}, "whole number"),
    ({"ESHA_WEIGHTS": "high=500"}, "from 0 to 100"),
    ({"ESHA_WEIGHTS": "threshold.medium=90,threshold.high=50"}, "must not be above"),
    ({"ESHA_WEIGHTS": "colour=red"}, "unknown key"),
    ({"ESHA_CONFIG": "/nonexistent/esha.json"}, "does not exist"),
])
def test_invalid_config_is_rejected(env, match, tmp_path):
    with pytest.raises(ConfigError, match=match):
        load(env=env, cwd=tmp_path)


def test_config_changes_the_report():
    text = (SAMPLES / "phish_paypal.eml").read_text()
    base = analyze(text, from_file=True)
    lookalike = next(f for f in base["findings"] if f["rule_id"] == "ESHA-102")
    cfg = ScoringConfig(disabled_rules=frozenset({"ESHA-102"}), rule_weights={"ESHA-108": 0}, critical_floor=None)
    r = analyze(text, from_file=True, config=cfg)
    assert lookalike["title"] not in {f["title"] for f in r["findings"]}
    assert next(f for f in r["findings"] if f["rule_id"] == "ESHA-108")["weight"] == 0
    assert r["meta"]["scoring"]["disabled_rules"] == ["ESHA-102"]
    assert r["score"]["value"] < base["score"]["value"]


def test_invalid_config_stops_cli(monkeypatch, capsys):
    from esha.core import scoring
    monkeypatch.setenv("ESHA_WEIGHTS", "bogus=1")
    scoring.set_config(None)
    try:
        assert main(["analyze", str(SAMPLES / "legit_github.eml")]) == 1
        assert "Invalid ESHA scoring configuration" in capsys.readouterr().err
    finally:
        monkeypatch.delenv("ESHA_WEIGHTS")
        scoring.set_config(None)
