"""
ScoringEngine — direct port of BAS.Server/ScoringEngine.cs.
Same weights, same formula, same classification thresholds.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SimScore:
    risk_score:               int = 0
    classification:           str = "Unknown"
    confidence:               int = 0
    execution_reliability:    int = 0
    attack_progression:       int = 0
    objective_success:        int = 0
    detection_timing:         int = 0
    blast_radius:             int = 0
    prevention_effectiveness: int = 0

    def to_dict(self) -> dict:
        return {
            "riskScore":               self.risk_score,
            "classification":          self.classification,
            "confidence":              self.confidence,
            "executionReliability":    self.execution_reliability,
            "attackProgression":       self.attack_progression,
            "objectiveSuccess":        self.objective_success,
            "detectionTiming":         self.detection_timing,
            "blastRadius":             self.blast_radius,
            "preventionEffectiveness": self.prevention_effectiveness,
        }


def _phase_weight(phase: str) -> int:
    p = (phase or "").lower()
    if "initial access"  in p: return 1
    if "execution"       in p: return 2
    if "defense evasion" in p: return 2
    if "persistence"     in p: return 3
    if "privilege"       in p: return 4
    if "credential"      in p: return 5
    if "lateral"         in p: return 6
    if "command"         in p: return 6
    if "exfiltration"    in p or "c2" in p: return 7
    if "impact"          in p: return 7
    if "post-compromise" in p: return 7
    return 1


def _classify(risk: int) -> str:
    if risk <= 20: return "Protected"
    if risk <= 40: return "Low Risk"
    if risk <= 60: return "Medium Risk"
    if risk <= 80: return "High Risk"
    return "Critical"


def compute(categories: list[dict[str, Any]]) -> SimScore:
    all_checks = [ch for cat in categories for ch in (cat.get("checks") or [])]
    if not all_checks:
        return SimScore()

    ap = _attack_progression(categories)
    os_ = _objective_success(all_checks)
    dt = _detection_timing(categories)
    br = _blast_radius(categories)
    pe = _prevention_effectiveness(all_checks)

    risk = max(0, min(100, ap + os_ + dt + br - pe))

    return SimScore(
        risk_score=risk,
        classification=_classify(risk),
        confidence=_confidence(all_checks),
        execution_reliability=_reliability(all_checks),
        attack_progression=ap,
        objective_success=os_,
        detection_timing=dt,
        blast_radius=br,
        prevention_effectiveness=pe,
    )


def _attack_progression(categories: list[dict]) -> int:
    weights = [
        _phase_weight(cat.get("phase", ""))
        for cat in categories
        if any(ch.get("result") == "Fail" for ch in (cat.get("checks") or []))
    ]
    return round(max(weights, default=0) / 7.0 * 30)


def _objective_success(checks: list[dict]) -> int:
    countable = [c for c in checks if c.get("result") != "Skipped"]
    if not countable:
        return 0
    failed = sum(1 for c in countable if c.get("result") == "Fail")
    return round(failed / len(countable) * 25)


def _detection_timing(categories: list[dict]) -> int:
    def fail_weight(cat: dict) -> int:
        return _phase_weight(cat.get("phase", "")) if any(
            ch.get("result") == "Fail" for ch in (cat.get("checks") or [])
        ) else 0

    def pass_weight(cat: dict) -> int:
        return _phase_weight(cat.get("phase", "")) if any(
            ch.get("result") in ("Pass", "Blocked") for ch in (cat.get("checks") or [])
        ) else 0

    deepest_fail  = max((fail_weight(c) for c in categories), default=0)
    if deepest_fail == 0:
        return 0
    first_defense = min(
        (pw for c in categories if (pw := pass_weight(c)) > 0),
        default=None
    )
    if first_defense is None:
        return 25
    gap = max(0, deepest_fail - first_defense)
    return round(gap / 6.0 * 25)


def _blast_radius(categories: list[dict]) -> int:
    weights = [
        _phase_weight(cat.get("phase", ""))
        for cat in categories
        if any(ch.get("result") == "Fail" for ch in (cat.get("checks") or []))
    ]
    deepest = max(weights, default=0)
    if deepest >= 7: return 20
    if deepest >= 5: return 14
    if deepest >= 3: return 8
    if deepest >= 1: return 3
    return 0


def _prevention_effectiveness(checks: list[dict]) -> int:
    if not checks:
        return 0
    prevented = sum(1 for c in checks if c.get("result") in ("Pass", "Blocked"))
    return round(prevented / len(checks) * 50)


def _confidence(checks: list[dict]) -> int:
    countable = [c for c in checks if c.get("result") != "Skipped"]
    if not countable:
        return 0
    prevented = sum(1 for c in countable if c.get("result") in ("Pass", "Blocked"))
    return round(prevented / len(countable) * 100)


def _reliability(checks: list[dict]) -> int:
    countable = [c for c in checks if c.get("result") != "Skipped"]
    if not countable:
        return 0
    failed = sum(1 for c in countable if c.get("result") == "Fail")
    return round(failed / len(countable) * 100)
