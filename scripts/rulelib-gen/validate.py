"""Stage 3 of the generator pipeline: the quality gate. Fails the build (via
ValidationError) only on structural problems or a systemic per-backend
regression; an isolated single rule/backend translation gap is tolerated —
see the design spec's "Generator Pipeline" validate.py policy."""
from collections import defaultdict


class ValidationError(Exception):
    pass


def validate_build(built_rules: list[dict], known_technique_ids: set[str], failure_threshold: float = 0.25) -> None:
    seen_rule_ids: set[str] = set()
    seen_sigma_ids: set[str] = set()
    backend_attempts: dict[str, int] = defaultdict(int)
    backend_failures: dict[str, int] = defaultdict(int)

    for rule in built_rules:
        if rule["id"] in seen_rule_ids:
            raise ValidationError(f"duplicate rule id: {rule['id']}")
        seen_rule_ids.add(rule["id"])

        if rule["sigmaId"] in seen_sigma_ids:
            raise ValidationError(f"duplicate sigma id: {rule['sigmaId']}")
        seen_sigma_ids.add(rule["sigmaId"])

        for tid in rule["techniqueIds"]:
            if tid not in known_technique_ids:
                raise ValidationError(f"unrecognized ATT&CK technique {tid} on rule {rule['id']}")

        if not rule["translations"]:
            raise ValidationError(f"rule {rule['id']} has zero successful translations across all backends")

        for t in rule["translations"]:
            backend_attempts[t["backend"]] += 1
        for f in rule["failures"]:
            backend_attempts[f["backend"]] += 1
            backend_failures[f["backend"]] += 1

    for backend, attempts in backend_attempts.items():
        if attempts == 0:
            continue
        rate = backend_failures[backend] / attempts
        if rate > failure_threshold:
            raise ValidationError(
                f"backend {backend!r} failure rate {rate:.0%} exceeds the {failure_threshold:.0%} "
                "threshold — likely a broken backend plugin or a major compatibility regression, "
                "not normal per-rule variance"
            )
