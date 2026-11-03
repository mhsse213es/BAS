"""Stable Audspect rule ids. A rule keeps the same AUDRULE id for as long as its SigmaHQ id exists, across every
regeneration, so a scenario's rule_ids, a saved report and an exported bundle never point at a different rule
after the library is refreshed. New rules are numbered after the highest id ever issued; ids are never reused."""
import re

_NUM = re.compile(r"^AUDRULE-(\d+)$")


def assign_ids(sigma_ids: list[str], registry: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """Returns (ids for sigma_ids, updated registry). The registry maps sigmaId -> AUDRULE id and only grows."""
    updated = dict(registry)
    highest = max((int(m.group(1)) for v in registry.values() if (m := _NUM.match(v))), default=0)
    for sid in sorted(s for s in set(sigma_ids) if s not in updated):
        highest += 1
        updated[sid] = f"AUDRULE-{highest:06d}"
    return {sid: updated[sid] for sid in sigma_ids}, updated
