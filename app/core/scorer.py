"""
Risk scoring engine for SentraGuard Lite.

Converts detector findings into:
- Overall risk score (0-100)
- Risk tags
"""

from __future__ import annotations

from typing import Iterable

from app.core.findings import Finding
from app.core.policy import EXTRA_RULE_BONUS, EXTRA_RULE_BONUS_CAP


def calculate_score(findings: Iterable[Finding]) -> tuple[int, list[str]]:
    """
    Calculate the overall risk score and collect unique risk tags.

    Per tag:
        highest rule severity
        + EXTRA_RULE_BONUS for each additional DISTINCT rule that fired
          (capped at EXTRA_RULE_BONUS_CAP)

    Repeating the same rule many times never raises the score; tags are
    summed and the total is capped at 100.

    Returns:
        (risk score, sorted list of unique tags)
    """

    per_tag: dict[str, dict[str, int]] = {}

    for finding in findings:

        rules = per_tag.setdefault(finding.tag, {})

        rules[finding.rule_id] = max(
            rules.get(finding.rule_id, 0),
            finding.severity,
        )

    score = 0

    for rules in per_tag.values():

        severities = sorted(rules.values(), reverse=True)

        bonus = min(
            EXTRA_RULE_BONUS * (len(severities) - 1),
            EXTRA_RULE_BONUS_CAP,
        )

        score += severities[0] + bonus

    return min(score, 100), sorted(per_tag)
