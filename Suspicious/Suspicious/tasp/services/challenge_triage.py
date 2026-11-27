"""Rules-only triage of a challenge: does it need a TheHive alert now (ALERT) or can it
wait in the analysts' queue (ANALYST)?

Ordered rules, first match wins, each with a reason code. Only an explicit rule may say
ANALYST; anything unmatched alerts, as every challenge did before. The reporter's reason is
untrusted text: it can only escalate (a compromise claim), never suppress.

Mode (``integrations.thehive.challenge_triage``): ``off``, ``log`` (default: record the
decision, still alert) or ``enforce`` (an ANALYST decision sends no alert).
"""
from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass

logger = logging.getLogger(__name__)

ALERT = "ALERT"
ANALYST = "ANALYST"
RULESET = "2026-11-27"

# Claims of a compromise, English and French. A false match only costs an alert.
_COMPROMISE = re.compile(
    r"click|clic|cliqu|opened|open(ed)? the|ouvert|ouvr|entered|typed|saisi|"
    r"password|mot de passe|credential|identifiant|login|logged in|connect[ée]|"
    r"download|télécharg|telecharg|install|paid|payé|paye|virement|wire",
    re.IGNORECASE,
)
_QUIET = {"Safe", "Inconclusive"}


@dataclass(frozen=True)
class Facts:
    verdict: str
    proposed: str
    reason: str
    campaign_verdicts: tuple = ()
    denylisted: bool = False


@dataclass(frozen=True)
class Decision:
    decision: str
    reason_code: str
    ruleset: str = RULESET


def decide(f: Facts) -> Decision:
    if f.reason and _COMPROMISE.search(f.reason):
        return Decision(ALERT, "compromise-claimed")
    if f.verdict == "Dangerous":
        return Decision(ALERT, "case-dangerous")
    if "Dangerous" in f.campaign_verdicts:
        return Decision(ALERT, "campaign-dangerous")
    if f.denylisted:
        return Decision(ALERT, "denylisted")
    if f.proposed == "Safe" and f.verdict in _QUIET | {"Suspicious"}:
        return Decision(ANALYST, "reporter-false-positive")
    if f.proposed == "Dangerous":
        if f.verdict == "Suspicious":
            return Decision(ALERT, "missed-threat-corroborated")
        if f.verdict in _QUIET:
            return Decision(ANALYST, "missed-threat-uncorroborated")
    return Decision(ALERT, "no-rule-matched")


def _config() -> dict:
    from settings.config import get_section
    return get_section("integrations.thehive")


def _mode() -> str:
    mode = str(_config().get("challenge_triage", "log")).lower()
    return mode if mode in ("off", "log", "enforce") else "log"


def gather_facts(case) -> Facts:
    from case_handler.models import CampaignMember

    member = CampaignMember.objects.filter(case=case).first()
    verdicts = ()
    if member:
        verdicts = tuple(member.campaign.members.values_list("case__results", flat=True))
    return Facts(
        verdict=case.results, proposed=case.challenge_proposed_result or "",
        reason=case.challenge_reason or "", campaign_verdicts=verdicts,
        denylisted=bool(case.is_denylisted),
    )


def triage(case):
    """Decide and record. Returns the ``ChallengeTriage`` row (``applied`` says whether the
    caller must skip the alert), or None when triage is off."""
    from case_handler.models import ChallengeTriage

    mode = _mode()
    if mode == "off":
        return None
    f = gather_facts(case)
    d = decide(f)
    return ChallengeTriage.objects.create(
        case=case, decision=d.decision, reason_code=d.reason_code, ruleset=d.ruleset, mode=mode,
        applied=mode == "enforce" and d.decision == ANALYST,
        facts={**asdict(f), "campaign_verdicts": list(f.campaign_verdicts)},
    )
