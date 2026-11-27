"""Replay the live scoring path on stored cases and keep nothing.

`replay_case` runs the real ``CortexAnalyzerReports.get_report`` (signals, AI vote, deny and allow
lists, embedded escalation, apply) inside a transaction that is always rolled back, so the result is
what finalisation would give today and the engine cannot drift away from this tool. Rollback undoes
the writes and discards every ``on_commit`` hook (events, Celery tasks, search indexing). Screenshot
capture (an object-store write that a rollback cannot undo) is switched off for the run; it does not
affect the verdict. Run it on a restored copy anyway: the run takes row locks, and a replica refuses
the writes.

``get_report`` logs and swallows its own exceptions, so a scoring error is read back from its logger
by its "get_report: error scoring" and "collect_votes failed" messages. Other error lines on that logger (for example "MailInfo not
found" for a case with no mail) are existing noise, not scoring failures.
"""
import logging
import math
from collections import Counter
from dataclasses import dataclass
from unittest.mock import patch

from django.db import transaction

from case_handler.models import Case, Result

SCORING_LOGGER = "tasp.cron.update_ongoing_case_jobs"  # the logger get_report writes to
# Messages get_report logs when it swallows a failure that changes the verdict.
FAILURE_PREFIXES = ("get_report: error scoring", "get_report: collect_votes failed")


@dataclass
class Row:
    case_id: int
    road: str
    stored: str
    replay: str | None
    analyst: str | None
    score: float | None
    error: str | None = None
    ai: bool | None = None  # mail road: the case carries an AI verdict (results_ai set); None elsewhere
    scored: int | None = None  # analyzer reports the replay could score; 0 = nothing to replay


class _Rollback(Exception):
    pass


class _ErrorCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.messages = []

    def emit(self, record):
        msg = record.getMessage()
        if msg.startswith(FAILURE_PREFIXES):
            self.messages.append(msg)


def wilson(k, n, z=1.96):
    """95% Wilson interval of k out of n; (None, None) with no samples."""
    if n == 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def road_of(case):
    if case.observable_group_id or case.nonFileIocs_id:
        return "ioc"
    mail = getattr(case.fileOrMail, "mail", None) if case.fileOrMail_id else None
    return "mail" if mail else "file"


def analyst_labels():
    """case id -> the latest active analyst verdict in the label ledger."""
    from ai_model.models import LabelRecord
    out = {}
    rows = (LabelRecord.objects.filter(source="analyst_verdict", status="active", case__isnull=False)
            .order_by("observed_at", "id").values_list("case_id", "label_class"))
    for case_id, label in rows:
        out[case_id] = label
    return out


def replay_case(case_id, analyst=None):
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    case = Case.objects.select_related("fileOrMail", "nonFileIocs").get(pk=case_id)
    row = Row(case_id, road_of(case), case.results, None, analyst, None)
    if row.road == "mail":
        # The live scorer reads the AI vote from the case's own AI fields, and treats
        # results_ai == Inconclusive as "AI missing" (collect_signals).
        row.ai = case.results_ai != Result.INCONCLUSIVE
    capture = _ErrorCapture()
    logger = logging.getLogger(SCORING_LOGGER)
    logger.addHandler(capture)
    try:
        with transaction.atomic(), patch(
            "score_process.scoring.screenshots.registry.capture", return_value=None
        ):
            CortexAnalyzerReports.get_report(case)
            row.replay, row.score, row.scored = case.results, case.final_score, case.analysis_done
            raise _Rollback
    except _Rollback:
        pass
    finally:
        logger.removeHandler(capture)
    if capture.messages:
        row.replay, row.score, row.scored, row.error = None, None, None, capture.messages[0][:300]
    return row


def _rate(rows, truth, wrong):
    base = [r for r in rows if r.analyst == truth]
    k = sum(1 for r in base if r.replay == wrong)
    lo, hi = wilson(k, len(base))
    return {"k": k, "n": len(base), "rate": (k / len(base)) if base else None, "lo": lo, "hi": hi}


def summarise(rows):
    # A mail case with results_ai == Inconclusive has no AI vote; the engine treats that as Inconclusive on
    # purpose (rule analysis-incomplete), so replaying it proves nothing about the scoring.
    no_ai = [r for r in rows if not r.error and r.ai is False]
    # Nothing scorable (no analyzer report reached the engine): cases whose reports were purged by
    # retention (`delete_old_reports`) and synthetic test cases whose verdict never came from reports. The replay can only say Failure; that is not drift.
    nothing = [r for r in rows if not r.error and r.ai is not False and r.scored == 0]
    ok = [r for r in rows if not r.error and r.ai is not False and r.scored != 0]
    plain = [r for r in ok if not r.analyst]
    edited = [r for r in ok if r.analyst]
    return {
        "errors": sum(1 for r in rows if r.error),
        "no_ai": len(no_ai),
        "nothing": len(nothing),
        "drift": {
            "n": len(plain),
            "changed": sum(1 for r in plain if r.stored != r.replay),
            "matrix": Counter((r.stored, r.replay) for r in plain),
        },
        "accuracy": {
            "n": len(edited),
            "agree": sum(1 for r in edited if r.analyst == r.replay),
            "matrix": Counter((r.analyst, r.replay) for r in edited),
            "missed_threat": _rate(edited, Result.DANGEROUS, Result.SAFE),
            "false_alarm": _rate(edited, Result.SAFE, Result.DANGEROUS),
        },
    }
