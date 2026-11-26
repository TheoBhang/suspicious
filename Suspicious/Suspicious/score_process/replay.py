"""Replay the live scoring path on stored cases and keep nothing.

`replay_case` runs the real ``CortexAnalyzerReports.get_report`` (signals, AI vote, deny and allow
lists, embedded escalation, apply) inside a transaction that is always rolled back, so the result is
what finalisation would give today and the engine cannot drift away from this tool. Rollback undoes
the writes and discards every ``on_commit`` hook (events, Celery tasks, search indexing). Run it on a
restored copy anyway: the run takes row locks, and a replica refuses the writes.

``get_report`` logs and swallows its own exceptions, so a scoring error is read back from its logger
by the "get_report: error scoring" message. Other error lines on that logger (for example "MailInfo not
found" for a case with no mail) are existing noise, not scoring failures.
"""
import logging
import math
from collections import Counter
from dataclasses import dataclass

from django.db import transaction

from case_handler.models import Case, Result

SCORING_LOGGER = "tasp.cron.update_ongoing_case_jobs"  # the logger get_report writes to


@dataclass
class Row:
    case_id: int
    road: str
    stored: str
    replay: str | None
    analyst: str | None
    score: float | None
    error: str | None = None


class _Rollback(Exception):
    pass


class _ErrorCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.messages = []

    def emit(self, record):
        msg = record.getMessage()
        if msg.startswith("get_report: error scoring"):
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
            .order_by("observed_at").values_list("case_id", "label"))
    for case_id, label in rows:
        out[case_id] = label
    return out


def replay_case(case_id, analyst=None):
    from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

    case = Case.objects.select_related("fileOrMail", "nonFileIocs").get(pk=case_id)
    row = Row(case_id, road_of(case), case.results, None, analyst, None)
    capture = _ErrorCapture()
    logger = logging.getLogger(SCORING_LOGGER)
    logger.addHandler(capture)
    try:
        with transaction.atomic():
            CortexAnalyzerReports.get_report(case)
            row.replay, row.score = case.results, case.final_score
            raise _Rollback
    except _Rollback:
        pass
    finally:
        logger.removeHandler(capture)
    if capture.messages:
        row.replay, row.score, row.error = None, None, capture.messages[0][:300]
    return row


def _rate(rows, truth, wrong):
    base = [r for r in rows if r.analyst == truth]
    k = sum(1 for r in base if r.replay == wrong)
    lo, hi = wilson(k, len(base))
    return {"k": k, "n": len(base), "rate": (k / len(base)) if base else None, "lo": lo, "hi": hi}


def summarise(rows):
    ok = [r for r in rows if not r.error]
    plain = [r for r in ok if not r.analyst]
    edited = [r for r in ok if r.analyst]
    return {
        "errors": len(rows) - len(ok),
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
