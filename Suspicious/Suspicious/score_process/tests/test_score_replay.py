"""score_replay: replay the live scoring path on stored cases without keeping a write."""
import csv
import io
import os
import tempfile
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from ai_model.models import LabelRecord
from case_handler.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs, Result
from cortex_job.models import Analyzer, AnalyzerReport
from file_process.models import File
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail, MailArchive
from score_process import replay


def make_ioc_case(n, stored=Result.SAFE, level="malicious", analyst=None):
    user = get_user_model().objects.get_or_create(username="replay_u")[0]
    ip = IP.objects.create(address=f"203.0.113.{n}")
    analyzer = Analyzer.objects.get_or_create(
        name="ReplayAbuse", defaults={"analyzer_cortex_id": "ReplayAbuse", "weight": 1})[0]
    AnalyzerReport.objects.create(
        cortex_job_id=f"rp{n}", type="ip", status="Success", analyzer=analyzer, ip=ip,
        level=level, confidence=9, score=9 if level == "malicious" else 1,
        report_summary={"taxonomies": [{"level": level, "value": "x"}]},
        report_taxonomy={}, report_full={})
    case = Case.objects.create(description="", reporter=user, results=stored)
    case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
    case.save()
    if analyst:
        LabelRecord.objects.create(
            case=case, source="analyst_verdict", source_ref=f"t{n}", label=analyst,
            label_class=analyst, trust=1.0, observed_at=timezone.now(), status="active",
            message_id=f"<{n}@x>", message_id_hash=f"{n:064d}")
    return case


def snapshot():
    """Every row of every table, so a replay that kept any write shows up."""
    from django.apps import apps
    return {m._meta.label: sorted(map(str, m.objects.values())) for m in apps.get_models()}


class Wilson(TestCase):
    def test_interval_brackets_the_rate_and_widens_with_few_samples(self):
        lo, hi = replay.wilson(1, 10)
        self.assertLess(lo, 0.1)
        self.assertGreater(hi, 0.1)
        lo2, hi2 = replay.wilson(100, 1000)
        self.assertLess(hi2 - lo2, hi - lo)

    def test_no_samples_gives_no_interval(self):
        self.assertEqual(replay.wilson(0, 0), (None, None))


class ReplayCase(TestCase):
    def test_replay_gives_the_live_verdict_and_keeps_nothing(self):
        case = make_ioc_case(1, stored=Result.SAFE)
        before = snapshot()
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            out = replay.replay_case(case.pk)
        self.assertIsNone(out.error)
        self.assertEqual(out.replay, Result.DANGEROUS)
        self.assertEqual(out.stored, Result.SAFE)
        self.assertEqual(snapshot(), before)   # no row of any table changed (KPIs included)
        self.assertEqual(callbacks, [])

    def test_a_scoring_error_is_reported_not_hidden(self):
        case = make_ioc_case(2, stored=Result.SAFE)
        with patch("score_process.scoring.apply.apply_verdict", side_effect=RuntimeError("boom")):
            out = replay.replay_case(case.pk)
        self.assertIsNotNone(out.error)
        self.assertIn("boom", out.error)
        self.assertIsNone(out.replay)

    def test_the_road_is_named(self):
        row = replay.replay_case(make_ioc_case(3).pk)
        self.assertEqual(row.road, "ioc")
        self.assertIsNone(row.ai)   # the AI vote only exists on the mail road

    def test_a_case_with_nothing_to_score_has_zero_scored(self):
        user = get_user_model().objects.get_or_create(username="replay_u")[0]
        ip = IP.objects.create(address="203.0.113.99")   # no analyzer report at all
        case = Case.objects.create(description="", reporter=user, results=Result.DANGEROUS)
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.save()
        row = replay.replay_case(case.pk)
        self.assertEqual(row.scored, 0)
        self.assertEqual(replay.replay_case(make_ioc_case(8).pk).scored, 1)

    def test_the_ai_flag_follows_the_cases_own_ai_fields(self):
        case = make_ioc_case(7)
        mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="rp-m7")
        archive = File.objects.create(linked_hash=Hash.objects.create(value="rp-h7"), tmp_path="rp7.tar.gz")
        MailArchive.objects.create(mail=mail, archive=archive)
        mail_only = Case.objects.create(description="", reporter=case.reporter, results=Result.SAFE,
                                        results_ai=Result.INCONCLUSIVE)
        mail_only.fileOrMail = CaseHasFileOrMail.objects.create(case=mail_only, mail=mail)
        mail_only.save()
        row = replay.replay_case(mail_only.pk)
        self.assertEqual(row.road, "mail")
        self.assertFalse(row.ai)
        Case.objects.filter(pk=mail_only.pk).update(results_ai="Unwanted", score_ai=5, confidence_ai=58)
        self.assertTrue(replay.replay_case(mail_only.pk).ai)

    def test_screenshot_capture_is_switched_off_during_a_replay(self):
        from score_process.scoring.screenshots import registry
        seen = []
        with patch("score_process.scoring.cortex_analyzers.reports.CortexAnalyzerReports.get_report",
                   side_effect=lambda case: seen.append(registry.capture(None))):
            replay.replay_case(make_ioc_case(9).pk)
        self.assertEqual(seen, [None])
        self.assertEqual(registry.capture.__module__, registry.__name__)   # the real function is back

    def test_a_swallowed_vote_failure_is_an_error(self):
        import logging

        def noisy(case):
            logging.getLogger(replay.SCORING_LOGGER).exception(
                "get_report: collect_votes failed for case %s", case.id)

        with patch("score_process.scoring.cortex_analyzers.reports.CortexAnalyzerReports.get_report",
                   side_effect=noisy):
            row = replay.replay_case(make_ioc_case(10).pk)
        self.assertIsNotNone(row.error)
        self.assertIsNone(row.replay)


class Summary(TestCase):
    def row(self, stored, new, analyst=None, road="mail", error=None):
        return replay.Row(case_id=1, road=road, stored=stored, replay=new, analyst=analyst,
                          score=None, error=error)

    def test_drift_ignores_analyst_edited_cases_and_accuracy_uses_only_them(self):
        rows = [
            self.row("Safe", "Safe"),
            self.row("Safe", "Dangerous"),
            self.row("Dangerous", "Safe", analyst="Dangerous"),   # a missed threat
            self.row("Dangerous", "Dangerous", analyst="Dangerous"),
            self.row("Safe", "Dangerous", analyst="Safe"),        # a false alarm
        ]
        s = replay.summarise(rows)
        self.assertEqual(s["drift"]["n"], 2)
        self.assertEqual(s["drift"]["changed"], 1)
        self.assertEqual(s["accuracy"]["n"], 3)
        self.assertEqual(s["accuracy"]["missed_threat"]["k"], 1)
        self.assertEqual(s["accuracy"]["missed_threat"]["n"], 2)
        self.assertEqual(s["accuracy"]["false_alarm"]["k"], 1)
        self.assertEqual(s["accuracy"]["false_alarm"]["n"], 1)

    def test_mail_cases_without_an_ai_vote_are_left_out_of_both_views_and_counted(self):
        no_ai = self.row("Safe", "Inconclusive", analyst="Safe")
        no_ai.ai = False
        also = self.row("Safe", "Inconclusive")
        also.ai = False
        s = replay.summarise([no_ai, also, self.row("Safe", "Safe", analyst="Safe")])
        self.assertEqual(s["no_ai"], 2)
        self.assertEqual(s["accuracy"]["n"], 1)
        self.assertEqual(s["drift"]["n"], 0)

    def test_cases_with_nothing_scorable_are_counted_and_left_out(self):
        empty = self.row("Dangerous", "Failure")
        empty.scored = 0
        real = self.row("Safe", "Safe")
        real.scored = 3
        s = replay.summarise([empty, real])
        self.assertEqual(s["nothing"], 1)
        self.assertEqual(s["drift"]["n"], 1)
        self.assertEqual(s["drift"]["changed"], 0)

    def test_errors_are_counted_apart_from_both_views(self):
        s = replay.summarise([self.row("Safe", None, error="x"), self.row("Safe", "Safe")])
        self.assertEqual(s["errors"], 1)
        self.assertEqual(s["drift"]["n"], 1)


class Command(TestCase):
    def test_the_road_filter_comes_before_the_limit(self):
        make_ioc_case(11)
        out = io.StringIO()
        call_command("score_replay", "--road", "mail", "--limit", "5", stdout=out)
        self.assertIn("0 cases", out.getvalue())

    def test_command_prints_both_views_and_writes_the_disagreements(self):
        make_ioc_case(4, stored=Result.SAFE)                        # drift: Safe -> Dangerous
        make_ioc_case(5, stored=Result.SAFE, analyst=Result.DANGEROUS)  # replay agrees with analyst
        make_ioc_case(6, stored=Result.DANGEROUS, level="benign", analyst=Result.DANGEROUS)  # missed threat
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.csv")
            call_command("score_replay", "--csv", path, stdout=out)
            rows = list(csv.DictReader(open(path)))
        text = out.getvalue()
        self.assertIn("Drift", text)
        self.assertIn("Accuracy", text)
        self.assertIn("Missed threats", text)
        self.assertEqual(sorted(r["kind"] for r in rows), ["accuracy", "drift"])
        self.assertEqual(Case.objects.filter(results=Result.SAFE).count(), 2)  # nothing was kept
