"""connectors.engines: the analyzer selection policy and dispatch (rows written as run_analyzer)."""
from types import SimpleNamespace
from unittest import mock

import pybreaker
from django.contrib.auth import get_user_model
from django.forms.models import model_to_dict
from django.test import SimpleTestCase, TestCase

from case_handler.models import Case
from common.http_client import BREAKERS
from connectors import engines
from connectors.base import (
    PROVIDER_KIND_ANALYSIS,
    CatalogEntry,
    Connector,
    ConnectorManifest,
    HealthStatus,
    StartResult,
)
from connectors.contrib.cortex.connector import CortexConnector
from connectors.models import ConnectorDelivery, ConnectorState
from connectors.registry import ConnectorRegistry
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
from cortex_job.models import Analyzer, AnalyzerReport, CaseAnalyzerJob
from mail_feeder.models import MailHeader
from url_process.models import URL

ROLES = {"yara": "Yara", "file_info": "FileInfo", "sandbox": "Sandbox", "header": "Header", "ai": "AI"}
NO_AI = {"header": "Header", "yara": "Yara", "sandbox": None, "file_info": "FileInfo"}


def e(name, *types):
    return CatalogEntry(id=f"id-{name}", name=name, data_types=types or ("url",))


def names(entries):
    return [x.name for x in entries]


def a_file(name):
    return SimpleNamespace(file_path=SimpleNamespace(name=name))


class SelectAnalyzersTest(SimpleTestCase):
    ALL = [e(n) for n in ("Yara", "FileInfo", "Sandbox", "Header", "AI", "VT")]

    def select(self, data_type, value=None, roles=ROLES):
        return names(engines.select_analyzers(data_type, value, self.ALL, roles))

    def test_mail_body_is_only_yara(self):
        self.assertEqual(self.select("mail_body", "/tmp/x.txt"), ["Yara"])

    def test_mail_header_is_only_header(self):
        self.assertEqual(self.select("mail_header"), ["Header"])

    def test_mail_header_without_header_role_is_empty(self):
        roles = {k: v for k, v in ROLES.items() if k != "header"}
        self.assertEqual(self.select("mail_header", roles=roles), [])

    def test_file_is_yara_file_info_sandbox(self):
        self.assertEqual(self.select("file", a_file("x.pdf")), ["Yara", "FileInfo", "Sandbox"])

    def test_eml_file_drops_ai_yara_sandbox_header(self):
        self.assertEqual(self.select("file", a_file("mail.eml")), ["FileInfo"])

    def test_eml_file_with_absent_ai_and_none_sandbox(self):
        # An absent role must never put None or {} into a set (an earlier bug).
        self.assertEqual(self.select("file", a_file("mail.eml"), NO_AI), ["FileInfo"])

    def test_file_without_file_path_raises(self):
        with self.assertRaises(TypeError):
            engines.select_analyzers("file", SimpleNamespace(), self.ALL, ROLES)

    def test_other_types_drop_yara_sandbox_header(self):
        for data_type in ("url", "ip", "domain", "hash", "mail"):
            self.assertEqual(self.select(data_type), ["FileInfo", "AI", "VT"], data_type)

    def test_absent_roles(self):
        self.assertEqual(self.select("url", roles={}), names(self.ALL))
        self.assertEqual(self.select("file", a_file("x.pdf"), roles={}), [])
        self.assertEqual(self.select("mail_body", "/tmp/x", roles={}), [])
        self.assertEqual(self.select("url", roles={"yara": None, "sandbox": ""}), names(self.ALL))


class LedgerIdsTest(SimpleTestCase):
    def test_cortex_is_raw(self):
        self.assertEqual(engines.ledger_ids("cortex", "job1", "an1"), ("job1", "an1"))

    def test_other_is_namespaced(self):
        job, analyzer = engines.ledger_ids("fake", "job1", "an1")
        self.assertEqual((job, analyzer), ("fake-job1", "fake:an1"))
        self.assertLessEqual(max(len(job), len(analyzer)), 50)

    def test_too_long_raises(self):
        with self.assertRaises(ValueError):
            engines.ledger_ids("fake", "j" * 50, "a")


def make_engine(engine_name):
    class Fake(Connector):
        manifest = ConnectorManifest(name=engine_name, version="0.0.1", provides=PROVIDER_KIND_ANALYSIS)
        offered: list = []
        started: list = []
        refuse: set = set()
        raise_on: set = set()
        catalog_error = None

        def health_check(self):
            return HealthStatus(ok=True)

        def catalog(self, data_type=None, name=None):
            if type(self).catalog_error:
                raise type(self).catalog_error
            return [x for x in type(self).offered
                    if (name and x.name == name) or (data_type and data_type in x.data_types)]

        def start(self, analyzer, data_type, value):
            if analyzer.name in type(self).raise_on:
                raise ConnectionError("http://user:pw@engine.example/api")
            if analyzer.name in type(self).refuse:
                return None
            type(self).started.append((analyzer.name, data_type, value))
            return StartResult(job_id=f"job-{analyzer.name}")

    return Fake


CONFIGS = {
    "integrations.cortex": {"url": "http://cortex:9001", "api_key": "k", "analyzers": ROLES},
}


class DispatchTest(TestCase):
    def setUp(self):
        patcher = mock.patch.dict(BREAKERS)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.fake_a, self.fake_b = make_engine("fake_a"), make_engine("fake_b")
        self.registry = ConnectorRegistry()
        for cls in (self.fake_a, self.fake_b, CortexConnector):
            self.registry.register(cls)
        for target in ("connectors.engines.registry", "connectors.delivery.registry",
                       "connectors.dispatch.registry"):
            patcher = mock.patch(target, self.registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("settings.config.get_section", side_effect=lambda n: CONFIGS.get(n, {}))
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, on in (("fake_a", True), ("fake_b", True), ("cortex", False)):
            ConnectorState.objects.create(name=name, enabled=on)
        user = get_user_model().objects.create_user(username="engines", password="x")
        self.case = Case.objects.create(status="On Going", description="", reporter=user)
        self.case2 = Case.objects.create(status="On Going", description="", reporter=user)
        self.url = URL.objects.create(address="http://phish.example/login")

    def only(self, *enabled):
        ConnectorState.objects.update(enabled=False)
        ConnectorState.objects.filter(name__in=enabled).update(enabled=True)

    def test_enabled_engines_sorted(self):
        self.assertEqual(engines.enabled_engines(), ["fake_a", "fake_b"])

    def test_row_parity_with_run_analyzer_through_cortex(self):
        self.only("cortex")
        vt = SimpleNamespace(id="vt1", name="VT", dataTypeList=["url"])
        with mock.patch("cortex_job.cortex_utils.session_cortex_api.SessionCortexApi") as api_cls:
            api = api_cls.return_value
            api.analyzers.get_by_type.return_value = [vt]
            api.analyzers.run_by_name.side_effect = [SimpleNamespace(id="j1"), SimpleNamespace(id="j2")]
            CortexJob.run_analyzer(api, vt, self.url, "url", self.case)
            ids = engines.dispatch(self.url, "url", self.case2)
        self.assertEqual(ids, ["j2"])
        first, second = api.analyzers.run_by_name.call_args_list
        self.assertEqual(first, second)
        self.assertEqual(second.args[1], {"data": self.url.address, "dataType": "url", "tlp": 2})
        skip = ("id", "cortex_job_id")
        old, new = (model_to_dict(AnalyzerReport.objects.get(cortex_job_id=j), exclude=skip)
                    for j in ("j1", "j2"))
        self.assertEqual(old, new)
        self.assertEqual(
            (new["status"], new["level"], new["confidence"], new["score"], new["report_summary"],
             new["report_full"], new["report_taxonomy"], new["url"], new["type"]),
            ("InProgress", "info", 0, 0, {"ongoing": "analysis"}, {"ongoing": "analysis"},
             {"ongoing": "analysis"}, self.url.id, "url"),
        )
        caj = CaseAnalyzerJob.objects.get(case=self.case2)
        self.assertEqual((caj.cortex_job_id, caj.status), ("j2", CaseAnalyzerJob.STATUS_INPROGRESS))
        self.assertEqual(caj.analyzer_report.cortex_job_id, "j2")
        self.assertEqual(Analyzer.objects.get().analyzer_cortex_id, "vt1")

    def test_fake_engine_rows_are_namespaced(self):
        self.only("fake_a")
        self.fake_a.offered = [e("VT")]
        ids = engines.dispatch(self.url, "url", self.case)
        self.assertEqual(ids, ["fake_a-job-VT"])
        self.assertEqual(self.fake_a.started, [("VT", "url", self.url.address)])
        analyzer = Analyzer.objects.get(name="VT")
        self.assertEqual((analyzer.analyzer_cortex_id, analyzer.source), ("fake_a:id-VT", "fake_a"))
        ar = AnalyzerReport.objects.get()
        self.assertEqual((ar.cortex_job_id, ar.status, ar.url_id), ("fake_a-job-VT", "InProgress", self.url.id))
        caj = CaseAnalyzerJob.objects.get()
        self.assertEqual((caj.cortex_job_id, caj.analyzer_report_id, caj.status),
                         ("fake_a-job-VT", ar.id, CaseAnalyzerJob.STATUS_INPROGRESS))

    def test_finished_start_is_written_as_pending(self):
        self.only("fake_a")
        self.fake_a.offered = [e("VT")]
        from connectors.base import FetchResult
        with mock.patch.object(self.fake_a, "start",
                               return_value=StartResult("j9", finished=FetchResult("result", "Success"))):
            engines.dispatch(self.url, "url", self.case)
        self.assertEqual(CaseAnalyzerJob.objects.get().status, CaseAnalyzerJob.STATUS_INPROGRESS)

    def test_two_engines_one_raising(self):
        self.fake_a.offered, self.fake_b.offered = [e("VT_A")], [e("VT_B")]
        self.assertEqual(len(engines.dispatch(self.url, "url", self.case)), 2)
        self.assertEqual(CaseAnalyzerJob.objects.filter(case=self.case).count(), 2)
        self.fake_a.catalog_error = RuntimeError("down")
        self.assertEqual(engines.dispatch(self.url, "url", self.case2), ["fake_b-job-VT_B"])

    def test_refused_and_raising_starts_do_not_stop_the_others(self):
        self.only("fake_a")
        self.fake_a.offered = [e("Refused"), e("Boom"), e("Ok")]
        self.fake_a.refuse, self.fake_a.raise_on = {"Refused"}, {"Boom"}
        self.assertEqual(engines.dispatch(self.url, "url", self.case), ["fake_a-job-Ok"])
        self.assertEqual(list(AnalyzerReport.objects.values_list("analyzer__name", flat=True)), ["Ok"])
        failed = ConnectorDelivery.objects.filter(connector="fake_a", event="start", status="failed")
        self.assertEqual(sorted(failed.values_list("error", flat=True)),
                         ["Boom: ConnectionError", "Refused: refused"])
        self.assertEqual(set(failed.values_list("case_id", flat=True)), {self.case.id})

    def test_disabled_engine_starts_nothing(self):
        self.only("fake_b")
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])

    def test_no_engine_enabled_writes_nothing(self):
        self.only()
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertFalse(AnalyzerReport.objects.exists())
        self.assertFalse(CaseAnalyzerJob.objects.exists())
        self.assertFalse(ConnectorDelivery.objects.exists())

    def test_name_owned_by_another_source_is_skipped(self):
        self.only("fake_a")
        Analyzer.objects.create(name="VT", analyzer_cortex_id="vt1", source="cortex")
        self.fake_a.offered = [e("VT")]
        with self.assertLogs("connectors.engines", "ERROR"):
            self.assertEqual(engines.dispatch(self.url, "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])
        self.assertFalse(AnalyzerReport.objects.exists())

    def test_case_required(self):
        with self.assertRaises(TypeError):
            engines.dispatch(self.url, "url", None)

    def test_empty_value_starts_nothing(self):
        self.only("fake_a")
        self.fake_a.offered = [e("VT")]
        self.assertEqual(engines.dispatch(URL.objects.create(address="  "), "url", self.case), [])
        self.assertEqual(self.fake_a.started, [])

    def test_role_types_look_roles_up_by_name(self):
        self.only("fake_a")
        self.fake_a.offered = [e("Header", "other"), e("Yara", "other")]
        header = MailHeader.objects.create(header_value="From: a@b", fuzzy_hash="fh")
        self.assertEqual(engines.dispatch(header, "mail_header", self.case), ["fake_a-job-Header"])
        self.assertEqual(AnalyzerReport.objects.get().mail_header, header)

    def test_launch_cortex_jobs_forwards(self):
        with mock.patch("connectors.engines.dispatch", return_value=["x"]) as dispatch, \
                mock.patch("cortex_job.cortex_utils.cortex_and_job_management.SessionCortexApi") as api:
            self.assertEqual(CortexJob().launch_cortex_jobs(self.url, "url", self.case), ["x"])
        dispatch.assert_called_once_with(self.url, "url", self.case)
        api.assert_not_called()
