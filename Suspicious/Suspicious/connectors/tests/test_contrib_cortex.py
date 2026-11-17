from unittest import mock

from django.test import SimpleTestCase, TestCase

from connectors.contrib.cortex.connector import CortexConnector
from connectors.delivery import get_state
from connectors.registry import registry

CONFIGURED = {"url": "http://cortex:9001", "api_key": "k"}


class CortexManifestTest(SimpleTestCase):
    def test_manifest(self):
        m = CortexConnector.manifest
        m.validate()
        self.assertEqual(m.name, "cortex")
        self.assertEqual(m.provides, "analysis")
        self.assertEqual(m.category, "Analysis")
        self.assertTrue(m.enabled_by_default)
        [schedule] = m.schedules
        self.assertEqual((schedule.name, schedule.interval_seconds), ("sync", 60))
        fields = {f.key: f for f in m.config_schema}
        self.assertEqual(set(fields), {
            "url", "api_key", "webhook_secret", "stale_job_timeout_seconds",
            "analyzers.yara", "analyzers.sandbox", "analyzers.header",
            "analyzers.file_info", "analyzers.ai",
        })
        self.assertEqual(fields["api_key"].type, "secret")
        self.assertEqual(fields["webhook_secret"].type, "secret")
        self.assertEqual(fields["stale_job_timeout_seconds"].default, 7200)
        self.assertTrue(fields["url"].required and fields["api_key"].required)

    def test_health_ok_on_status_200(self):
        with mock.patch("requests.get", return_value=mock.Mock(status_code=200)) as get:
            status = CortexConnector(CONFIGURED).health_check()
        self.assertTrue(status.ok)
        self.assertEqual(get.call_args.args[0], "http://cortex:9001/api/status")
        self.assertEqual(get.call_args.kwargs["timeout"], 2)

    def test_health_not_ok_on_connection_error(self):
        with mock.patch("requests.get", side_effect=OSError("down")):
            self.assertFalse(CortexConnector(CONFIGURED).health_check().ok)

    def test_health_unconfigured_returns_not_ok_without_raising(self):
        for cfg in ({}, {"url": "https://cortex.example.com", "api_key": "k"},
                    {"url": "http://cortex:9001", "api_key": ""}):
            with mock.patch("requests.get") as get:
                status = CortexConnector(cfg).health_check()
            self.assertFalse(status.ok)
            get.assert_not_called()
        self.assertIn("api_key", CortexConnector({"url": "http://c"}).health_check().detail)

    def test_sync_calls_sync_cortex_analyzers(self):
        with mock.patch("tasp.cron.sync_cortex.sync_cortex_analyzers") as run:
            CortexConnector(CONFIGURED).sync()
        run.assert_called_once_with()

    def test_sync_when_unconfigured_does_nothing(self):
        with mock.patch("tasp.cron.sync_cortex.sync_cortex_analyzers") as run:
            CortexConnector({}).sync()
        run.assert_not_called()


class CortexRegistrationTest(TestCase):
    def test_registered_and_enabled_on_a_fresh_database(self):
        registry.discover()
        self.assertIn("cortex", registry.names())
        self.assertTrue(get_state("cortex").enabled)

    def test_beat_has_one_cortex_sync_entry(self):
        from django.conf import settings
        from suspicious.celery import app
        from connectors.apps import ConnectorsConfig

        self.assertNotIn("sync-cortex", settings.CELERY_BEAT_SCHEDULE)
        registry.discover()
        ConnectorsConfig._register_beat_schedules()
        entry = app.conf.beat_schedule["connector-cortex-sync"]
        self.assertEqual(entry["args"], ["cortex"])
        self.assertEqual(entry["schedule"], 60.0)
        self.assertNotIn("sync-cortex", app.conf.beat_schedule)

    def test_sync_cortex_task_runs_the_connector_sync(self):
        from tasp.tasks import sync_cortex
        with mock.patch("connectors.delivery.run_sync_now") as run:
            sync_cortex.apply()
        run.assert_called_once_with("cortex")


# integrations.cortex exactly as in docs/getting-started/examples/Suspicious-settings.example.json,
# with a key filled in: an existing deployment's section must work with no edit.
EXISTING_SECTION = {
    "url": "http://cortex:9001",
    "api_key": "k",
    "analyzers": {
        "header": "Mail_Header_Analyzer_1_0",
        "ai": "AI_Mail_Analyzer",
        "sandbox": "ThreatGridOnPrem_1_0",
        "yara": "Yara_Boosted_3_2",
        "file_info": "FileInfo_8_0",
    },
    "webhook_secret": "",
}


class UpgradeTests(TestCase):
    def setUp(self):
        registry.discover()
        for target in ("settings.config.get_section", "api.views.connectors.get_section"):
            patcher = mock.patch(
                target, side_effect=lambda n: EXISTING_SECTION if n == "integrations.cortex" else {},
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_existing_section_reaches_the_connector(self):
        config = registry.instantiate("cortex").config
        self.assertEqual(config["url"], "http://cortex:9001")
        self.assertEqual(config["api_key"], "k")
        self.assertEqual(
            set(config["analyzers"]), {"header", "ai", "sandbox", "yara", "file_info"},
        )

    def test_reads_as_connected_with_no_state_row(self):
        from api.views.connectors import _serialize_connector
        self.assertEqual(_serialize_connector("cortex")["status"], "connected")

    def test_listed_and_enabled_over_the_api(self):
        from django.contrib.auth import get_user_model
        from django.contrib.auth.models import Group
        from rest_framework.test import APIClient

        user = get_user_model().objects.create_user(username="admin", password="x")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        client = APIClient()
        client.force_authenticate(user)
        items = client.get("/api/connectors/").json()["connectors"]
        [cortex] = [c for c in items if c["name"] == "cortex"]
        self.assertTrue(cortex["enabled"])
