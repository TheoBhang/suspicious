"""A dev-only engine (the fixture engine) keeps its Analyzer rows active only while it is enabled and
confirmed: the Settings weight guard counts active rows, and a stack where the fixture was once
confirmed must not keep weighting them."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase

from connectors.contrib.fixture.connector import FixtureEngineConnector
from connectors.models import ConnectorState
from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector
from cortex_job.models import Analyzer


class DevEngineRowsTest(APITestCase):
    def setUp(self):
        registry = ConnectorRegistry()
        for cls in (FixtureEngineConnector, DummyConnector):
            registry.register(cls)
        for target in ("api.views.connectors.registry", "connectors.delivery.registry"):
            patcher = mock.patch(target, registry)
            patcher.start()
            self.addCleanup(patcher.stop)
        user = get_user_model().objects.create_user(username="admin", password="x")
        user.groups.add(Group.objects.get_or_create(name="Admin")[0])
        self.client.force_authenticate(user)
        ConnectorState.objects.update_or_create(name="fixture_engine", defaults={"enabled": True})
        Analyzer.objects.create(name="Fixture_Reputation_1_0", analyzer_cortex_id="fixture_engine:r",
                                source="fixture_engine")
        Analyzer.objects.create(name="Cortex_One", analyzer_cortex_id="c1", source="cortex")
        Analyzer.objects.create(name="Dummy_One", analyzer_cortex_id="d1", source="dummy")

    def active(self, name):
        return Analyzer.objects.get(name=name).is_active

    def test_disabling_the_engine_deactivates_its_rows_only(self):
        response = self.client.patch("/api/connectors/fixture_engine/", {"enabled": False, "force": True},
                                     format="json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.active("Fixture_Reputation_1_0"))
        self.assertTrue(self.active("Cortex_One"))
        self.assertTrue(self.active("Dummy_One"))

    def test_unconfirming_the_engine_deactivates_its_rows(self):
        response = self.client.put("/api/connectors/fixture_engine/config/", {"confirm_fixture": False},
                                   format="json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.active("Fixture_Reputation_1_0"))
        self.assertTrue(self.active("Cortex_One"))

    def test_confirming_an_enabled_engine_leaves_its_rows_alone(self):
        response = self.client.put("/api/connectors/fixture_engine/config/", {"confirm_fixture": True},
                                   format="json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.active("Fixture_Reputation_1_0"))

    def test_an_ordinary_connector_never_touches_analyzer_rows(self):
        self.client.patch("/api/connectors/dummy/", {"enabled": False}, format="json")
        self.client.put("/api/connectors/dummy/config/", {"url": "http://x.example/"}, format="json")
        self.assertTrue(self.active("Dummy_One"))
        self.assertTrue(self.active("Fixture_Reputation_1_0"))
