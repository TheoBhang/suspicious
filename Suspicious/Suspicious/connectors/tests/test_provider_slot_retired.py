"""The mail_ai provider slot is retired: its names are gone (the one-release forwarder
`run_provider_analysis` too), and the engine layer stays AI-free."""
import inspect

from django.test import SimpleTestCase

from connectors import base, engines, providers, tasks
from connectors.base import ConnectorManifest
from connectors.contrib.ai_model.connector import AiModelConnector
from connectors.providers import ProviderUnavailable
from connectors.registry import ConnectorRegistry
from connectors.tests.dummy import DummyConnector

REMOVED = {
    base: ("PROVIDER_KIND_MAIL_AI", "ProviderResult"),
    providers: ("queue_provider_analysis", "queue_mail_ai", "finish_provider_analysis",
                "enabled_provider", "provider_connector", "PROVIDER_JOB_PREFIX"),
    tasks: ("run_provider_analysis",),
}
AI_WORDS = ("ai_model", "AiAssessment", "results_ai")


class RemovedNamesTest(SimpleTestCase):
    def test_the_provider_slot_names_are_gone(self):
        for module, names in REMOVED.items():
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertFalse(hasattr(module, name))
        self.assertFalse(hasattr(base.Connector, "analyze"))

    def test_provider_unavailable_is_still_importable(self):
        self.assertTrue(issubclass(ProviderUnavailable, Exception))
        self.assertFalse(ProviderUnavailable("x", retryable=False).retryable)

    def test_mail_ai_is_no_longer_a_valid_provides(self):
        self.assertEqual(base.VALID_PROVIDER_KINDS, frozenset({base.PROVIDER_KIND_ANALYSIS}))
        with self.assertRaises(ValueError):
            ConnectorManifest(name="x1", version="1", provides="mail_ai").validate()
        ConnectorManifest(name="x1", version="1", provides="analysis").validate()
        ConnectorManifest(name="x1", version="1").validate()

    def test_registry_providers_lists_only_the_matching_kind(self):
        registry = ConnectorRegistry()
        for cls in (DummyConnector, AiModelConnector):
            registry.register(cls)
        self.assertEqual(registry.providers("analysis"), ["ai_model"])
        self.assertEqual(registry.providers("mail_ai"), [])


class EngineLayerIsAiFreeTest(SimpleTestCase):
    """Scoped to the engine code paths: the same files hold older, legitimate mentions (the
    campaign tasks in connectors/tasks.py)."""

    def test_no_engine_code_path_names_the_ai(self):
        functions = [tasks.run_engine_job.run, tasks._run_deferred_job, tasks._close_engine_job]
        functions += [getattr(engines, name) for name in (
            "dispatch", "_dispatch", "_dispatch_engine", "_analyzer_row", "_start", "_start_deferred",
            "store_result", "apply_result", "update_report", "refresh", "close_row", "handle_webhook",
        )]
        for function in functions + [base.Connector]:
            source = inspect.getsource(function)
            for word in AI_WORDS:
                with self.subTest(function=function.__name__, word=word):
                    self.assertNotIn(word, source)
