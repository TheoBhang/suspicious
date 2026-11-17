"""Cortex connector: config, health and the analyzer catalogue sync.

Step 1 of the analysis-engine work: ``enabled`` gates only the sync and the
connector UI. Job starts, the webhook and reconcile still talk to Cortex
directly whatever the flag says.
"""
from __future__ import annotations

from connectors.base import (
    PROVIDER_KIND_ANALYSIS,
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
)

_PLACEHOLDER_URL = "https://cortex.example.com"


class CortexConnector(Connector):
    manifest = ConnectorManifest(
        name="cortex",
        version="1.0.0",
        author="Thales CERT",
        category="Analysis",
        description=(
            "Syncs the Cortex analyzer catalogue every minute. Job starts still go to "
            "Cortex whatever the enabled flag says; gating them comes with the engine layer."
        ),
        provides=PROVIDER_KIND_ANALYSIS,
        enabled_by_default=True,
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret", required=True),
            ConfigField("webhook_secret", "secret"),
            ConfigField("stale_job_timeout_seconds", "int", default=7200),
            ConfigField("analyzers.yara", "str"),
            ConfigField("analyzers.sandbox", "str"),
            ConfigField("analyzers.header", "str"),
            ConfigField("analyzers.file_info", "str"),
            ConfigField("analyzers.ai", "str"),
        ),
        schedules=(Schedule("sync", 60),),
    )

    def _missing(self) -> str:
        url = (self.config.get("url") or "").rstrip("/")
        missing = []
        if not url or url == _PLACEHOLDER_URL:
            missing.append("url")
        if not self.config.get("api_key"):
            missing.append("api_key")
        return ", ".join(missing)

    def health_check(self) -> HealthStatus:
        missing = self._missing()
        if missing:
            return HealthStatus(ok=False, detail=f"not configured: {missing}")
        try:
            import requests
            response = requests.get(
                f"{self.config['url'].rstrip('/')}/api/status",
                timeout=2,
                proxies={"http": "", "https": ""},
            )
            return HealthStatus(ok=response.status_code < 500, detail=f"HTTP {response.status_code}")
        except Exception as exc:  # noqa: BLE001: a health check must not raise
            return HealthStatus(ok=False, detail=str(exc))

    def sync(self) -> None:
        if self._missing():
            return
        from tasp.cron.sync_cortex import sync_cortex_analyzers
        sync_cortex_analyzers()
