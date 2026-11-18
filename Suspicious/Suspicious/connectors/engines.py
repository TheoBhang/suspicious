"""Analysis engines: the only code the pipeline calls to start analyzer jobs.

Every enabled connector whose manifest ``provides`` "analysis" (Cortex first)
offers analyzers through ``catalog``; ``select_analyzers`` is the one policy
that picks among them, and ``dispatch`` alone writes the AnalyzerReport and
CaseAnalyzerJob rows, exactly as ``CortexJob.run_analyzer`` did.
"""
from __future__ import annotations

import dataclasses
import logging

from django.db import transaction

from connectors.base import PROVIDER_KIND_ANALYSIS, CatalogEntry
from connectors.registry import registry

logger = logging.getLogger(__name__)

ID_MAX_LENGTH = 50  # Analyzer.analyzer_cortex_id and CaseAnalyzerJob.cortex_job_id

# Data types whose analyzers are the configured roles, looked up by name.
ROLE_TYPES = {
    "file": ("yara", "file_info", "sandbox"),
    "mail_body": ("yara",),
    "mail_header": ("header",),
}
EML_EXCLUDED_ROLES = ("ai", "yara", "sandbox", "header")
GENERIC_EXCLUDED_ROLES = ("yara", "sandbox", "header")


def _role_names(roles: dict, wanted) -> set[str]:
    # Only set names: an absent or empty role must never put None or {} into the set.
    return {roles[r] for r in wanted if roles.get(r)}


def enabled_engines() -> list[str]:
    from connectors.delivery import get_state  # lazy: delivery imports the registry too

    return sorted(n for n in registry.providers(PROVIDER_KIND_ANALYSIS) if get_state(n).enabled)


def select_analyzers(data_type: str, value, offered: list[CatalogEntry], roles: dict) -> list[CatalogEntry]:
    """The analyzer selection policy, from launch_cortex_jobs, get_file_analyzers and
    get_analyzers_by_type. Raises TypeError for a file without ``file_path.name``, as they did."""
    if data_type in ROLE_TYPES:
        keep = _role_names(roles, ROLE_TYPES[data_type])
        if data_type == "file":
            if not hasattr(value, "file_path") or not hasattr(value.file_path, "name"):
                raise TypeError("file must have 'file_path.name' attribute")
            if value.file_path.name.endswith(".eml"):
                keep -= _role_names(roles, EML_EXCLUDED_ROLES)
        return [entry for entry in offered if entry.name in keep]
    excluded = _role_names(roles, GENERIC_EXCLUDED_ROLES)
    return [entry for entry in offered if entry.name not in excluded]


def ledger_ids(connector: str, ext_job_id: str, ext_analyzer_id: str) -> tuple[str, str]:
    """(CaseAnalyzerJob.cortex_job_id, Analyzer.analyzer_cortex_id): raw for Cortex,
    namespaced for any other engine. ValueError when either exceeds the column."""
    if connector == "cortex":
        ids = (ext_job_id, ext_analyzer_id)
    else:
        ids = (f"{connector}-{ext_job_id}", f"{connector}:{ext_analyzer_id}")
    if max(len(i) for i in ids) > ID_MAX_LENGTH:
        raise ValueError(f"{connector} id over {ID_MAX_LENGTH} characters")
    return ids


def dispatch(value, data_type: str, case) -> list[str]:
    """Start the selected analyzers of every enabled engine on ``value``; returns the
    ledger job ids. One engine or analyzer failing never stops the others."""
    if case is None:
        raise TypeError("dispatch requires a non-None case")
    names = enabled_engines()
    if not names:
        return []

    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
    from settings.config import get_section

    try:
        data_value = CortexJob.get_data_value(value, data_type)
    except Exception as exc:  # noqa: BLE001
        logger.error("Error extracting data value for %s: %s", data_type, exc)
        return []
    if not data_value or (isinstance(data_value, str) and not data_value.strip()):
        logger.debug("Skip %s dispatch: empty data value", data_type)
        return []

    roles = get_section("integrations.cortex").get("analyzers") or {}
    job_ids = []
    for name in names:
        try:
            job_ids += _dispatch_engine(name, value, data_type, data_value, case, roles)
        except Exception as exc:  # noqa: BLE001: one engine must not stop the others
            logger.error("Engine %s failed to dispatch %s: %s", name, data_type, type(exc).__name__)
    return job_ids


def _dispatch_engine(name, value, data_type, data_value, case, roles) -> list[str]:
    from cortex_job.models import Analyzer

    connector = registry.instantiate(name)
    if data_type in ROLE_TYPES:
        offered = [
            entry
            for role in ROLE_TYPES[data_type] if roles.get(role)
            for entry in connector.catalog(name=roles[role])
        ]
    else:
        offered = connector.catalog(data_type=data_type)

    job_ids = []
    for entry in select_analyzers(data_type, value, offered, roles):
        if Analyzer.objects.filter(name=entry.name).exclude(source=name).exists():
            logger.error("Engine %s offers analyzer %r, owned by another source: skipped", name, entry.name)
            continue
        try:
            job_id = _start(connector, name, entry, value, data_type, data_value, case)
        except Exception as exc:  # noqa: BLE001: one analyzer must not stop the others
            logger.error("Error running analyzer %s on %s: %s", entry.name, name, type(exc).__name__)
            continue
        if job_id:
            job_ids.append(job_id)
    return job_ids


def _start(connector, name, entry, value, data_type, data_value, case) -> str | None:
    from connectors.models import ConnectorDelivery
    from cortex_job.cortex_utils.cortex_and_job_management import CortexJob
    from cortex_job.models import AnalyzerReport, CaseAnalyzerJob

    try:
        started = connector.start(entry, data_type, data_value)
        reason = "" if started else "refused"
    except Exception as exc:  # noqa: BLE001: the class name only, never a URL or secret
        started, reason = None, type(exc).__name__
    if reason:
        logger.warning("Engine %s did not start %s on %s: %s", name, entry.name, data_type, reason)
        ConnectorDelivery.objects.create(
            connector=name, event="start", case_id=case.id,
            status=ConnectorDelivery.STATUS_FAILED, error=f"{entry.name}: {reason}",
        )
        return None

    # Task 4 adds the finished-result path; until then started.finished is ignored (row pending).
    job_id, analyzer_id = ledger_ids(name, str(started.job_id), str(entry.id))
    with transaction.atomic():
        analyzer_db = CortexJob.get_analyzer_db(dataclasses.replace(entry, id=analyzer_id), source=name)
        analyzer_report = AnalyzerReport(
            cortex_job_id=job_id,
            type=data_type,
            analyzer=analyzer_db,
            status="InProgress",
            level="info",
            confidence=0,
            score=0,
            report_summary={"ongoing": "analysis"},
            report_full={"ongoing": "analysis"},
            report_taxonomy={"ongoing": "analysis"},
        )
        CortexJob.set_analyzer_report_data(analyzer_report, value, data_type)
        CaseAnalyzerJob.objects.create(
            case=case,
            cortex_job_id=job_id,
            analyzer=analyzer_db,
            analyzer_report=analyzer_report,
            status=CaseAnalyzerJob.STATUS_INPROGRESS,
        )
    return job_id
