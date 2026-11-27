"""The object-store health check must not depend on mail arriving.

/health used to mark MinIO healthy only after an upload, so a feeder with an empty mailbox went
"degraded" five minutes after its last mail although nothing was wrong. The poll loop now probes the
store on a timer.
"""
import unittest
from unittest import mock

import main
import classes.models.configs.internals.minio as minio_config
import classes.services.minio_service as minio_service


def _service(feeder_bucket: str = "feeder-bucket") -> tuple[minio_service.MinioService, mock.Mock]:
    cfg = minio_config.MinioConfig(
        endpoint="rustfs:9000", access_key="a", secret_key="s", secure=False, feeder_bucket=feeder_bucket,
    )
    svc = minio_service.MinioService(cfg)
    client = mock.Mock()
    svc._MinioService__minio_client = client
    return svc, client


class MinioServiceProbe(unittest.TestCase):
    def test_probe_checks_the_feeder_bucket_when_there_is_one(self):
        svc, client = _service("feeder-bucket")
        svc.probe()
        client.bucket_exists.assert_called_once_with("feeder-bucket")
        client.list_buckets.assert_not_called()

    def test_probe_lists_buckets_in_bucket_per_submission_mode(self):
        svc, client = _service("")
        svc.probe()
        client.list_buckets.assert_called_once_with()
        client.bucket_exists.assert_not_called()

    def test_probe_raises_when_the_store_is_unreachable(self):
        svc, client = _service()
        client.bucket_exists.side_effect = OSError("connection refused")
        with self.assertRaises(OSError):
            svc.probe()

    def test_probe_raises_without_a_client(self):
        svc = minio_service.MinioService(minio_config.MinioConfig(
            endpoint="e", access_key="a", secret_key="s", secure=False))
        with self.assertRaises(Exception):
            svc.probe()


class ProbeSchedule(unittest.TestCase):
    def setUp(self):
        main._stats["minio_last_ok"] = 0.0
        main._last_minio_probe = 0.0

    def test_an_idle_feeder_is_healthy_once_the_probe_has_run(self):
        svc = mock.Mock()
        main._probe_minio_if_due(svc, now=1_000_000.0)
        svc.probe.assert_called_once_with()
        self.assertEqual(main._stats["minio_last_ok"], 1_000_000.0)

    def test_the_probe_runs_at_most_once_per_interval(self):
        svc = mock.Mock()
        main._probe_minio_if_due(svc, now=1_000_000.0)
        main._probe_minio_if_due(svc, now=1_000_000.0 + main._MINIO_PROBE_INTERVAL_S - 1)
        self.assertEqual(svc.probe.call_count, 1)
        main._probe_minio_if_due(svc, now=1_000_000.0 + main._MINIO_PROBE_INTERVAL_S)
        self.assertEqual(svc.probe.call_count, 2)

    def test_a_failing_probe_does_not_mark_the_store_healthy_or_raise(self):
        svc = mock.Mock()
        svc.probe.side_effect = OSError("down")
        main._stats["minio_last_ok"] = 5.0
        main._probe_minio_if_due(svc, now=1_000_000.0)          # must not raise
        self.assertEqual(main._stats["minio_last_ok"], 5.0)      # the last good time is kept
        # and it stays due, so the next cycle tries again after the interval
        svc.probe.side_effect = None
        main._probe_minio_if_due(svc, now=1_000_000.0 + main._MINIO_PROBE_INTERVAL_S)
        self.assertEqual(main._stats["minio_last_ok"], 1_000_000.0 + main._MINIO_PROBE_INTERVAL_S)

    def test_health_stays_ok_with_no_mail_while_the_probe_succeeds(self):
        import time
        svc = mock.Mock()
        main._stats["mailboxes_configured"] = 1
        main._stats["mailbox_last_ok"] = {"box": time.time()}
        main._probe_minio_if_due(svc, now=time.time())
        payload = main._build_health_payload()
        self.assertTrue(payload["checks"]["minio"]["ok"])
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
