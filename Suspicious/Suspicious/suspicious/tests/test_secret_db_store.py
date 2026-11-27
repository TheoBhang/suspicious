import os
from unittest import mock

from cryptography.fernet import Fernet
from django.db import DatabaseError
from django.test import TestCase

from settings.models import StoredSecret
from suspicious import secrets as sec

K1, K2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()
NO_VAULT = {"VAULT_ADDR": ""}


class DbSecretStoreTest(TestCase):
    def setUp(self):
        sec._CACHE.clear()
        self.addCleanup(sec._CACHE.clear)

    def _env(self, **env):
        p = mock.patch.dict(os.environ, {"VAULT_ADDR": "", **env})
        p.start()
        self.addCleanup(p.stop)

    def test_write_then_read_roundtrips(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "s3cret")
        sec._CACHE.clear()
        self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "s3cret")

    def test_the_value_is_not_stored_in_clear(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "s3cret")
        row = StoredSecret.objects.get(key="integrations.thehive.api_key")
        self.assertNotIn("s3cret", row.ciphertext)

    def test_a_second_write_replaces_the_value(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.watcher.api_key", "one")
        sec.set_secret("integrations.watcher.api_key", "two")
        sec._CACHE.clear()
        self.assertEqual(sec.get_secret("integrations.watcher.api_key"), "two")
        self.assertEqual(StoredSecret.objects.filter(key="integrations.watcher.api_key").count(), 1)

    def test_no_master_key_means_store_unavailable(self):
        self._env(SECRETS_MASTER_KEY="")
        with self.assertRaises(sec.SecretStoreUnavailable):
            sec.set_secret("integrations.thehive.api_key", "x")

    def test_without_a_row_the_settings_value_is_used(self):
        self._env(SECRETS_MASTER_KEY=K1)
        with mock.patch.object(sec, "settings_get", return_value="from-json"):
            self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "from-json")

    def test_a_row_beats_the_settings_value(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "db")
        sec._CACHE.clear()
        with mock.patch.object(sec, "settings_get", return_value="from-json"):
            self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "db")

    def test_rotation_new_first_key_still_reads_old_rows(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "v")
        sec._CACHE.clear()
        self._env(SECRETS_MASTER_KEY=f"{K2},{K1}")
        self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "v")
        sec.set_secret("integrations.thehive.api_key", "v2")  # re-encrypted under K2
        sec._CACHE.clear()
        self._env(SECRETS_MASTER_KEY=K2)
        self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "v2")

    def test_a_wrong_master_key_fails_loudly_not_silently(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "s3cret-value")
        sec._CACHE.clear()
        self._env(SECRETS_MASTER_KEY=K2)
        with self.assertRaises(RuntimeError) as cm:
            sec.get_secret("integrations.thehive.api_key")
        self.assertNotIn("s3cret-value", str(cm.exception))

    def test_a_ciphertext_moved_to_another_key_is_refused(self):
        self._env(SECRETS_MASTER_KEY=K1)
        sec.set_secret("integrations.thehive.api_key", "v")
        row = StoredSecret.objects.get(key="integrations.thehive.api_key")
        StoredSecret.objects.create(key="integrations.watcher.api_key", ciphertext=row.ciphertext)
        sec._CACHE.clear()
        with self.assertRaises(RuntimeError):
            sec.get_secret("integrations.watcher.api_key")

    def test_boot_critical_keys_never_use_the_database(self):
        self._env(SECRETS_MASTER_KEY=K1)
        with self.assertRaises(sec.SecretStoreUnavailable):
            sec.set_secret("app.secret_key", "x")
        with mock.patch.object(sec, "settings_get", return_value="boot"), \
             mock.patch("settings.models.StoredSecret.objects") as m_objects:
            self.assertEqual(sec.get_secret("database.password"), "boot")
        m_objects.filter.assert_not_called()

    def test_a_database_error_falls_back_to_the_settings_value(self):
        self._env(SECRETS_MASTER_KEY=K1)
        with mock.patch("settings.models.StoredSecret.objects") as m_objects, \
             mock.patch.object(sec, "settings_get", return_value="from-json"):
            m_objects.filter.side_effect = DatabaseError("down")
            self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "from-json")

    def test_vault_wins_when_configured(self):
        self._env(SECRETS_MASTER_KEY=K1, VAULT_ADDR="https://vault")
        with mock.patch.object(sec, "_read_from_vault", return_value="vault-v"):
            self.assertEqual(sec.get_secret("integrations.thehive.api_key"), "vault-v")
        with mock.patch.object(sec, "_with_login_retry") as m_vault:
            sec.set_secret("integrations.thehive.api_key", "x")
        m_vault.assert_called_once()
        self.assertFalse(StoredSecret.objects.exists())
