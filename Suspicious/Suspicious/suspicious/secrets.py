"""HashiCorp Vault secret client, an encrypted database store and a settings.json fallback.

Read order:
  - VAULT_ADDR set   -> Vault KV v2 at suspicious/data/<key>, field "value".
  - VAULT_ADDR unset, SECRETS_MASTER_KEY set -> the encrypted StoredSecret row (not for
    app.secret_key and database.password), then settings.json when there is no row.
  - neither          -> settings.json dotted lookup (local dev / CI), read-only.

In-process cache; values are small and rotation is out of scope here.
``fail_fast=True`` (used at boot for SECRET_KEY + DB password) turns any
Vault error into SystemExit(1) with a readable message, no silent
fallback to plaintext when Vault is configured.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any

from suspicious._config_common import settings_get

logger = logging.getLogger(__name__)

_VAULT_MOUNT = "suspicious"

# Needed before the database is reachable: never kept in the database.
_BOOT_CRITICAL = frozenset({"app.secret_key", "database.password"})

_CACHE_TTL = 60
_CACHE: dict[str, Any] = {}
_client_singleton: list = [None]


class SecretStoreUnavailable(RuntimeError):
    """Raised when a secret write is attempted with no Vault and no SECRETS_MASTER_KEY."""


def _fernet():
    """MultiFernet over SECRETS_MASTER_KEY (comma-separated, newest first), None when unset."""
    from cryptography.fernet import Fernet, MultiFernet

    keys = [k.strip() for k in os.environ.get("SECRETS_MASTER_KEY", "").split(",") if k.strip()]
    if not keys:
        return None
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except ValueError as exc:
        raise RuntimeError("SECRETS_MASTER_KEY is not a valid Fernet key list") from exc


def _read_from_db(key: str) -> Any:
    """The decrypted value, None when there is no row (or the database is unreachable)."""
    from django.db import DatabaseError

    from settings.models import StoredSecret

    try:
        row = StoredSecret.objects.filter(key=key).first()
    except DatabaseError as exc:
        logger.warning("secret '%s' not read from the database (%s); using settings.json", key,
                       type(exc).__name__)
        return None
    if row is None:
        return None
    try:
        payload = json.loads(_fernet().decrypt(row.ciphertext.encode()))
        if payload["k"] != key:
            raise ValueError("sealed under another key")
        return payload["v"]
    except Exception as exc:  # noqa: BLE001 -- never echo ciphertext or value
        raise RuntimeError(
            f"could not decrypt secret '{key}' ({type(exc).__name__}): is SECRETS_MASTER_KEY the key it was saved with?"
        ) from None


def _write_to_db(key: str, value: str) -> None:
    from settings.models import StoredSecret

    token = _fernet().encrypt(json.dumps({"k": key, "v": value}).encode()).decode()
    StoredSecret.objects.update_or_create(key=key, defaults={"ciphertext": token})


def _make_client():
    import hvac

    # VAULT_CACERT names the CA that signed the Vault listener certificate; unset
    # means the system trust store, so a Vault behind a public CA still works.
    client = hvac.Client(url=os.environ["VAULT_ADDR"], verify=os.environ.get("VAULT_CACERT") or True)
    client.auth.approle.login(
        role_id=os.environ["VAULT_ROLE_ID"],
        secret_id=os.environ["VAULT_SECRET_ID"],
    )
    if not client.is_authenticated():
        raise RuntimeError("Vault AppRole authentication failed")
    return client


def _client():
    if _client_singleton[0] is None:
        _client_singleton[0] = _make_client()
    return _client_singleton[0]


def _with_login_retry(call):
    """call(client), logging in again once when Vault answers 403.

    The AppRole token expires after its token_ttl (1h from provision-vault.sh) and the client is
    cached for the life of the process, so without this every read fails with "permission denied /
    invalid token" until the container is restarted. A real policy denial is retried once too (one
    extra login) and then raised."""
    import hvac

    try:
        return call(_client())
    except hvac.exceptions.Forbidden:
        _client_singleton[0] = None
        return call(_client())


def _read_from_vault(key: str) -> Any:
    resp = _with_login_retry(lambda client: client.secrets.kv.v2.read_secret_version(
        path=key, mount_point=_VAULT_MOUNT, raise_on_deleted_version=True,
    ))
    return resp["data"]["data"]["value"]


def get_secret(key: str, default: Any = None, *, fail_fast: bool = False) -> Any:
    """Resolve a secret by its dotted settings key.

    ``fail_fast`` exits the process on any Vault error (boot-critical keys).
    Cache entries carry a short TTL so a UI-driven Vault write propagates to
    other worker processes within ``_CACHE_TTL`` seconds.
    """
    cached = _CACHE.get(key)
    if cached is not None and cached[1] > time.monotonic():
        return cached[0]

    if not os.environ.get("VAULT_ADDR"):
        value = None
        if key not in _BOOT_CRITICAL and _fernet() is not None:
            value = _read_from_db(key)
        if value is None:
            value = settings_get(key, default)
        _cache_set(key, value)
        return value

    try:
        value = _read_from_vault(key)
    except Exception as exc:  # noqa: BLE001 (boot must fail readably)
        import hvac

        if isinstance(exc, hvac.exceptions.InvalidPath):
            _cache_set(key, default)
            return default
        message = (
            f"FATAL: could not read secret '{key}' from Vault at "
            f"{os.environ.get('VAULT_ADDR')}: {exc}"
        )
        if fail_fast:
            # codeql[py/clear-text-logging-sensitive-data]: this is the READ
            # failure branch: _read_from_vault raised before ever returning a
            # value, so `message` can only contain the secret's dotted *name*
            # (`key`) and the Vault client's error, never a resolved value.
            sys.stderr.write(f"\n{message}\n\n")
            raise SystemExit(1) from exc
        raise RuntimeError(message) from exc

    _cache_set(key, value)
    return value


def _cache_set(key: str, value: Any) -> None:
    _CACHE[key] = (value, time.monotonic() + _CACHE_TTL)


def set_secret(key: str, value: str) -> None:
    """Write a secret to Vault KV v2 and refresh this process's cache.

    Raises ``SecretStoreUnavailable`` when no Vault is configured:
    settings.json is read-only config, never a write target.
    """
    if not os.environ.get("VAULT_ADDR"):
        if key in _BOOT_CRITICAL or _fernet() is None:
            raise SecretStoreUnavailable(
                "no secret store configured (set VAULT_ADDR or SECRETS_MASTER_KEY); cannot store secret"
            )
        _write_to_db(key, value)
        _cache_set(key, value)
        return
    _with_login_retry(lambda client: client.secrets.kv.v2.create_or_update_secret(
        path=key, secret={"value": value}, mount_point=_VAULT_MOUNT,
    ))
    _cache_set(key, value)
