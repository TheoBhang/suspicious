# Deploy & Rollback

Updates are applied with a zero-downtime rolling update from `deployment/`:

```bash
make deploy   # pull new images → run migrations → restart services in order
```

Individual steps are also available: `make migrate`, `make collectstatic`,
`make build`. Check health afterwards with `make status` and tail logs with
`make logs s=<service>`.

To roll back, redeploy the previous image tags (set in `deployment/.env`) and
run `make deploy` again.

`make deploy` stops until the data services enforce authentication, so an
existing stack must run `make db-auth-migrate` once first (next section).
`make db-auth-check` verifies the result at any time.

## AI model (ai_model connector)

The Cortex AI analyzer is removed. The AI vote comes from `ai_inference`, which
`make deploy` builds and starts, called by the `ai_model` connector. The
connector is **off by default**, so an upgraded instance has no AI vote until
you do this once:

1. Create a token (`openssl rand -hex 24`) and set it as `AI_INFERENCE_TOKEN` in
   `deployment/.env`. Nothing generates it for you; empty makes the `/v2`
   routes answer 503.
2. Set the same value as `integrations.ai_model.token` (`settings.json` or the
   Settings tile). A mismatch shows as `rejected the token (HTTP 401)`.
3. Check the weights in `Analyzers/AIMailAnalyzer/models/`, then recreate the
   app tier: `docker compose --env-file .env up -d --force-recreate --no-deps suspicious suspicious_celery suspicious_celery_beat`.
4. Enable the `ai_model` connector and set the `chromadb` `collection_name`.
5. Keep `integrations.cortex.analyzers.ai` in `settings.json`.

Until step 4 is done, mail verdicts that need the AI vote end `Inconclusive`.
Full procedure: [AI inference](../getting-started/ai-inference.md#10-upgrading-an-existing-instance).

## Authenticated data services

Redis, Elasticsearch and ChromaDB require credentials (see
[Internal service authentication](../../CONFIG.md#internal-service-authentication)).
New installs get them from `make init`.

### Upgrading an existing deployment (one time)

`make deploy` refuses to run until the data services enforce authentication.
Back up first (`make backup-db`), then:

```bash
make db-auth-migrate
```

Maintenance window of about 1-2 minutes: the app tier stops (Celery gets a warm
shutdown), the data tier restarts with authentication, the Elasticsearch service
accounts are created, then the app tier starts with credentials. Users are
logged out and the Redis cache is dropped.

Before you run it:

- **Queued Celery tasks are discarded** by the Redis recreate (Redis has no
  volume), so migrate when the queue is quiet. Ongoing cases are re-synced by
  `update_ongoing_cases` within about 5 minutes; Cortex jobs in flight are lost
  and restarted by that sweep.
- The Elasticsearch and Cortex containers are required in this path even when
  `case_search` is off (Cortex stores its data in Elasticsearch).
- If the script dies after stopping the app tier, the app stays down. Re-run
  `make db-auth-migrate`: every step is idempotent. If everything is already
  authenticated it prints "already migrated" and exits (`--force` reruns).

The script ends with `make db-auth-check`.

Order of operations: back up `.env` / `.env.data` -> generate secrets -> stop app
tier -> recreate redis, elasticsearch, chromadb, chromadb_proxy -> wait for them
to be healthy -> create ES accounts -> start app tier -> verify.

### Rollback

Before changing anything the script copies `.env` and `.env.data` (if present)
to `<file>.pre-db-auth.<epoch>`. To roll back, restore those copies **and** check
out the previous release (older compose files do not load `.env.data`), then
`docker compose up -d --force-recreate` the data tier. Redis held only
cache/queue data; Elasticsearch and Chroma volumes are untouched.

### Rotating a secret

All commands run from `deployment/` after editing the value.

| Secret | Steps |
|---|---|
| Redis broker | `docker compose --env-file .env up -d --force-recreate --no-deps redis_broker suspicious suspicious_celery suspicious_celery_beat` (about 30 s, users logged out) |
| Redis cache | same with `redis_cache` instead of `redis_broker` |
| ES app / Cortex users | `bash scripts/es-security-bootstrap.sh`, then `up -d --force-recreate --no-deps suspicious suspicious_celery cortex` |
| `ELASTIC_PASSWORD` | Send the change through the security API with a curl config on stdin, so neither password appears in argv: `printf 'user = "elastic:OLD"\ndata = "{\"password\":\"NEW\"}"\n' \| docker compose exec -T elasticsearch curl -sS -K - -X POST -H 'Content-Type: application/json' http://localhost:9200/_security/user/elastic/_password` (run it with history disabled). Then update `.env.data` and `up -d --force-recreate --no-deps elasticsearch` (its healthcheck reads the container's `$ELASTIC_PASSWORD`) |
| `CHROMA_TOKEN` | recreate `chromadb_proxy suspicious suspicious_celery` |

## Network segmentation

The stack no longer runs on one flat network. The shared network (Compose key
`suspicious_network`, real name `${NETWORK_NAME}`, default `suspicious_net`,
created by `make network`) stays the shared network for the reverse proxy, the UI, the
feeder, Vault and integrations such as TheHive, MISP or monitoring. Three
networks managed by Compose sit behind it, so a compromised front-end service
cannot connect to a database:

| Network | Members | Reachable by |
|---|---|---|
| `data` (internal, no outbound traffic) | MariaDB (and replica), Redis broker, Redis cache, Chroma proxy | Django, Celery worker, Celery beat |
| `storage` | RustFS | Django, Celery worker, feeder, `ai_inference` (presigned training dataset and bundle URLs) |
| `cortex` | Cortex, Elasticsearch | Django, Celery worker |

The Chroma server itself sits on its own internal link behind the proxy. The UI,
the reverse proxy and Vault are not on any of the three networks; the feeder
reaches only the Django API and RustFS; Cortex reaches only Elasticsearch and
the Django webhook. Cortex still needs the Docker socket to start analyzers.

`make network-check` verifies that every service is on exactly the networks it
needs and that the paths it needs work (Django and Celery reach every data
service, the feeder reaches Django and RustFS, Cortex reaches Elasticsearch and
the webhook, and the feeder cannot resolve Redis or MariaDB). `make deploy`
runs it at the end.

### Upgrading an existing deployment

`make deploy` handles it. As the last step it recreates MariaDB and RustFS so
they join their own networks and leave the shared one. Compose only recreates a
service whose configuration changed, so this is a no-op on an up-to-date stack
and a single restart of MariaDB and RustFS (a few seconds of database errors,
once) on the first run. Run it in a quiet period. Tools that connected to
MariaDB, Elasticsearch or Redis through `suspicious_net` from outside the
stack (a backup container, a monitoring exporter) must be attached to the
network they need or use `docker compose exec`.

## Docker socket and container hardening

Only Cortex reaches the Docker daemon, and not by mounting the socket: it goes
through a `tecnativa/docker-socket-proxy` container (`docker_proxy_cortex`) on a
private network that only the two of them share. It allows containers, images
and daemon info, with writes, which is what Cortex's Docker job runner calls.

Traefik has no Docker access at all. Routes come from the file provider
(`traefik/dynamic`), and nothing in the stack uses Traefik container labels, so
the Docker provider and its proxy were removed. A Traefik with the socket, or a
read-only proxy, still exposes every container's environment variables (secrets
included) to a compromised Traefik.

The socket proxy alone is a narrower surface, not a complete fix: it filters by path and
method, not by request body, so a compromised Cortex could still ask for a privileged container.
A second service, `docker_policy_cortex` (`deployment/docker/docker-policy-proxy/`), sits between
Cortex and that proxy and reads the body of container create and image pull requests. It refuses:

- an image that is not in the analyzer catalogs (`analyzers.json` of the public and custom
  catalogs, plus `DOCKER_POLICY_EXTRA_IMAGES`, comma separated, for anything else);
- `Privileged`, added capabilities, devices, device requests, `Mounts`, `VolumesFrom`, port
  bindings, host PID, IPC, user or UTS namespaces, any network except the default, `bridge` or `none`
  (a container on a user network could reach the socket proxy itself), `unconfined` or
  `label=disable` security options, a non-default runtime;
- a bind whose source is not a directory inside the Cortex job directory (`${CORTEX_PATH}/jobs`; the
  directory itself is refused), including named volumes and `..` escapes;
- any endpoint an analyzer run does not use (exec, update, archive, volumes, networks, build), connection upgrades, and any second request on a connection (one request is
  forwarded per connection, the rest is never read). Docker decodes JSON keys case-insensitively, so
  the body is parsed strictly: a key repeated in any case is refused.

Beyond the create body, the policy also:

- sits alone between Cortex and the raw socket proxy: the proxy is on its own internal network
  (`docker_upstream`) shared only with the policy, so Cortex cannot skip the policy by using another
  hostname (`make network-check` asserts it);
- adds the label `org.thalesgroup.suspicious.cortex-analyzer=1` to every container it lets Cortex create,
  and lets start, stop, kill, wait, logs, inspect and delete reach only containers with that label, so a
  compromised Cortex cannot read the environment of, or stop, the stack's own containers. Containers made
  before the label existed are refused after `enforce`: switch while no analyzer is running;
- allows only the `HostConfig` fields an analyzer run sends (binds, network mode, resource limits,
  `CapDrop`, `AutoRemove`) and refuses `NetworkingConfig.EndpointsConfig`, `MaskedPaths` and
  `ReadonlyPaths`, and non-ASCII JSON keys;
- refuses a body on every request except container create, and a create sent as a form;
- cuts off a client that stalls while sending a request (15 s).

It exits at start if a catalog cannot be read, or holds no image, instead of running with an empty
allow-list. Bind sources are resolved through symlinks (the job directory is mounted read-only into the
policy container). Known limits: a symlink swapped between the check and the daemon's mount is not
caught, and an allowed analyzer still runs as root in its own container with outbound network access on
the default bridge.

The service has a healthcheck (`GET /_ping` through the whole path) and Cortex waits for it; `make deploy`
starts it before Cortex. The Python image is pinned by digest.

`DOCKER_POLICY_MODE` selects `log` (the default: everything is forwarded, and what would have been
refused is logged as `would_deny`) or `enforce` (answers 403). Run in `log` first, run a few of
each analyzer you use, then check
`docker logs docker_policy_cortex | grep -E '"verdict": "(would_deny|deny)"'`. When that is empty,
set `DOCKER_POLICY_MODE=enforce` in `.env` and recreate the service. Recreating `docker_policy_cortex` drops its connections for a
couple of seconds: any analyzer job being started, waited on or collected at that moment fails with
"Connection refused" (seen on the dev stack when switching to `enforce`). Switch modes while no
analyzers are running; jobs lost anyway are failed by the stale-job rescue (`fail_stale_jobs`, after
`STALE_JOB_TIMEOUT_SECONDS`) or can be redone from the case. On the dev stack a run of 14
analyzers sent only a bind of the job directory in `HostConfig`; nothing was flagged. The policy is
not a sandbox: an allowed analyzer image still runs as root in its own container with network
access. Rootless Docker or a dedicated analyzer host remain the stronger options.

**Required when you upgrade:** if your `traefik.yaml` defines a `providers.docker`
section, remove it and declare those routes under `traefik/dynamic`. `make deploy`
stops with a message if the section is present (`scripts/check-traefik-provider.sh`).
Cortex needs no change: the compose file passes `docker.host` as a Java option,
and `DOCKER_SOCK_GID` is no longer used by Cortex.

The Django, Celery, beat and feeder containers also run with every Linux
capability dropped and `no-new-privileges`. The UI and Cortex start as root and
then drop to their own user, so they keep only `CHOWN`, `DAC_OVERRIDE`, `SETGID`
and `SETUID`. Vault is unchanged.

### Mail preview renderer

The PNG preview of a reported mail is drawn by `mail_renderer`, a separate
headless-Chromium container (`mail-renderer/`), not by a binary inside the Django
image. It replaces `wkhtmltoimage`, an unmaintained 2020 WebKit, and removes
`wkhtmltopdf` and `imgkit` from the Django image.

- **Isolation.** It sits on its own `internal` network with only Django and
  Celery. It has no route to the internet or to any other service, which
  `make network-check` verifies. Inside it: JavaScript off, every request the page
  makes aborted, no DNS, a non-root user, all capabilities dropped, a read-only
  root, 1 GB of memory, 512 processes.
- **Sandbox.** Chromium's own sandbox stays on. As Playwright documents for
  untrusted content, that needs a non-root user and its seccomp profile,
  vendored as `mail-renderer/seccomp_profile.json` and applied by the compose
  file. It uses `shm_size` instead of sharing the host IPC namespace.
- **Output.** The screenshot is clipped to the content, at most 4000 px tall, as a
  compressed PNG (about 20 KB for a typical mail). The old renderer wrote a fixed
  900 x 4000 canvas of about 14 MB for every mail.
- **Upgrading.** `make deploy` builds and starts the service. Previews stored by
  the old renderer keep working; shrink them with
  `docker compose exec suspicious python manage.py regenerate_mail_previews --all`
  (add `--limit N` to do it in batches). If the renderer is down, new previews are
  skipped and retried by the existing sweeper; analysis is not affected.
- **Pinning.** The image tag and the `playwright` pip package must be the same
  version (`PLAYWRIGHT_VERSION` in `mail-renderer/Dockerfile`).
