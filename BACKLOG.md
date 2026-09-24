# Backlog

Source: [2026-09-24 app audit](docs/audit/2026-09-24-app-audit.md). Sequencing:
[`ROADMAP.md`](ROADMAP.md).

Priority: **P1** fix before next release · **P2** next cycle · **P3** when capacity allows.
Size: **S** ≤1 day · **M** 2–4 days · **L** 1–2 weeks.

## Security

| ID | Item | Pri | Size | Done when |
|---|---|---|---|---|
| SEC-1 | Challenge link: GET shows confirm page, POST consumes token (`api/views/challenge.py`) | P1 | S | Pre-fetch by a link scanner no longer triggers a challenge; test covers GET-is-safe |
| SEC-2 | OIDC: require `email_verified`; handle duplicate email and username collision explicitly (`api/views/oidc.py`) | P1 | S | Unverified email refused; tests for both collision cases |
| SEC-3 | OIDC: pin JWT algorithm allowlist; cache `PyJWKClient` | P1 | S | `none`/`HS*` rejected in test; one JWKS fetch per TTL |
| SEC-4 | CSRF/Origin check for cookie-authenticated unsafe requests (`api/authentication.py`) | P1 | M | Cross-origin POST with cookie → 403; UI unaffected |
| SEC-5 | Cortex webhook: HMAC body signature + timestamp, or document bearer model; enqueue before dedup mark | P2 | M | Tampered body rejected; failed enqueue retried |
| SEC-6 | Pin UI/analyzer base images; non-root nginx + analyzers | P1 | S | No floating tags; every image runs non-root |
| SEC-7 | Re-enable secret scanning (gitleaks binary or TruffleHog) | P1 | S | Scanner runs on every PR |

## Reliability

| ID | Item | Pri | Size | Done when |
|---|---|---|---|---|
| REL-1 | Decide + implement mail-road Option-B split; wire `mail_band_escalation` | P2 | L | Decision recorded; `backtest_scoring --road mail` drift reviewed |
| REL-2 | Narrow `except Exception` on finalise / scoring / dispatch paths; add swallowed-error metric | P2 | M | Hot paths audited; metric visible in Grafana |
| REL-3 | Backfill and drop legacy `nonFileIocs` | P3 | M | Migration + backfill shipped; no code reads it |

## Maintainability

| ID | Item | Pri | Size | Done when |
|---|---|---|---|---|
| MNT-1 | Centralise RBAC group names + `is_investigator` helper | P2 | S | No `"CERT"`/`"CISO"`/`"Admin"` literals outside one module |
| MNT-2 | Split oversized modules (mailbox_service, cortex_and_job_management, InvestigationPage, SubmissionsPage, themes.ts) | P3 | L | No module >600 LOC except data files |
| MNT-3 | Align Python version across backend, feeder, analyzers | P2 | S | One supported version in all Dockerfiles + CI |
| MNT-4 | Dependabot for MailHeaderAnalyzer and `requirements-connectors.txt` | P2 | S | Dependabot PRs appear for both |

## Testing / CI

| ID | Item | Pri | Size | Done when |
|---|---|---|---|---|
| TST-1 | Run Playwright `e2e/` specs in CI | P2 | M | Specs gate PRs touching `suspicious-ui/` |
| TST-2 | Coverage reports + floor (backend + frontend) | P2 | S | Coverage in CI summary; floor enforced |
| TST-3 | Tests for Investigation / Submissions / Profile / Login pages | P3 | M | Each page has render + main-flow tests |

## Docs

| ID | Item | Pri | Size | Done when |
|---|---|---|---|---|
| DOC-1 | Fix doc drift: webhook auth wording, test count, LDAP config path in warning | P1 | S | `CLAUDE.md`, architecture doc and log text match code |

## Product

| ID | Item | Pri | Size | Source |
|---|---|---|---|---|
| FEAT-1 | Cross-case IOC sightings ("seen in N previous cases") | P2 | L | IOC-road spec §11 |
| FEAT-2 | Derived-observable provenance chip + `escalation_note` on mail detail | P2 | M | Derived-observables spec §6 |
| FEAT-3 | Render AI narration in report / UI (after governance sign-off) | P3 | M | AI-narration specs |
| FEAT-4 | Absorb VT Tool into the IOC road | P3 | L | IOC-road spec §11 |
| FEAT-5 | Per-observable similarity search | P3 | M | IOC-road spec §11 |
| FEAT-6 | On-demand URL screenshot; urlscan egress-failure metric | P3 | S | Screenshot spec |
