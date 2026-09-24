# Roadmap

Built from the [2026-09-24 app audit](docs/audit/2026-09-24-app-audit.md).
Item detail lives in [`BACKLOG.md`](BACKLOG.md). Dates are targets, not promises.

## Phase 1 — Harden (Now · Oct 2026)

Close auth/identity and supply-chain gaps before the next tagged release.

- SEC-1 Challenge link safe against link scanners
- SEC-2 OIDC `email_verified` + collision handling
- SEC-3 OIDC algorithm allowlist + JWKS cache
- SEC-4 CSRF/Origin check for cookie auth
- SEC-6 Pinned, non-root images
- SEC-7 Secret scanning back on
- DOC-1 Doc drift fixes

**Exit:** all P1 closed; security + CodeQL workflows green on `main`; release tagged.

## Phase 2 — Stabilise (Next · Nov–Dec 2026)

Make regressions visible and the codebase cheaper to change.

- TST-1 Playwright in CI
- TST-2 Coverage floor
- SEC-5 Webhook signature model
- REL-2 Exception narrowing + metric
- MNT-1 Central RBAC groups
- MNT-3 Python version alignment
- MNT-4 Dependabot gaps
- REL-1 Mail-road Option-B decision (decision in this phase; implementation may slip to Phase 3)

**Exit:** coverage reported on every PR; e2e specs gating UI changes; REL-1 decision recorded.

## Phase 3 — Analyst value (Later · Q1 2027)

Features the specs already queued.

- FEAT-1 Cross-case IOC sightings
- FEAT-2 Derived-observable provenance in mail detail
- REL-1 Mail escalation implementation
- FEAT-3 AI narration in report / UI
- FEAT-6 On-demand screenshots

## Phase 4 — Consolidate (Q2 2027+)

- FEAT-4 VT Tool absorption
- FEAT-5 Per-observable similarity search
- REL-3 Drop `nonFileIocs`
- MNT-2 Split oversized modules
- TST-3 Page-level frontend tests

## Tracking

GitHub Issues are disabled on this repository. Once enabled, each backlog ID
becomes one issue, with one epic issue per phase.
