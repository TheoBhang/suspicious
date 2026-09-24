# Roadmap

Built from the [2026-09-24 app audit](docs/audit/2026-09-24-app-audit.md).
Item detail lives in [`BACKLOG.md`](BACKLOG.md). Dates are targets, not promises.

## Phase 1 — Harden (Now · Oct 2026)

Epic: [#17](https://github.com/TheoBhang/suspicious/issues/17)

Close auth/identity and supply-chain gaps before the next tagged release.

- [SEC-1](https://github.com/TheoBhang/suspicious/issues/21) Challenge link safe against link scanners
- [SEC-2](https://github.com/TheoBhang/suspicious/issues/22) OIDC `email_verified` + collision handling
- [SEC-3](https://github.com/TheoBhang/suspicious/issues/23) OIDC algorithm allowlist + JWKS cache
- [SEC-4](https://github.com/TheoBhang/suspicious/issues/24) CSRF/Origin check for cookie auth
- [SEC-6](https://github.com/TheoBhang/suspicious/issues/25) Pinned, non-root images
- [SEC-7](https://github.com/TheoBhang/suspicious/issues/26) Secret scanning back on
- [DOC-1](https://github.com/TheoBhang/suspicious/issues/27) Doc drift fixes

**Exit:** all P1 closed; security + CodeQL workflows green on `main`; release tagged.

## Phase 2 — Stabilise (Next · Nov–Dec 2026)

Epic: [#18](https://github.com/TheoBhang/suspicious/issues/18)

Make regressions visible and the codebase cheaper to change.

- [TST-1](https://github.com/TheoBhang/suspicious/issues/34) Playwright in CI
- [TST-2](https://github.com/TheoBhang/suspicious/issues/35) Coverage floor
- [SEC-5](https://github.com/TheoBhang/suspicious/issues/28) Webhook signature model
- [REL-2](https://github.com/TheoBhang/suspicious/issues/30) Exception narrowing + metric
- [MNT-1](https://github.com/TheoBhang/suspicious/issues/31) Central RBAC groups
- [MNT-3](https://github.com/TheoBhang/suspicious/issues/32) Python version alignment
- [MNT-4](https://github.com/TheoBhang/suspicious/issues/33) Dependabot gaps
- [REL-1](https://github.com/TheoBhang/suspicious/issues/29) Mail-road Option-B decision (decision in this phase; implementation may slip to Phase 3)

**Exit:** coverage reported on every PR; e2e specs gating UI changes; REL-1 decision recorded.

## Phase 3 — Analyst value (Later · Q1 2027)

Epic: [#19](https://github.com/TheoBhang/suspicious/issues/19)

Features the specs already queued.

- [FEAT-1](https://github.com/TheoBhang/suspicious/issues/36) Cross-case IOC sightings
- [FEAT-2](https://github.com/TheoBhang/suspicious/issues/37) Derived-observable provenance in mail detail
- [REL-1](https://github.com/TheoBhang/suspicious/issues/29) Mail escalation implementation
- [FEAT-3](https://github.com/TheoBhang/suspicious/issues/38) AI narration in report / UI
- [FEAT-6](https://github.com/TheoBhang/suspicious/issues/39) On-demand screenshots

## Phase 4 — Consolidate (Q2 2027+)

Epic: [#20](https://github.com/TheoBhang/suspicious/issues/20)

- [FEAT-4](https://github.com/TheoBhang/suspicious/issues/40) VT Tool absorption
- [FEAT-5](https://github.com/TheoBhang/suspicious/issues/41) Per-observable similarity search
- [REL-3](https://github.com/TheoBhang/suspicious/issues/42) Drop `nonFileIocs`
- [MNT-2](https://github.com/TheoBhang/suspicious/issues/43) Split oversized modules
- [TST-3](https://github.com/TheoBhang/suspicious/issues/44) Page-level frontend tests

## Tracking

Each backlog ID is one GitHub issue, attached as a sub-issue to its phase epic.
Labels: `epic`, `roadmap`, area (`security`, `backend`, `frontend`, `ci`, …),
priority (`P1`–`P3`) and size (`size: S/M/L`).
