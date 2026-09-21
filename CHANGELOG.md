# Changelog

## [Unreleased]

### Added

- **Live SoulAuth integration (`crates/srg-live`, `scripts/live-soulauth.sh`).** Authenticates
  an AI actor against a running SoulAuth end to end — challenge, Ed25519 signature, session
  token, `GET /api/auth/introspect` — and hands the returned authentication fact to
  `srg-soulauth`, which now consumes the introspection response (fact plus session
  projection) and carries the session id into `VerifiedActorFact`. Negative checks (missing,
  forged, replayed) and an optional human password session are recorded too. Evidence under
  `results/live/soulauth/`; the core run manifest reports the last live execution instead of
  a bare `NOT_RUN`. The adapter is pinned to SoulAuth v0.4.0 (`82ff8ae`), the release that introduced the endpoint.

## [0.1.0] - 2026-09-19

First public release: the executable companion artifact of *Persistent Subjecthood and
Responsibility Black Holes*.

- Four crates: `srg-core` (types, reference contract, four-valued reduction), `srg-harness`
  (controlled ledger, ten independent checkers, twenty scenarios across four baselines, tables,
  P4 composition), `srg-explorer` (finite worlds, P1/P2 collisions, bounded BFS with eight
  mutations), `srg-soulauth` (SoulAuth v0.3.0 authentication-fact adapter).
- Two TLA+ models executed with SANY and TLC; the per-fault counterexample matrix is committed
  and cross-checked against the Rust search by a test and by CI.
- Committed, deterministic evidence under `results/`; CI regenerates it and diffs.
- `docs/ARTIFACT_DELTA.md` records every remaining difference between the artifact and the
  paper text, classified per the conformance baseline.
