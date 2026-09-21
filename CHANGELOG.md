# Changelog

## [Unreleased]

## [0.1.1] - 2026-09-21

Two corrections from the external review of 0.1.0, plus the live SoulAuth integration.

### Changed

- **P4(b) states exactly which premises it checked.** Each composition instance now lists
  its premises by name; `premises_established` is their conjunction. For P4(b) that is G1,
  G5, `revocation_effective_before_final_admission`, `no_applicable_reauthorization`,
  `final_admission_denied` and `complete_mediation_bounded` — the last one a real
  execution: the reference resource is handed the Deny admission and must refuse it with
  the ledger unchanged. Before, `premises_established = true` was written after checking
  G1, G5, a Deny and the absence of effects; the revocation ordering, the reauthorization
  clause and complete mediation were satisfied by the scenario but not verified, and the
  G4 checker's N/A on an effect-free scenario was silently standing in for a mediation
  premise. `p4_matrix.csv` gains a `premises` column.
- **`run_manifest.json` names its commit for what it is.** `git_commit` / `git_dirty` are
  now `evidence_source_commit` / `evidence_source_dirty`: the source commit the evidence
  was generated from, which is one commit behind the release commit by construction (the
  release commit differs only by this manifest). Release tag, release commit and archive
  digest live in the release notes; `source_sha256` is what binds evidence to source.

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
