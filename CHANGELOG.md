# Changelog

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
