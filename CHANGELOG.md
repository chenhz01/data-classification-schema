# Changelog — data-classification-schema

All releases are local drafts; no remote operations are performed.

## v0.1.1 — 2026-10-13

Fixed:
- `check_fields` no longer crashes on field entries whose `field` value is null
  (fnmatch receives an empty string instead of None).

Changed:
- self_test expanded to 64 cases across functional / exception / extreme-edge
  categories (scaffold v2 four defenses: SystemExit capture, Unicode-safe
  matching, Windows newline-safe fixtures, SUMMARY last line).
- README: Performance section numbers re-measured via the shipped `bench`
  subcommand with reproducible command column.

## v0.1.0 — 2026-10-13

Added:
- Initial local draft: sensitivity-level schema (id/rank levels + glob min_level
  rules), structural validation R1–R3, field-label checking with
  violations/unknown_level/unlabeled buckets, argparse CLI
  (`validate` / `check` / `bench`) and scaffold-v2 self_test.
