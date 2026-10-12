# data-classification-schema

A sensitivity-level schema and field-labeling checker for data inventories. Levels (`public`…`restricted`) are declared once with numeric ranks, pattern rules force minimum levels for risky field names, and the checker lists every unlabeled field. Pure standard library, single file, offline. *No direct equivalent found as of 2026-10-13.*

## Problem

Data classification policies live in PDFs; field labels live in schema files; nothing connects them. The result is predictable: a column named `user_password_reset_token` sits at `internal` while the policy says credentials are `restricted`, and half the new tables ship with no label at all. Auditors ask "show me where the policy is enforced" and the honest answer is a shrug.

## How it works

A **schema** is a JSON document with two parts:

- `levels` — an ordered list of `{id, rank}` entries. Rank is a non-negative integer; higher means more sensitive. Ids are `[A-Za-z][A-Za-z0-9_-]{0,63}`, unique, as are ranks.
- `rules` — an optional list of `{field_pattern, min_level}` entries. Patterns use shell-style globbing (`*email*`, `user[._]ssn`) and are matched case-sensitively.

A **field inventory** is a JSON array of `{field, level}` entries. `check` reports four buckets:

- **violations** — the field matches a rule but its label ranks below `min_level` (exit 1);
- **unknown_level** — the label is not a declared level (exit 1);
- **unlabeled** — no level declared (listed, exit 0: a listing, not a gate);
- **ok** — labeled, and no rule it fails.

`validate` enforces schema structure (rules R1–R3). Reports are text or `--json`.

## Quickstart

```console
$ python data_classification_schema.py validate schema.json      # ~0.1 s
OK: no findings
$ python data_classification_schema.py check schema.json fields.json
checked=120 ok=95 violations=6 unknown_level=2 unlabeled=17
```

Labeling a 100-field inventory with this loop is minutes, not sprints; checking 10,000 synthetic fields takes 0.08 s [Measured] (see Performance).

## Why not X

- **AWS Macie / cloud DSPM products** — classify data inside one vendor's cloud by scanning content; no standalone, vendor-neutral artifact you can version or diff.
- **Apache Ranger / Sentry policies** — enforce access at query time in specific engines; they assume labels exist somewhere else and never validate the labeling itself.
- **JSON Schema** — can require that a `level` key exists, but cannot express "the level must outrank what this name pattern demands".
- **Spreadsheets of approved labels** — the status quo: no rank semantics, no pattern rules, no way to run in CI.

## Performance

All numbers [Measured] locally (Python 3.13, Windows 10, single core):

| Workload | Result | Command |
|---|---|---|
| 10,000 fields, 2 rules | 0.08 s (~125k fields/s) | `python data_classification_schema.py bench --fields 10000` |
| Schema validation | <1 ms | `python data_classification_schema.py validate schema.json` |

`bench` builds a deterministic synthetic inventory; runtimes scale linearly with field count.

## Minimal Fallback

Without this tool: a two-column CSV (`field,level`) plus a grep for `email|token|secret|ssn` over the inventory, comparing hits against the CSV by hand. You lose rank semantics (a rule cannot say "at least confidential") and the unlabeled listing becomes a manual diff — but the CSV alone already beats a policy PDF nobody can query.

## Design Trade-offs

- **Glob patterns, not regex.** Shell globs are readable by non-engineers and cannot catastrophically backtrack; regex power is not needed for name-shaped rules.
- **Case-sensitive matching.** `*Email*` deliberately does not match `user.email` — silent case folding hides typos in rule files; make the rule say what you mean.
- **Unlabeled is advisory, not fatal.** Bootstrapping a classification effort on a legacy inventory fails immediately if every unlabeled field blocks CI; the listing is the ramp.
- **Ranks, not ordering-by-list-position.** Explicit integers survive JSON reordering and make `min_level` references legible in review.

## Limits & Second-order Effects

- Matching is by field *name* only; a field named `notes` can hold anything. Name rules are a heuristic floor, not content inspection.
- Teams may label everything `restricted` to silence violations, which destroys the value of ranking — watch for label inflation in review.
- The schema checks declarations, not enforcement: a correct label on a wrong ACL is still a leak. Pair it with access-control audits.
- Once integrated, the tool's clean exit code can become a rubber stamp; rotate the pattern rules as new sensitive field names appear.

## FAQ

**When NOT to use this?** If your platform already enforces classification at the storage layer (e.g. BigLake / Synapse security labels with mandatory policies), a second labeling artifact risks divergence — extend the platform's own instead. Also skip it for tiny single-owner datasets where a naming convention and one review suffice.

**Why does an unknown level fail but unlabeled does not?** A misspelled label is a correctness bug in the inventory file; an unlabeled field is an incomplete migration. The first is a bug, the second is a backlog — they get different exit codes.

**Can two fields with the same name in different tables differ?** Yes — labels are per inventory entry. Add table-qualified names (`orders.user_email`) if you need per-table granularity.

**Does it inspect file contents or connect anywhere?** No. It reads two JSON files you give it. There is no network code in the module.

## [Core Assumptions]

1. Sensitivity is a total order (ranks) for the organization in question; orgs with orthogonal compliance axes (e.g. GDPR vs PCI) need multiple runs with different schemas.
2. Field names carry enough signal for pattern rules to be useful; fully opaque names (`c1`, `c2`) defeat the mechanism.
3. The inventory file is generated or at least regenerable — a hand-maintained inventory drifts from the real schema within weeks.
4. Glob-level pattern expressiveness covers the common sensitive-name vocabulary (email, token, secret, ssn, salary, …).

Confidence: High (≥80%) for the mechanism (direct linting of declared artifacts) and rank semantics; Medium (60-79%) for pattern-rule coverage of real-world sensitive names and the single-order assumption. As of 2026-10-13.

---

Part of the [zhengming-toolbox](https://github.com/chenhz01/zhengming-toolbox) — 105 purpose-built AI-engineering tools across neglected niches.

Related tools: [file-permission-drift](https://github.com/chenhz01/file-permission-drift) · [cors-policy-validator](https://github.com/chenhz01/cors-policy-validator) · [cron-security-audit](https://github.com/chenhz01/cron-security-audit)
