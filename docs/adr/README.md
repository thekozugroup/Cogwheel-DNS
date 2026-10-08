# Architecture decision records

Decisions kept for the reasoning behind them, which is the part that is
expensive to recover later. A record here is not a plan — it describes a
boundary that is currently in force, and changing that boundary means amending
the record in the same change as the code.

| | |
|---|---|
| [0001 — Crate boundaries and ownership](0001-crate-boundaries.md) | Which crate owns what, why the DNS hot path depends on exactly one other crate, and the test that fails if the dependency graph drifts. |
| [0002 — AI review and the AI list](0002-ai-review-tier.md) | The owner's decision to admit an opt-in, off-by-default AI review, narrowing the old refusal of model classification: the model stays off the DNS path, its verdicts form a separate exact-name list below your rules, and the record says what leaves the house and when, how each verdict stays auditable, and what was rejected. |

[ARCHITECTURE.md](../ARCHITECTURE.md) is the readable version of the same
material; this directory is the record.
