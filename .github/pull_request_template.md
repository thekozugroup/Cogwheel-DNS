<!--
CONTRIBUTING.md has the long version of all of this. The four headings below are the four
things a reviewer needs and cannot get from the diff on its own.

Delete any section that genuinely does not apply — an empty heading is worse than no heading.
-->

## What changed and why

<!--
The "why" is the expensive part to recover later, so spend the words there. Link the issue if
there is one: "Fixes #123".
-->

## How I know it works

<!--
Paste real output, not a claim about it. `sh scripts/verify.sh` is the whole gate — the same
checks CI runs, in the same order — and `sh scripts/verify.sh --list` prints them without
running anything.

A false green is worse than a known gap — if part of this is untested, or you could not verify
something in your environment (no aarch64 host, no spare box to point a router at), say so
plainly here. That is not a mark against the PR.
-->

```
$ sh scripts/verify.sh

```

## Screenshots

<!--
UI changes only. Light and dark — the app ships a theme toggle and a pre-paint theme script, so
a change checked in one theme is a change checked half the time. Include both states of anything
that has states: loading, empty, error, and the thing actually populated.
-->

## What I decided not to do

<!--
Often the most useful part of the description: the alternative you rejected, the edge case you
left, the follow-up this makes possible. Write it down while you still remember it.
-->

---

- [ ] `sh scripts/verify.sh` passes, with nothing skipped that CI will run — `cargo audit` and
      `cargo deny check` in particular, which skip themselves when the tool is not installed
- [ ] If a dependency moved, `cargo audit` was run against the new `Cargo.lock`
- [ ] Comments explain _why_, not _what_ — matching the surrounding code
- [ ] `docs/spec-dnsnet-plus-four.md` is amended in the same PR if routes, schema or precedence changed
- [ ] No new dependency, or the description says what it does that the existing surface cannot
- [ ] Nothing here claims a status the code cannot actually verify

<!--
Three boundaries that are permanent, so a PR crossing one will be pushed back regardless of how
good the code is:

  • No list may take down a protected name. Protection is enforced when a query is evaluated,
    and a rule the operator wrote outranks both the lists and the protected set —
    crates/cogwheel-policy/src/lib.rs.
  • Nothing allocates on the DNS hot path. Enforced by the counting-allocator test, not by
    review — docs/ARCHITECTURE.md, "What the hot path may not do".
  • A crate's path dependencies must match the ADR graph. Enforced by
    `crate_path_dependencies_match_the_adr_boundaries` in apps/cogwheel-server/src/tests/mod.rs
    — docs/adr/0001-crate-boundaries.md.
-->
