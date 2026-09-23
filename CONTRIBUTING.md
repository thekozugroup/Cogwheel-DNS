# Contributing to Cogwheel

Issues and pull requests are welcome. This file covers getting a working
checkout, running the appliance and the web app, the checks that have to pass
before you open a pull request, and where the contracts live — because this
repository has a written contract and a change that disagrees with it is a bug
in one of the two.

- [Setup](#setup)
- [Running it](#running-it)
- [The checks](#the-checks)
- [The repository](#the-repository)
- [Commits and pull requests](#commits-and-pull-requests)
- [What will get pushed back](#what-will-get-pushed-back)
- [Where the contracts live](#where-the-contracts-live)

---

## Setup

You need **Rust 1.97.0** and **Node 22**.

The Rust version is not a suggestion. `rust-toolchain.toml` pins it, and
`rustup` will install and select that exact toolchain the first time you run
`cargo` in this directory — you do not have to do anything, but you do have to
not fight it. The pin is load-bearing: with a floating `stable`, a Rust release
adds new Clippy lints and CI turns red on a commit that changed nothing related
to them, on a day nobody touched the repository. That happened here, and using
`@stable` in CI instead of the pin is what made the workflow fail on eight
consecutive commits.

You do **not** need Docker to develop, and you do not need it to run the tests.

```bash
git clone https://github.com/thekozugroup/Cogwheel-DNS.git
cd Cogwheel-DNS

cargo build                                  # installs the pinned toolchain on first run
npm --prefix apps/cogwheel-web ci
```

`npm ci`, not `npm install` — the lockfile is the contract and CI installs from
it.

There is no `.env` to write. Everything is environment variables read by the
server itself, the `dev` profile supplies loopback defaults for all of them, and
[`.env.example`](.env.example) documents the full set with the reasoning behind
each default. It is the best-written file in the repository; read it once.

---

## Running it

### The appliance

```bash
COGWHEEL_PROFILE=dev cargo run -p cogwheel-server
```

`dev` binds `127.0.0.1:30080` for HTTP and `127.0.0.1:30053` for DNS, and
refreshes blocklists hourly instead of daily. No privileged ports, nothing
listening on an interface anyone else can reach.

```bash
curl -s http://127.0.0.1:30080/health/ready
# {"data":{"status":"ready","subsystems":{"storage":true,"policy":true,"dns_listeners":true}}}

dig @127.0.0.1 -p 30053 example.com +short
```

A fresh database subscribes itself to one list — oisd small — and downloads it
on first boot, so you get a realistic ruleset (around 57,000 rules) without
doing anything. The data directory it writes is relative to
`COGWHEEL_STORAGE__DATABASE_URL`; point that somewhere disposable if you would
rather not have `data/` in your checkout.

### The web app

```bash
cd apps/cogwheel-web
npm run dev          # http://localhost:5174
```

Two things about that address, both of which have cost someone an afternoon:

- **It is `:5174`, not `:30080`.** Vite proxies `/api` through to
  `http://127.0.0.1:30080`, so the dev UI is same-origin with the API and there
  is no CORS to configure. `:30080` is the Rust server serving the *built*
  bundle, which is what an installed appliance does — useful, but not the thing
  with hot reload.
- **The proxy target is a variable.** `VITE_COGWHEEL_API_TARGET` repoints it, so
  you can drive a real appliance from a local UI:

  ```bash
  VITE_COGWHEEL_API_TARGET=http://cogwheel.local:8080 npm run dev
  ```

  `VITE_COGWHEEL_API_BASE` is a different thing again: it sets the base the API
  client in `src/lib/api.ts` builds request URLs from, for a build that is
  served from somewhere other than the API's own origin. You almost certainly
  want the first one.

---

## The checks

```bash
sh scripts/verify.sh
```

**That script is the canonical list.** It runs what `.github/workflows/ci.yml`
runs, in the order CI runs it, and every other document in the repository names
the script rather than restating the commands — four copies is how they end up
disagreeing with each other and with CI. `sh scripts/verify.sh --list` prints
the commands, from the same code path that executes them, so you can lift one
out and run it on its own.

It stops at the first failure; `--keep-going` runs everything and reports at the
end, which is what you want just before opening a pull request.

Three of the checks are not always available, and each one reports itself as
**skipped** rather than passed. A skip is never a pass — CI has all three.

```bash
cargo install cargo-audit --locked    # the advisory scan
cargo install cargo-deny --locked     # licences and duplicate dependencies
```

The third is `docker buildx build --check .`, which needs a Docker daemon CI has
and a laptop may not.

Three details in that list are the difference between a green local run and a
red CI:

| | |
|---|---|
| `-- --check` on `fmt` | without it, `cargo fmt --all` *rewrites* your files and exits 0. It has told you nothing. |
| `-D warnings` on `clippy` | CI fails on a warning. A local run without this flag passes on code CI will reject. |
| `--locked` on the release build | it fails rather than silently updating `Cargo.lock`. A lockfile change should be a deliberate commit. |

`npm run build` runs `tsc --noEmit` before Vite, so it is the typecheck as well
as the build.

CI also runs things you cannot easily run locally and should know exist: an
aarch64 cross-compile (the Raspberry Pi target), a container that must **refuse
to start** without `CAP_NET_BIND_SERVICE`, an end-to-end DNS and web check
against the built image, an in-place upgrade of a v0 database, and a check that
a database from a *newer* Cogwheel is refused with a message naming both schema
versions.

### About the tests

**173 of them, and they are real** — no mocked resolver, no fake database.

| Crate | Tests | What they are |
|---|---|---|
| `cogwheel-server` | 69 | routes driven through the real router against a real SQLite file |
| `cogwheel-dns-core` | 40 | wire parsing, the cache and its TTL clamps, CNAME re-check, upstream selection |
| `cogwheel-storage` | 30 | the schema, the v0→v1 upgrade, paging, retention bounds |
| `cogwheel-policy` | 21 | the precedence order, the protected-suffix net, normalisation |
| `cogwheel-lists` | 13 | the three list grammars, conditional GET, verification |

The whole suite finishes in under a second of test time. There is no excuse for
not running it.

A new feature comes with tests. A bug fix comes with the test that fails without
it. Two kinds of test in here are guards rather than coverage, and they fail on
purpose if you cross a line:

- `crate_path_dependencies_match_the_adr_boundaries` reads each crate's manifest
  and fails if the dependency graph drifts from
  [ADR 0001](docs/adr/0001-crate-boundaries.md).
- `hot_path_crates_remain_llm_and_network_independent` fails if
  `cogwheel-dns-core` gains an HTTP client or a model-API dependency.

If one of those fails, the fix is usually not the test.

---

## The repository

```
crates/cogwheel-policy    The rule model and `evaluate` — the seven-tier precedence,
                          the 64-slot list bitmask, domain normalisation, and the
                          21 protected suffixes. Pure: no I/O, no path dependencies.
                          Everything that filters is built on this.
crates/cogwheel-dns-core  The UDP and TCP listeners, request parsing, the TTL-aware
                          response cache, CNAME uncloaking, upstream forwarding
                          (cleartext, DoT, DoH), the pause switch, the counters.
                          Depends on cogwheel-policy and nothing else.
crates/cogwheel-lists     Fetching and parsing blocklists — `domains`, `hosts` and
                          Adblock syntax — plus verification. Talks HTTP, so it is
                          never on the DNS path.
crates/cogwheel-storage   The SQLite schema, the guarded v0→v1 upgrade, the
                          repositories and the retention prune. Schema details stay
                          inside it; nothing else writes SQL.
apps/cogwheel-server      The composition root: configuration, the 22 routes, the
                          response envelope, the readiness tracker, the refresh
                          scheduler, the event stream. The only crate that depends
                          on all four libraries.
apps/cogwheel-web         React 19 + Vite + Tailwind 4 on Shark UI. Five pages.
                          Talks to the server only through `src/lib/api.ts`.
docs/                     Quick start, deployment, architecture, design, releasing,
                          and the spec that is the contract.
scripts/                  verify.sh (the gate), install.sh, install-native.sh,
                          verify-install.sh, check-update.sh, pi-acceptance.sh,
                          and the bench harness.
```

Dependencies flow one way and the graph is deliberately small:
`cogwheel-policy` knows about nothing, `cogwheel-dns-core` and `cogwheel-lists`
know only about `cogwheel-policy`, `cogwheel-storage` knows about nothing, and
the server composes all four. [ARCHITECTURE.md](docs/ARCHITECTURE.md) explains
why, and a test enforces it.

---

## Commits and pull requests

### Commits

Present tense, imperative, and about the change rather than about the process.
The "why" is the expensive part to recover later, so spend the words there.

```
Stop top_domains full-scanning the query log

The Overview page's top-ten queried and top-ten blocked were computed with a
GROUP BY over every row within the retention window — 250,000 of them at the
default cap — on every page load. The hourly rollup table already holds the
same aggregate, so read it instead. On a 250k-row log this is 480 ms to 3 ms.
```

`fix stuff`, `wip` and `address review` tell a future reader nothing.

### Pull requests

1. **What changed and why.** Link the issue if there is one.
2. **How you know it works.** Paste the real output, not a claim about it. A
   false green is worse than a known gap — if something is untested, or you
   could not verify it in your environment, say so. That is not a mark against
   the PR.
3. **Screenshots for UI changes.** Light and dark, and every state that has one:
   loading, empty, error, and the thing actually populated.
4. **Numbers for anything on the DNS path.** See below.
5. **What you decided not to do**, and why. Often the most useful part.

Keep them focused. A troubleshooting entry, a bug fix and a refactor are three
pull requests.

---

## What will get pushed back

- **A network call, a storage write or a model API on the DNS request path.**
  `cogwheel_policy::evaluate` is pure, the cache and the counters are in memory,
  and the only network call a query may make is to the configured upstream. A
  test in `cogwheel-dns-core` fails if the crate's manifest gains an HTTP client
  or an LLM dependency. New cloud-backed or AI-assisted ideas belong in
  off-path control-plane code, if anywhere.

- **A hot-path change without a measurement.** `scripts/bench/run.py` exists and
  documents its own measurement bugs; use it. "Should be faster" is not a
  number, and a 5 µs difference inside a 45 µs client round trip is inside the
  harness's own floor — [the spec's §12.3](docs/spec-dnsnet-plus-four.md)
  explains how to read it without fooling yourself.

- **A new user-facing setting.** The UI contract is deliberately small: five
  pages, and Settings is read-only. A setting is a promise to support a
  combination forever. Most proposed settings are a default someone disagrees
  with, and the right change is usually the default.

- **A change to the crate dependency graph without an ADR.** Update
  [ADR 0001](docs/adr/0001-crate-boundaries.md) first, then the guard test, then
  the code, in the same change.

- **An accent colour used as an action, or colour as the only signal.** Red,
  yellow and green name a *state*, never a control, and a status is always a
  word as well as a dot. [DESIGN.md](docs/DESIGN.md) is what UI changes are
  reviewed against.

- **A status the code cannot verify.** A green tick that means "we did not
  check" is worse than no tick. The appliance reports "unknown" and "not yet
  ready" in several places precisely because those are the honest answers.

- **Behaviour that disagrees with the spec**, without the spec changing in the
  same pull request. See below.

---

## Where the contracts live

| Document | What it decides |
|---|---|
| [`docs/spec-dnsnet-plus-four.md`](docs/spec-dnsnet-plus-four.md) | **The contract.** Every route and its shape, the schema and its migration, the precedence order, the per-device model, the query log, the configuration surface. If the code and this file disagree, one of them is a bug — decide which, and fix that one. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How a query becomes an answer, why the crates are split where they are, and — §1 — what Cogwheel deliberately is not. Read §1 before proposing a feature. |
| [`docs/DESIGN.md`](docs/DESIGN.md) | The visual contract: the palette and its three hues, the single gutter, the component set, the accessibility floor. **UI changes are reviewed against this.** |
| [`docs/adr/`](docs/adr/) | Decisions with reasons, kept because the reasoning is what is expensive to recover. |
| [`.env.example`](.env.example) | Every environment variable, its default, and why that is the default. |

Behaviour changes update the spec in the same pull request. Operator-facing
changes update [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md); anything that changes what a
household member sees updates [docs/USING.md](docs/USING.md); anything worth
knowing before upgrading goes in [CHANGELOG.md](CHANGELOG.md) under
`## [Unreleased]`.

Security issues go through [SECURITY.md](SECURITY.md), never a public issue.
