# Cogwheel Overhaul — Quality Rubric

This is the acceptance gate for the platform overhaul. Adversarial critique agents grade the
repository against **seven** dimensions, each scored `0–100`. Iteration continues until **every
dimension scores 100**.

A dimension scores 100 only when **every** check in it passes. There is no partial credit for a
check: a check is `pass` or `fail`. The dimension score is `round(100 * passed / total)`.

Critics are instructed to be **adversarial**: assume the implementer cut corners, and go looking for
the corner. A critic that reports 100 without having run the verification commands has failed at its
own job. Every failing check must cite `file:line` and describe a concrete, reproducible defect.

---

## D1 — Correctness & Build Integrity

| # | Check |
|---|---|
| 1.1 | `cargo fmt --all -- --check` exits 0 |
| 1.2 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` exits 0 |
| 1.3 | `cargo test --workspace` exits 0, and the suite contains tests for every new module |
| 1.4 | `npm run build` in `apps/cogwheel-web` exits 0 (includes `tsc --noEmit`) |
| 1.5 | `npm run lint` in `apps/cogwheel-web` exits 0 |
| 1.6 | No `unwrap()`, `expect()`, `panic!`, `todo!`, `unimplemented!`, or `dbg!` in non-test Rust code |
| 1.7 | No `any` types, `@ts-ignore`, or `eslint-disable` added to silence real errors in the web app |
| 1.8 | The server binary starts, serves the SPA, and every route the UI calls exists on the server |
| 1.9 | No dead code: every exported symbol is reachable; no orphaned files left from the old UI |
| 1.10 | No placeholder/mock data rendered in the UI where real API data is expected |

## D2 — Design System Fidelity

Graded against the user's verbatim requirements.

| # | Check |
|---|---|
| 2.1 | UI is built on Shark UI (`shark.vini.one`) components, installed from its registry — not hand-rolled lookalikes |
| 2.2 | Tailwind CSS v4 is in use (CSS-first `@theme`, `@tailwindcss/vite`); no v3 `tailwind.config.ts` remains |
| 2.3 | Inter is the core font, **self-hosted** (no Google Fonts / CDN `<link>` anywhere) |
| 2.4 | Base palette is black/white/neutral only — no chromatic hues in the base theme |
| 2.5 | Exactly three accents, bound to Tailwind **400** values: `red-400`, `yellow-400`, `green-400` |
| 2.6 | Accents are used **only** for status/warning/indication, never as decoration or brand colour |
| 2.7 | Shark's default chromatic tokens (`red-500`, `emerald-500`, `amber-500`, `blue-500`, chart hues) are overridden to comply with 2.4–2.6 |
| 2.8 | A persistent sidebar is the primary navigation |
| 2.9 | Apple-esque restraint: generous whitespace, hairline borders, minimal shadow, restrained motion, clear type hierarchy |
| 2.10 | Light and dark themes both fully specified; no unstyled or contrast-broken surface in either |

## D3 — UX Quality

| # | Check |
|---|---|
| 3.1 | Every screen has explicit loading, empty, error, and populated states |
| 3.2 | Every destructive action has a confirmation naming the exact target |
| 3.3 | Every mutation gives feedback (toast or inline) on success **and** failure |
| 3.4 | Keyboard navigation works throughout; visible focus ring on every interactive element |
| 3.5 | Keyboard shortcuts (⌘/Ctrl+1..5, `/` to focus search) reach every screen and the screen's search field |
| 3.6 | Responsive down to 375px; sidebar collapses correctly; no horizontal body scroll |
| 3.7 | `prefers-reduced-motion` is honoured |
| 3.8 | Status is never conveyed by colour alone — always paired with icon and/or text |
| 3.9 | No user-facing jargon without explanation; every non-obvious control has help text |
| 3.10 | No screen exposes a control for a capability the server no longer has |

## D4 — Performance & Raspberry Pi 5 Fitness

| # | Check |
|---|---|
| 4.1 | A cache hit performs no upstream I/O and no policy evaluation — verified by reading `handle_wire_query`, not by claim |
| 4.2 | Cached answers honour record TTLs within the documented floor and ceiling, asserted by a test |
| 4.3 | A blocklist body larger than `MAX_SOURCE_BODY_BYTES` is rejected before it is parsed |
| 4.4 | The DNS hot path never blocks on a blocklist fetch, a storage write or an event-stream subscriber — verified by reading the code path |
| 4.5 | Event-stream fan-out is bounded (subscriber cap, per-subscriber buffer) with an explicit, documented drop policy under backpressure |
| 4.6 | A dead or slow upstream cannot stall cache hits or blocked answers |
| 4.7 | Web bundle is served gzipped/precompressed; initial JS payload is documented and reasonable |
| 4.8 | No unbounded in-memory growth (caches have explicit capacity/TTL) |
| 4.9 | Builds and runs on `linux/arm64`; no x86-only intrinsics or assumptions |
| 4.10 | Measured numbers are recorded in docs, with the measurement method stated |

## D5 — Filtering Safety

| # | Check |
|---|---|
| 5.1 | The protected suffixes (`cogwheel_policy::PROTECTED_SUFFIXES`) are documented with the reason each is there |
| 5.2 | Protection matches on a label boundary — subdomains covered, look-alikes not — asserted by a test |
| 5.3 | A protected domain outranks every subscribed block rule, asserted by a test |
| 5.4 | A candidate ruleset that would block a protected name is refused before activation and the policy in force keeps serving, asserted by a test |
| 5.5 | A source whose invalid-line ratio exceeds its strictness threshold fails verification, asserted by a test |
| 5.6 | Adblock modifier, path and regex rules are rejected rather than approximated |
| 5.7 | An allow rule beats a block rule regardless of source order, asserted by a test |
| 5.8 | Pausing protection answers every name unfiltered and resumes without a restart |
| 5.9 | A device marked `bypass` receives unfiltered answers, and a device allow-list entry wins over its profile |
| 5.10 | The block response mode is one of the four documented modes and applies to every blocked name |

## D6 — Deployment & Operability

| # | Check |
|---|---|
| 6.1 | Dockerfile uses dependency-layer caching and pinned base image versions |
| 6.2 | Multi-arch (`linux/amd64` + `linux/arm64`) image build is wired in CI |
| 6.3 | CI builds, typechecks, and lints the **web app** (it currently does not) |
| 6.4 | A one-line installer exists, is idempotent, and detects/resolves the port-53 conflict with `systemd-resolved` |
| 6.5 | Installer supports uninstall and rollback |
| 6.6 | A hardened systemd unit exists for native installs |
| 6.7 | Release automation publishes versioned, checksummed artifacts |
| 6.8 | Liveness and readiness endpoints are distinct and documented |
| 6.9 | Graceful shutdown drains in-flight queries |
| 6.10 | Exactly one deployment guide; no personal hostnames/usernames anywhere in the repo |

## D7 — Security, Robustness & Maintainability

| # | Check |
|---|---|
| 7.1 | `cargo audit` and `cargo deny check` pass |
| 7.2 | All external input (API bodies, blocklist payloads, config) is validated with bounded sizes |
| 7.3 | No secrets, tokens, or credentials committed; none logged |
| 7.4 | Errors are handled explicitly; no silent `let _ =` on fallible operations that matter |
| 7.5 | Malformed/hostile blocklist content cannot crash or hang the server |
| 7.6 | SSE/streaming endpoints have connection limits and clean teardown |
| 7.7 | Crate boundaries respected; no layering violations |
| 7.8 | Public APIs documented; non-obvious logic explained by comments that say *why* |
| 7.9 | Docs match reality — every documented command and endpoint actually works |
| 7.10 | Repo is clean: no stray build output, scratch files, or dead config |

---

## Verification commands

Critics must run these and paste real output. A dimension cannot be scored 100 on inspection alone
where a command exists to prove it.

```bash
cd /home/user/Cogwheel-DNS
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo audit
cargo deny check

cd apps/cogwheel-web
npm run build
npm run lint
```

## Scoring report format

Each critic returns, per dimension: the score, the list of failed check IDs, and for each failure a
`file:line` citation plus a one-sentence reproducible defect description. Critics do not fix
anything — they only report. A separate remediation pass applies fixes, then the critics re-grade
from scratch.
