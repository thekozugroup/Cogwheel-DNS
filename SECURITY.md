# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's [Security
Advisories](https://github.com/thekozugroup/Cogwheel-DNS/security/advisories/new), which opens a
thread visible only to the maintainers.

Include what an attacker can do and what they need to already have (a device on the LAN? a
browser on a device on the LAN? control of a blocklist you subscribe to?), steps to reproduce —
`COGWHEEL_PROFILE=dev` binds `127.0.0.1:30080` and `127.0.0.1:30053`, so nothing on a real
network has to be touched — and the image tag or commit you tested.

You can expect an acknowledgement, then either a fix or an explanation of why it is working as
intended, and credit in the release notes unless you would rather not have it. Please give a
reasonable window before disclosing publicly.

Read the rest of this file before reporting. The four properties below are the ones most
likely to be reported, and all four are deliberate — Cogwheel is a household appliance on a
LAN, and its threat model says so out loud rather than implying otherwise by silence.

## Supported versions

Cogwheel is pre-1.0. Fixes land on `main` and go out in the next release; there are no backported
patch branches yet.

| Version | Supported                     |
| ------- | ----------------------------- |
| 0.1.x   | Yes                           |
| < 0.1   | No — there is nothing earlier |

## Four things to know before you report

**The control plane has no authentication.** There is no login, no token and no session. The HTTP
stack that serves the API and the web UI applies compression and request tracing and nothing else
— read the end of `app()` in `apps/cogwheel-server/src/http.rs` and you have seen the whole of
it. On the default `home` profile it binds `0.0.0.0:8080`, so anyone who can reach the
box on your network can change what is filtered for the whole household, read the query log, and
pause protection. This is a documented property, not a vulnerability: Cogwheel is built for a
home LAN, where the device that answers DNS is trusted by everything on the network anyway.

If your LAN is not a trust boundary you can rely on, set
`COGWHEEL_SERVER__HTTP_BIND_ADDR=127.0.0.1:8080` and put a reverse proxy that does
authentication in front of it, or keep the bind and put a firewall rule in front instead. There
is also no `Host` header check on the control plane in general, which matters because it means a
page on the internet can point a name at your appliance's address and have your own browser talk
to it. The one exception is AI review's routes, below. Treat `:8080` as something to keep off the
open internet, not as something defended.

A report that `:8080` is unauthenticated will be closed as working-as-intended. A report that
something reaches it from outside the interface it is bound to, or that a request escapes the
static file root, will not.

**The resolver answers any client that can reach port 53.** There is no client ACL. A query's
source address chooses which device's policy applies, not whether the query gets an answer at
all. On a home network that is exactly right. An instance whose port 53 is reachable from the
internet is an **open resolver** — usable to amplify traffic at somebody else, and worth someone
else's attention long before it is worth yours. Do not forward port 53 from your router.

**The query log is the most sensitive thing on the box.** Its rows are a timestamp, the client's
IP address, the name that was looked up, whether it was blocked and which list decided —
`query_log` in `crates/cogwheel-storage/src/schema_v1.sql`. That is a record of what everyone in
the house looked at, kept for 7 days and capped at 250,000 rows by default.
`COGWHEEL_RETENTION__HISTORY_DAYS=0` switches the raw log off entirely and keeps only the hourly
per-device counts, which are numbers rather than browsing history.

Read a log or a screenshot before you paste it into an issue. It is more revealing than the
equivalent output from most software.

**AI review sends names out, and holds the one secret on the box.** It is off by default
([ADR 0002](docs/adr/0002-ai-review-tier.md) is the whole design). Once someone adds an
OpenRouter key and turns it on:

- **What leaves.** For each name a website loads that has not been judged recently, one request
  to OpenRouter — and through it to the company that runs the chosen model — carrying that name,
  the website the load is taken to be for, and up to 24 other names from the same load. Never a
  client address, the name a device has in Cogwheel, a query type or a timestamp, and never a name
  a household rule covers, the appliance's own names, a name under a private-use or router suffix
  (`.lan`, `.local`, `.home.arpa`, `fritz.box`, `speedport.ip` and the rest of
  `site::PRIVATE_SUFFIXES`), a name under a wildcard-address, tailnet or dynamic-DNS service
  (`nip.io`, `sslip.io`, `ts.net`, `duckdns.org`, `synology.me` and the rest of
  `site::HOME_SUFFIXES`), or a name with a dotted or dashed IPv4 address or an identifier-like
  label in it. A name under any other domain is sent whether or not it resolved, so a household
  domain Cogwheel cannot recognise — a router's own local domain, a split-horizon name, a
  dynamic-DNS name of another provider — goes out unless a household rule covers it; give it one
  (allow is the usual). Every request asks for providers that do not collect data, and by
  default for zero data retention; Cogwheel cannot check that they comply. Turning review off, or
  removing the key, closes the send gate before the request that did it answers.
- **The key.** It lives in `openrouter.key` beside the database, mode 0600 — never in SQLite, so
  never in a `.pre-v2` copy, a `VACUUM INTO` backup or the WAL. No route returns it or any part of
  it, nothing logs it, and the browser never caches it; OpenRouter's `label` for a key is a masked
  copy of the key, so it is never read or forwarded either. `COGWHEEL_AI__OPENROUTER_API_KEY` wins
  over a key saved in the UI. Where requests go, `COGWHEEL_AI__BASE_URL`, is environment-only, and
  the client follows no redirects, so neither the key nor the names can be sent somewhere else from
  the network.
- **The guard.** The AI routes that write, spend, make the appliance fetch something or touch the
  key refuse a request unless every name it was addressed to — the `Host` header and the request
  line's authority — is an IP address, `localhost`, a single label, a `.local`/`.lan`/`.home`/
  `.home.arpa`/`.internal`/`.localdomain` name or one in `COGWHEEL_SERVER__ALLOWED_HOSTS`; its
  `Origin`, if any, is the appliance itself; and its `Sec-Fetch-Site` is not `cross-site`. That is
  what stops a DNS-rebinding or cross-site page from saving its own key through a household
  browser, spending credit or wiping the AI list. What it does not stop: an old browser that sends
  neither `Origin` nor `Sec-Fetch-Site` can still make the appliance fetch OpenRouter's public
  model list, which carries no key and no household data and is cached for an hour.
- **Anyone on the LAN who can reach the control plane can replace a key saved in the UI**, and
  receive the household's names from then on in their own OpenRouter account. That is the
  unauthenticated control plane above, applied to a new thing. The mitigations are a key in the
  environment (which the UI cannot change), `COGWHEEL_AI__AVAILABLE=false`, and a credit limit on
  the key at OpenRouter.
- **Prompt injection.** Domain names are attacker-chosen text, so they only ever appear as JSON
  values in the request's `state`; the instructions are constants that say words in a name are
  not evidence and never instructions, and decision models return a typed choice and a confidence
  — no text to follow, no tools. Verdicts are exact-name, below every rule and the protected
  suffixes, and overriding a list needs two answers above a high bar. **Residual risk:** on a
  hostile site, a list-blocked tracker named convincingly as that site's own CDN can win an allow
  in that site's context. It is household-wide but for that exact name only, one of at most 20 a
  day, visible in the AI list's Changes, withdrawn if another site's context calls it a tracker,
  and one click to undo.
- **Credit exhaustion.** A flood of random names cannot spend without bound: each name is asked
  about once, at most 24 per site load, 60 per site per day and 300 per client per hour, at most
  2,000 requests a day, two at a time, within the household's daily limit (5¢ to $1) — and the
  key's own credit limit at OpenRouter holds even if Cogwheel is wrong.
- **The AI list is the second most sensitive thing on the box.** Its rows are names the
  household's websites loaded and, until `HISTORY_DAYS` passes, which website loaded them. Like
  the query log, anyone who can reach the control plane can read it. Rows that only left a name
  to the lists live `min(30 days, HISTORY_DAYS)`, blocks and allows up to 90 days, and Clear log
  forgets the websites and the left-to-the-lists rows with the log. The exception is a name two
  websites disagreed about (contested): it is kept like a block or allow, up to 90 days after it
  was judged, and Clear log removes its websites but not the row.

## In scope, and genuinely wanted

- Anything that changes policy or reads the log from outside the interface the control plane is
  bound to.
- Anything that makes a **subscribed list take down a protected name**. The
  [`PROTECTED_SUFFIXES`](crates/cogwheel-policy/src/lib.rs) — resolver bootstrap, captive-portal
  checks, NTP, certificate status — are enforced when a query is evaluated, so a list containing
  one is accepted and harmless. A path that bypasses that check is a real bug.
- Cache poisoning: any way to get an answer into the cache that the upstream did not send, or to
  have one scope's answer served to another.
- A crafted DNS message, blocklist body or API request that panics the process, wedges the
  resolver, or consumes memory without bound. The appliance failing is the household losing DNS.
- A path traversal or escape in the static file handler, or in the on-disk list body cache.
- Anything that writes outside the data directory, or that runs as anything other than uid 10001.
- A DNS-over-TLS or DNS-over-HTTPS upstream connection that is established without the
  certificate being validated against the configured name.
- AI review: any path that returns or logs the key or any part of it, including OpenRouter's
  masked `label`; a domain name logged by the reviewer, the OpenRouter client or the AI routes; a
  way past the guard on the AI routes; a queue, map or spend that grows without bound; a request
  to OpenRouter that starts after review was turned off or the key removed; a request that carries
  a client address, a device name or a name that should not have been shareable; and an AI-list
  verdict that overrides a protected name or one of your rules.

## Out of scope

- The four properties above, as properties. The mitigations are the answer, not a patch.
- A single wrong verdict from the model. It is a model's opinion, visible in the AI list with
  the model's confidence and undone in one click; a *way to cause* wrong verdicts that gets past
  the bounds above is in scope.
- Missing DNSSEC validation. Cogwheel is a DoT/DoH **client**, not a validating resolver; see
  the known limitations in [CHANGELOG.md](CHANGELOG.md).
- A device that ignores the resolver — a hardcoded DNS server, or DNS-over-HTTPS inside a
  browser. Cogwheel cannot filter a query it never sees, and says so.
- Reports generated by a scanner with no demonstrated path to an effect on this codebase.
