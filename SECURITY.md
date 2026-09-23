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

Read the rest of this file before reporting. The three properties below are the ones most
likely to be reported, and all three are deliberate — Cogwheel is a household appliance on a
LAN, and its threat model says so out loud rather than implying otherwise by silence.

## Supported versions

Cogwheel is pre-1.0. Fixes land on `main` and go out in the next release; there are no backported
patch branches yet.

| Version | Supported                     |
| ------- | ----------------------------- |
| 0.1.x   | Yes                           |
| < 0.1   | No — there is nothing earlier |

## Three things to know before you report

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
is also no `Host` header check, which matters because it means a page on the internet can point a
name at your appliance's address and have your own browser talk to it. Treat `:8080` as something
to keep off the open internet, not as something defended.

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

## Out of scope

- The three properties above, as properties. The mitigations are the answer, not a patch.
- Missing DNSSEC validation. Cogwheel is a DoT/DoH **client**, not a validating resolver; see
  the known limitations in [CHANGELOG.md](CHANGELOG.md).
- A device that ignores the resolver — a hardcoded DNS server, or DNS-over-HTTPS inside a
  browser. Cogwheel cannot filter a query it never sees, and says so.
- Reports generated by a scanner with no demonstrated path to an effect on this codebase.
