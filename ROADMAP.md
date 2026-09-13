# Cogwheel Scope

Cogwheel is a DNS filtering appliance for a household network: one Rust binary
(`apps/cogwheel-server`) that serves DNS on port 53, applies subscribed
blocklists, and hosts a small React control plane on port 8080. It is built for
a Raspberry Pi 5 and runs on any 64-bit Linux host, natively or in the
published container image.

What it does:

- Resolves and caches DNS for every device on the LAN, honouring record TTLs.
- Blocks names on subscribed lists (`domains`, `hosts` and Adblock syntax), with
  a fixed set of protected infrastructure names that no list may take down.
- Refreshes lists on a schedule and refuses a candidate that fails verification
  or would block a protected name; the policy already in force keeps serving.
- Lets a device be named and given its own profile, allow-list or bypass.
- Shows live queries and resolver counters in the web UI, and can pause blocking.

What it deliberately does not do: machine-learning classification, threat
feeds, multi-node sync, VPN or exit-node integration, notifications, a backup
API, soak-testing tooling, or a metrics exporter. `/api/v1/runtime` and
`/health/*` are the operational surface. The pre-cut tree that had those
features is preserved on the `archive/full-featured` branch.
