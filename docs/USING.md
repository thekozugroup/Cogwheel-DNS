# Using Cogwheel

For everyone in the house, including the people who did not install it.

Cogwheel sits between your devices and the internet and answers the question
*"what address is this name at?"*. When the name belongs to something on one of
your blocklists, it answers with nothing, and the ad or tracker never loads. It
is not a virus scanner and it is not a firewall; it just declines to look up
certain names.

---

## Opening it

`http://<the address of the Cogwheel machine>:8080`

Whoever installed it has that address — the installer prints it at the end, and
it is the same address the router's DNS setting points at. It is a machine on
your own network, so there is no account and no password, and it is not
reachable from outside the house.

---

## Three things, and everything is one of them

- A **device** is a name you have given an address, so Activity says *"Kitchen
  tablet"* instead of `192.168.1.20`. A device can also have filtering switched
  off entirely, or be limited to a subset of the lists.
- A **list** is a blocklist the appliance subscribes to by URL and re-downloads
  on its own. Almost all of the blocking comes from lists.
- A **rule** allows or blocks one name — for everyone, or for one device. **A
  rule beats every list**, and a name covers its subdomains.

---

## The five screens

**Overview** — whether protection is on, how many queries were blocked, the top
queried and top blocked names of the last day, and the exact addresses to put in
a router.

**Activity** — every query as it happens, with the device that asked and whether
it was blocked. Turn *Live* off to read it; filter by device, verdict or name.
Each row's menu can allow or block that name, name the device that asked, or
answer **"Why?"** — which tells you exactly which rule or list decided.

**Devices** — give an address a name so it shows up by name everywhere else, and
optionally its own settings: filtering off, a chosen set of lists, and rules
that apply to it alone.

**Lists** — the blocklists (add one from the presets or by URL, turn it on or
off, delete it, refresh now), your household allow/block rules, and a box that
answers what would happen to a name right now.

**Settings** — a read-only summary of what is stored. Upstream servers, bind
addresses and retention are set by whoever runs the machine, in its environment
file, so the page reports them rather than offering a control that would not
stick.

The sidebar also has the **pause control** — 5, 15 or 60 minutes, with a
countdown — and the light/dark toggle. `⌘`/`Ctrl` and a digit jumps between
screens; `/` focuses the search box.

---

## Is it actually filtering my device?

Only devices whose DNS goes through Cogwheel are filtered, and the reliable way
to arrange that is once, on the router, in its DHCP settings — then every device
is covered, including the ones you cannot configure.

If some things are filtered and others are not, the usual cause is **IPv6**: a
device that has an IPv6 DNS server configured will ignore an IPv4-only setting
entirely. Both addresses have to be set. Whoever runs the machine will find that
in
[DEPLOYMENT §6](DEPLOYMENT.md#6-pointing-your-router-at-cogwheel).

The honest test is to open Activity and use the device in question. If its
queries appear, it is going through Cogwheel.

---

## Setting it up for the first time

1. **Add a list.** *oisd small* is the right first subscription — it blocks the
   large majority of advertising and tracking and breaks very little. *oisd big*
   blocks more and breaks more. A fresh install already subscribes to oisd
   small, so this may be done.
2. **Name the devices you care about**, on Devices.
3. **Leave everything else alone.** The defaults are chosen for a household.

---

## When a site breaks

DNS filtering breaks sites in two different ways and the fix is different, so
find out which one you have before spending time on it.

### 1. Pause, and see

Pause protection from the sidebar and reload the page.

- **It works while paused** → something the site needs is on a blocklist.
  Continue below.
- **It still fails** → the problem is not Cogwheel. Resume protection and look
  elsewhere.

That is thirty seconds and it saves the wrong half of the work.

### 2. Find what was blocked

Open **Activity**, set the verdict filter to *Blocked*, and reload the broken
page. What the site needed will appear in the list — usually a login provider, a
payment frame or a CDN that a blocklist maintainer included.

Then, from that row's menu, either:

- **Allow it** — for everyone, or just for that device. A rule beats every list,
  so this takes effect on the next query; you do not have to wait for anything.
- **Or turn off the list that supplied it**, on Lists, if it is causing more
  trouble than it is worth. Switching from oisd big to oisd small fixes a lot of
  this.

### If a name still will not resolve after you allow it

Your browser and your phone keep DNS caches of their own, and they do not know
you just changed your mind. Reload harder, or give it a minute.

---

## Names that can never be blocked

Twenty-one suffixes are protected: the lookups a device needs in order to stay
reachable at all — resolver bootstrap and captive-portal checks, time servers,
and the certificate-status endpoints that TLS depends on. Blocking those leaves
a device with no route back to working, with errors that point nowhere near DNS.
A clock that has drifted, in particular, fails TLS everywhere.

So: **a list that contains one of these is still installed and still used.** The
names it hit are recorded against it and shown in its Status column, and those
names keep resolving. You do not lose the rest of a list because it contained
one line you would not have chosen.

Your own block rule is the exception, and deliberately so. If *you* block one of
these knowingly, it stays blocked.

The set is short — 21 entries — on purpose. It does not reach broad domains like
operating-system vendors or banks: a blocklist entry covering those is a choice
someone made, and silently overruling it would be its own surprise.

---

## What is recorded, and for how long

Cogwheel keeps a log of every name every device looked up, for **seven days** by
default, along with hourly totals that outlive it. That is what makes Activity
and the Overview charts work, and it is worth knowing it exists: on a shared
network, anyone who can open the web UI can read what everyone else has been
looking at.

Whoever runs the machine can shorten that, or turn the per-query log off
entirely while keeping the charts —
`COGWHEEL_RETENTION__HISTORY_DAYS` in
[DEPLOYMENT §9](DEPLOYMENT.md#9-configuration-reference).

Nothing leaves the house except the lookups themselves, which go to the upstream
resolver, and the blocklist downloads. Cogwheel makes no other outbound
connection — no telemetry, and not even an update check.
