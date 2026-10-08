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

## Four things, and everything is one of them

- A **device** is a name you have given an address, so Activity says *"Kitchen
  tablet"* instead of `192.168.1.20`. A device can also have filtering switched
  off entirely, or be limited to a subset of the lists.
- A **list** is a blocklist the appliance subscribes to by URL and re-downloads
  on its own. Almost all of the blocking comes from lists.
- A **rule** allows or blocks one name — for everyone, or for one device. **A
  rule beats every list and the AI list**, and a name covers its subdomains.
- The **AI list** is empty unless your household turns on AI review. It holds
  the names a decision model judged differently from your lists — blocks they
  missed, and allows that lift a list's block that broke a site — for exact
  names only. It sits below your rules and above every list.
  [AI review](#ai-review-if-your-household-turns-it-on) below says how it works.

---

## The five screens

**Overview** — first, in one line, whether the household is protected right
now, and when it is not, the one thing to press. Then how many queries were
blocked, the top queried and top blocked names of the last day, and the exact
addresses to put in a router.

**Activity** — every query as it happens, with the device that asked and whether
it was blocked. It stays live, but while you are reading or pointing at the
list, new queries wait above it behind *Show N new* instead of pushing it down;
turn *Live* off to hold everything. Filter by device, verdict or name; the
filters are in the page's address, so a filtered log can be bookmarked or
linked.
Each row's menu can allow or block that name, name the device that asked, or
answer **"Why?"** — which tells you exactly which rule or list decided.

**Devices** — give an address a name so it shows up by name everywhere else, and
optionally its own settings: filtering off, a chosen set of lists, and rules
that apply to it alone.

**Lists** — the blocklists (add one by how much it blocks — *Light*,
*Balanced* or *Strict* — or any list by its address; turn it on or off, delete
it, refresh now), the AI list and its set-up, your household allow/block rules
alongside each device's own (adding or removing one can be undone from the
notice that confirms it), and a box that answers what would happen to a name
right now.

**Settings** — a read-only summary of what is stored. Upstream servers, bind
addresses and retention are set by whoever runs the machine, in its environment
file, so the page reports them rather than offering a control that would not
stick. It shows AI review read-only too; AI review is set up on Lists, beside
the AI list.

The sidebar also shows whether protection is on and lets you **pause** it for
5, 15 or 60 minutes, with a countdown; with the sidebar collapsed, or on a
phone, a paused appliance says so in the bar along the top, with Resume beside
it. The light/dark toggle is at the foot of the sidebar. On a Mac, `⌘` and a
digit jumps between screens and `⌘B` folds the sidebar; `/` focuses the search
box.

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

1. **Add a list.** *Light* (oisd small) is the right first subscription — it
   blocks the large majority of advertising and breaks very little. *Balanced*
   and *Strict* (HaGeZi Pro and Pro++) add trackers and malware, and break more
   the stronger you go. A fresh install already subscribes to oisd small, so
   this may be done.
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

- **Allow it** — for everyone, or just for that device. A rule beats every list
  and the AI list, so this takes effect on the next query; you do not have to
  wait for anything. That is also the fix when the row says *AI list*.
- **Or turn off the list that supplied it**, on Lists, if it is causing more
  trouble than it is worth. Switching from oisd big to oisd small fixes a lot of
  this.

### If a name still will not resolve after you allow it

Your browser and your phone keep DNS caches of their own, and they do not know
you just changed your mind. Reload harder, or give it a minute.

---

## AI review, if your household turns it on

It is off unless someone turns it on, on Lists, with their own OpenRouter key.
While it is on:

- **What it does.** When a device opens a website, Cogwheel groups the names
  that website looked up in the next few seconds and, once the page has loaded,
  asks a decision model about each one it has not judged recently: is this part
  of the site, or advertising and tracking? Each answer is block, allow, or
  leave it to your lists. An answer that agrees with your lists, or is unsure,
  changes nothing.
- **The first visit is no different.** The model answers after the page has
  loaded, never before, so a first visit is filtered by your lists alone. New
  names are usually judged within a minute, and later visits use the answer. A
  repeat visit sends nothing.
- **What leaves the house.** The names, and the website that loaded them —
  never which device asked — go to OpenRouter and the company that runs the
  model. Turning AI review off stops that at once, and the AI list stops
  applying; it is kept, and applies again if review is turned back on.
- **How you can tell.** A name the AI list decided says *AI list* in Activity,
  and **Why?** says what the model thought and how sure it was. That is the
  model's confidence, not Cogwheel's.
- **Exact names only.** A verdict on `cdn.site.com` says nothing about
  `img.cdn.site.com`. And **an AI allow lifts a list's block on the name
  itself, not on a name it redirects to**: if that name redirects to one a list
  blocks, the lookup is still blocked, and Why? says so.
- **Keeping a name of your own out of it.** Give it a household rule — allow is
  the usual one. A name a household rule covers, and everything under it, is
  never sent. Local names (`.lan`, `.home` and the like), the appliance's own
  names, and names that look like they carry an identifier are never sent
  either.
- **"No lists" on a device means your rules and the AI list.** The AI list is
  household-wide and reaches every filtered device, including one set to No
  lists; the device editor says so. A device that should get nothing automated
  can have filtering off.
- **It is judged against the household's lists, not each device's.** A device
  on fewer lists gets the AI list's blocks only for names no household list
  blocks. For a name only a list it does not use blocks, it gets nothing from
  the AI list, and that name resolves for it as it always did.
- **Undoing it.** A rule of yours beats it. On Lists, a verdict's menu can
  forget it — it is judged again the next time a website loads it — and *Clear
  AI list* forgets them all.

---

## Names that can never be blocked

Twenty-one suffixes are protected: the lookups a device needs in order to stay
reachable at all — resolver bootstrap and captive-portal checks, time servers,
and the certificate-status endpoints that TLS depends on. Blocking those leaves
a device with no route back to working, with errors that point nowhere near DNS.
A clock that has drifted, in particular, fails TLS everywhere.

So: **a list that contains one of these is still installed and still used.** The
names it hit are recorded against it and shown under its name on Lists, and
those names keep resolving. You do not lose the rest of a list because it
contained one line you would not have chosen.

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
[DEPLOYMENT §9](DEPLOYMENT.md#9-configuration-reference). Turning the log off
also switches AI review off and empties the AI list.

If AI review has been used, the AI list is a record too. It keeps its blocks and
allows for up to 90 days, and the names it left to your lists for at most 30
days — or for the log's number of days, if that is fewer. Which website a
verdict was judged for is forgotten after the log's number of days. **Clear
log** forgets both: the websites, and the names left to your lists. Like the
log, anyone who can open the web UI can read the AI list.

Nothing leaves the house except the lookups themselves, which go to the upstream
resolver, and the blocklist downloads — and, only while AI review is on, the
names your household's websites load, sent to OpenRouter with the website that
loaded them. Device names and addresses never are. Turning AI review off stops
this at once. Cogwheel makes no other outbound connection — no telemetry, and
not even an update check.
