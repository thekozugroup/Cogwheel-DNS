# User Quick Start

This guide is for someone using Cogwheel as a DNS filtering appliance.

## Open the Web UI

Visit the Cogwheel web UI in your browser:

- Standard deployment: `http://<your-cogwheel-host>:8080`
- Local development: `http://localhost:30080`

Whoever installed Cogwheel will have the address; the installer prints it at
the end, and it is the same address your router's DNS setting points at.

## Make Sure Your Devices Are Actually Using It

Filtering only applies to devices whose DNS goes through Cogwheel. The reliable
way is to set it once on your router, in the DHCP settings, so every device is
covered — including the ones you cannot configure.

If some sites are filtered and others are not, the most common cause is IPv6:
a device with an IPv6 DNS server configured will ignore an IPv4-only setting.
Ask your operator to set both addresses. See
[DEPLOYMENT.md](../DEPLOYMENT.md#6-pointing-your-router-at-cogwheel).

## Three Things to Know About

Everything in Cogwheel is one of three:

- A **device** is a name you have given an IP address, so Activity says
  "Kitchen tablet" instead of `192.168.1.20`. A device can also have filtering
  switched off entirely, and can be limited to a subset of the lists.
- A **list** is a blocklist the appliance subscribes to by URL and re-downloads
  on its own. Lists are where almost all of the blocking comes from.
- A **rule** allows or blocks one domain — for everyone, or for one device. A
  rule beats every list, and a domain covers its subdomains.

## The Five Screens

- **Overview** — whether protection is on, how many queries were blocked, the
  top queried and top blocked names of the last day, and the exact addresses
  to type into a router.
- **Activity** — every query as it happens, with the device that asked and
  whether it was blocked. Turn Live off to read it; filter by device, verdict
  or name. Each row's menu can allow or block that name, name the device that
  asked, or answer "Why?".
- **Devices** — give a device a name so it shows up by name in Activity, and
  optionally its own settings: filtering off, a chosen set of lists, and rules
  that apply to it alone.
- **Lists** — the blocklists the appliance subscribes to (add one from the
  preset list or by URL, turn it on or off, delete it, refresh now), your
  household allow/block rules, and a box that answers what would happen to a
  name right now.
- **Settings** — a read-only summary of what is stored. Upstream servers, bind
  addresses and retention are set by the operator in the environment file.

The sidebar also has the pause control (5, 15 or 60 minutes, with a countdown)
and the light/dark toggle.

## First Things to Configure

1. Add a list on the Lists screen. OISD Small is a good first subscription;
   OISD Big blocks more and breaks more.
2. Name the devices you care about on the Devices screen.
3. Leave everything else at its default.

## If Browsing Breaks

Try these steps in order:

1. Pause protection from the sidebar. If the site works while paused, a list is
   blocking something it needs; if it still fails, the problem is not Cogwheel.
2. Look for the site's names in Activity with the verdict filter set to
   *Blocked*, then add an allow rule for the one it needs — for that device, or
   for everyone — or switch to a smaller list.
3. Twenty-one names that devices need in order to stay reachable — Apple's and
   Windows' time and activation servers among them — can never be taken down by
   a list. A list that contains one of them is still installed, and says so in
   its Status column; the name keeps resolving. Your own block rule, on the
   other hand, does outrank that protection: if you block one of these
   deliberately, it stays blocked.
