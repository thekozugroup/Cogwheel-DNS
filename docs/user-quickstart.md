# User Quick Start

This guide is for someone using Cogwheel as a DNS filtering appliance.

## Open the Dashboard

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

## The Five Screens

- **Overview** — whether protection is on, how many queries were blocked, the
  top queried and top blocked names of the last day, and the exact addresses
  to type into a router.
- **Activity** — every query as it happens, with the device that asked and
  whether it was blocked. Pause the stream to read it; filter by device,
  verdict or name.
- **Devices** — give a device a name so it shows up by name in Activity, and
  optionally its own policy: a profile, a list of names it may always reach,
  or a full bypass.
- **Protection** — the blocklists the appliance subscribes to (add one by URL,
  turn it on or off, delete it, refresh now) and saved profiles built from the
  OISD presets plus your own exceptions.
- **Settings** — a read-only summary of what is stored. Upstream servers, bind
  addresses and retention are set by the operator in the environment file.

The sidebar also has the pause control (5, 15 or 60 minutes, with a countdown)
and the light/dark toggle.

## First Things to Configure

1. Add a blocklist on the Protection screen. OISD Small is a good first list;
   OISD Big blocks more and breaks more.
2. Name the devices you care about on the Devices screen.
3. Leave everything else at its default.

## If Browsing Breaks

Try these steps in order:

1. Pause protection from the sidebar. If the site works while paused, a list is
   blocking something it needs; if it still fails, the problem is not Cogwheel.
2. Look for the site's names in Activity with the verdict filter set to
   *Blocked*, then add the one it needs to the device's allowed names, or
   switch to a smaller list.
3. If a list update ever refuses to install, that is deliberate: a list that
   would block the names your devices need to stay online is rejected and the
   previous list keeps working. Nothing needs undoing.
