# Cogwheel design language

The contract the control plane is held to. It describes what the UI **is**, not
what someone should build, and a change to `apps/cogwheel-web` is reviewed
against it.

The brief, in the words it was given in: *clean, minimal, Apple-esque, with a
sidebar; Inter as the core font; a black-and-white scheme; any accent colours
from the Tailwind 400 range; red, yellow and green reserved for status and
warnings.*

Two consequences follow that are easy to get wrong, and both have been got wrong
here before:

1. **Colour is state, never action.** There are no coloured buttons, no coloured
   links and no coloured brand marks. The primary action is black in light mode
   and white in dark mode. A red that means "delete this" is a red being used as
   a control; a red that means "this name is blocked" is the system working.
2. **The component library's own palette is overridden, not inherited.** Shark
   UI ships chromatic semantic tokens — a blue `--info`, five chart hues.
   Installing it and leaving those alone fails the brief. `--info` is collapsed
   onto neutral; there is no fourth hue anywhere in the product.

---

## 1. Components

The UI is built on **Shark UI**, which is [Ark UI](https://ark-ui.com) plus
`tailwind-variants`, on **Tailwind CSS v4**. Components come from the registry
rather than being hand-written to look similar.

`src/components/ui/` holds the registry components. `src/components/app/` holds
the compositions the screens are actually built from, and a screen should reach
for these rather than for the primitives underneath them:

| Component | What it is |
|---|---|
| `PageShell` / `PageHeader` | the 1200px column, its gutters, and the title row |
| `SectionCard` | the card every block of content sits in — title, optional description, optional actions, optional busy rule |
| `StatTile` | one number with a label, and an optional tone |
| `StatusIndicator` / `StatusPill` | a dot plus a word, never a dot alone |
| `DataTable` | columns, rows, and the empty/loading/error states built in |
| `EmptyState`, `LoadingSkeleton`, `ErrorState` | the three states a table is in when it has no rows to show |
| `ConfirmDialog` | destructive confirmation that names the exact target |
| `RowMenu` | the per-row action menu in Activity and Devices |
| `FormField`, `TextField`, `SelectField` | label, hint, error, control |
| `Mark` | the product mark, in the sidebar header and the mobile bar |

Icons are [lucide](https://lucide.dev), at whatever size the component sets, and
they are decorative: an icon never carries meaning that the word beside it does
not also carry.

The **mark is the one glyph that is not from an icon set.**
`components/layout/mark.tsx` inlines the path from `docs/assets/logo.svg` and
fills it with `currentColor`, so it is black on paper and white on ink without
being told which. The same path is what `index.html`'s favicon and
`deploy/unraid/cogwheel.svg` carry. That is deliberate: a product with two
similar-looking logos has two logos. `docs/assets/logo.svg` is the master and
its comment lists every file that has to move with it.

---

## 2. Colour

The base is a neutral black-to-white ramp. **Exactly three chromatic values
exist in the entire theme**, all Tailwind 400:

| Token | Meaning |
|---|---|
| `--color-green-400` | healthy, allowed, protected, online |
| `--color-yellow-400` | degraded, warning, pending, monitor-only |
| `--color-red-400` | blocked, error, critical, offline |

Everything else is `--color-neutral-*` and `--color-white`. The semantic tokens
(`--background`, `--card`, `--primary`, `--muted`, `--border`, `--ring`, the
sidebar set and the five chart slots) are defined on `:root` for light and
redefined for dark; charts are monochrome by default, because the three accents
are reserved for status and a chart series is not a status.

### Using the accents

Tailwind 400 hues are mid-luminance. `text-green-400` on white is roughly 1.9:1
and fails WCAG AA badly. **A 400 colour is a surface, a mark or a border — never
body text on a light background.**

Approved:

- **A status dot** — `size-2 rounded-full`, always paired with a word in
  `--foreground`. This is `Status` inside `StatusPill`.
- **A tint** — `bg-red-400/10` with text in the matching 700 foreground token,
  which does meet AA.
- **A focus or selection ring.**
- **A chart series that is genuinely status-valued** — blocked against allowed.

The 24-hour chart is the one place two neutral fills have to be told apart from
each other *and* from the card behind them. Measured, as contrast ratios against
the surface each one sits on:

| | Answered fill | vs its card | vs the blocked segment |
|---|---|---|---|
| Light | `neutral-300` on white | 1.48 | 12.1 |
| Dark | `neutral-600` on `neutral-900` | 2.29 | 7.2 |

Neither fill reaches 3:1 against its card, and neither needs to: the pair
carries the meaning and the baseline rule carries the axis. What the numbers are
for is keeping the two themes within sight of each other — the previous values
(`neutral-200` / `neutral-700`) were 1.26 and 1.73, and the light one was the
weaker of the two, which is the opposite of the usual assumption.

Not approved:

- `text-{color}-400` for anything a person has to read.
- A coloured primary button.
- **A status colour on a control.** The 400 colours name a state — a blocked
  verdict, a list whose last fetch failed, a paused appliance — not an action.
  A destructive button therefore takes the neutral outline treatment, and the
  red in a delete flow lives on `ConfirmDialog`'s consequence sentence, which is
  describing what the appliance will be in after the click.
- **A left-edge accent strip.** These were removed deliberately. A card is
  separated by its hairline border and by whitespace, and nothing else.
- Colour as the only carrier of meaning — see [§7](#7-accessibility-floor).

---

## 3. Typography

**Inter, self-hosted**, via `@fontsource-variable/inter`.

Self-hosted is not a preference. The appliance runs on a LAN and may have no
route to the internet at all — that is a supported configuration, not an edge
case. A webfont from `fonts.googleapis.com` would hang on every request on such
a network and render the UI in a fallback face, and the browser would be told
which pages were being loaded by a third party, on the one product whose whole
job is to stop that.

| | |
|---|---|
| Scale | 12 / 13 / 14 / 16 / 20 / 24 / 32 px |
| Body | 14px |
| Headings | `-0.011em` tracking |
| Display (24px+) | `-0.02em` |
| Serif | never |

Numbers that are compared down a column are tabular. A monospace stack exists
for addresses and domain names, where character-by-character reading is the
point.

---

## 4. Shape, elevation and motion

| Token | Value |
|---|---|
| `--radius` | 0.625rem (10px) — cards, panels |
| control radius | 0.5rem (8px) — buttons, inputs |
| pill radius | full — badges, status pills |
| border | 1px solid `--border` |
| shadow | none on cards; popovers and dialogs only |
| duration | 150ms interactions, 200ms overlays |
| easing | `cubic-bezier(0.4, 0, 0.2, 1)` |

**Apple-esque here means separation by hairline and whitespace, not by shadow.**
Cards sit flat on the background with a 1px border. `SectionCard` sets
`shadow-none` explicitly, because the underlying `Card` would otherwise bring
one.

The one piece of motion that is not a transition is `SectionCard`'s `busy`
rule: a 2px indeterminate bar under the card header, for work that changes
several rows at once and can take tens of seconds — refreshing every list —
where a spinner inside one 28px icon button is not visible from across the card.

---

## 5. Layout and spacing

**One gutter: 24px.** `gap-6` between cards, between stat tiles, between the
fields of a form row. There is not a second spacing value competing with it, and
adding one is the change most likely to be asked for and refused.

The content column is `max-w-[1200px]`, centred, with page padding that steps
`px-6 → sm:px-8 → lg:px-10`.

The layout is a persistent left sidebar, collapsible to icons, and a sheet
drawer below `md`. It works down to 375px: the sidebar becomes a sheet, tables
become stacked cards, and there is no horizontal page scroll at any width.

**A table that stacks gets a purpose-built row, not the generic label/value
card.** Activity and Devices both define one: two lines of about 56px, the
identifying values on the first and the ones you came to read on the second,
separated by the list's own divider and no second border inside the section
card's. The generic form is still there for tables where every field is
genuinely a label/value pair, but a log or a device list is not one — seven
stacked rows per device was six devices to a phone screen and a half.

Nothing is dropped in the narrow form that the wide form treats as the point.
Activity's verdict and the list that decided it travel down to 375px, because
"Blocked · HaGeZi Pro" is the sentence the page exists to print.

Below `sm`, a `SectionCard` with actions moves them under the title rather than
beside it — at 375px the action row is wider than what is left of the card, and
the previous layout squeezed "Showing 50 of 200 rows held." into a five-line
column and pushed a button off the edge.

---

## 6. The five screens

The sidebar has five entries and will not grow a sixth without a very good
reason. `⌘`/`Ctrl` + a digit jumps between them; a bare `/` focuses the current
screen's search field.

| Screen | What it is for |
|---|---|
| **Overview** | Is protection on, what has been blocked, the top queried and top blocked names of the last day, and the exact addresses to type into a router. |
| **Activity** | Every query as it happens, with the device that asked and the verdict. Live can be turned off so the list can be read. Each row's menu can allow or block that name, name the device that asked, or answer "Why?". |
| **Devices** | Give an address a name, and optionally its own settings: filtering off, a chosen subset of lists, and rules that apply to it alone. |
| **Lists** | The subscribed blocklists, the household allow/block rules, and a box that answers what would happen to a name right now. |
| **Settings** | A **read-only** summary of what is stored. Upstreams, binds and retention are set by the operator in the environment, and the UI says so rather than offering a control that will not stick. |

The sidebar also carries the pause control — 5, 15 or 60 minutes with a visible
countdown — and the light/dark toggle.

Settings being read-only is a design decision, not an unfinished screen. A
setting in two places is a setting that will disagree with itself.

---

## 7. Accessibility floor

Not aspirations. These are the rules a change is checked against.

- **Colour is never the only signal.** Every tone pairs a 400-weight dot with a
  word, and the accessible name states the status in text — `StatusPill` renders
  a visually hidden "OK: ", "Warning: ", "Problem: " before its label precisely
  for this.
- Contrast: body text ≥ 4.5:1, large text ≥ 3:1, in **both** themes. The 400
  accents are never used as text on a light surface.
- Every interactive element has a visible focus ring, and the whole product is
  operable from the keyboard — sidebar, tables and dialogs all reachable and
  escapable.
- Every icon-only button has an `aria-label` and a tooltip.
- `prefers-reduced-motion: reduce` disables transitions and any auto-scrolling
  in the live stream.
- The live query stream is an `aria-live="polite"` region; toasts announce.
- Minimum touch target 44×44px.

---

## 8. Behaviour

| | |
|---|---|
| **Theme** | Light, dark or system. Persisted to `localStorage` and applied to `data-theme` on `<html>` by an inline script **before first paint**, so there is no flash of the wrong theme. |
| **Live activity** | Server-sent events, with pause/resume and filters by device, verdict and domain text. The client reconnects with backoff, shows `connecting` / `open` / `reconnecting` / `paused` explicitly rather than pretending, buffers at most 500 rows, and holds new rows while paused so a frozen list can actually be read. |
| **Toasts** | Every mutation confirms or reports failure, with the reason the API gave. |
| **Optimistic updates** | Toggles apply immediately and roll back **visibly** on error. |
| **Offline** | A failed poll degrades to a banner, not a blank page. The last-known data stays on screen and is marked stale. |
| **Deep links** | Every screen, and every dialog worth sharing, has a URL. |

---

## 9. Voice

The interface says what happened, in the fewest words that are still true.

- **No status the code cannot verify.** "Unknown" and "not yet ready" appear in
  several places because they are the honest answers; a green tick that means
  "we did not check" is worse than no tick.
- **A destructive confirmation names its target.** "Delete `oisd small`?", not
  "Are you sure?".
- **An error says what to do**, or says plainly that it does not know. The
  rate-limited refresh answers *"Lists were refreshed a moment ago; try again in
  27 seconds"* — a fact and a number, not "Too many requests".
- **No exclamation marks, and no congratulating the user** for configuring a DNS
  server.
