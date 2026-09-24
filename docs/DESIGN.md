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
   onto neutral and the five `--chart-*` tokens are deleted; there is no fourth
   hue anywhere in the product.

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
| `PageShell` / `PageSections` / `PageHeader` | the 1200px column and its page padding, the 24px stack of cards, and the title row |
| `SectionCard` | the card every block of content sits in — a real heading, optional description, optional actions, optional footer, optional busy rule |
| `StatTile` | one number with its label and a line or two of context |
| `StatusPill` / `StatusChip` | a dot plus a word, never a dot alone. The pill is a 24px label in a row; the chip is 32px of chrome (44px on a touch screen, as tall as the Resume beside it) that can carry a live countdown and the one action that ends the state. A pill marked `verdict` — "Blocked", a rule's "Allow" — carries no hidden status word, because its word is the meaning |
| `DataTable` / `NarrowRow` | columns, rows, the empty/loading/error states built in, and the purpose-built row the table becomes below its container breakpoint |
| `EmptyState`, `LoadingSkeleton`, `ErrorState` | the three states a table is in when it has no rows to show |
| `NoticeBanner` | a tinted line for a degraded or advisory state, or a neutral one for an answer ("Why?") |
| `ConfirmDialog` | confirmation that names the exact target; its `tone` colours the consequence by the state the appliance will be in — `bad` for what is lost, `warn` for what is degraded (a pause, a device left with no list) |
| `RowMenu` | the per-row "⋯" menu in Overview, Activity and Lists, and the icon rail's pause menu. Actions can carry a `group` (their scope); consecutive ones sit together, named for assistive technology, with a rule between groups |
| `DomainName` | a domain that breaks before a dot instead of truncating, for every list of names a row is identified by |
| `FormField`, `TextField`, `SelectField`, `GroupLabel` | label, hint, error, control; a required field's label carries a muted `*` (hidden from screen readers, which hear the input's own `required`); `GroupLabel` is the same label for a segment group, which is a radio group rather than a labelled input |
| `Mark` | the product mark, in the sidebar header and the mobile bar |

One file in `ui/` is not from the registry: `IconButton`, which every icon-only
button uses. It is a `Button` with an accessible name and a tooltip that is
mounted only while it is showing — the obvious `<Tooltip>` wrapper starts a
state machine per instance, which on Activity was one per row. The same thinking
is behind `RowMenu`: until it is opened it is one plain button, and the Ark menu
exists only while it is open.

The domain, action and button row that Lists and Devices both draw lives in
`routes/rule-fields.tsx` (`DomainField`, `RuleActionField`, `RowButtonSlot`), so
the paste handling, the error wording and the alignment cannot drift between
the three forms that use it.

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

The base is a neutral black-to-white ramp. **Exactly three hues exist in the
entire theme**, all at Tailwind 400, each with a 700 (light) / 300 (dark)
partner for the few places the hue has to be read as text:

| Token | Meaning |
|---|---|
| `--color-green-400` | healthy, allowed, protected, online |
| `--color-yellow-400` | degraded, warning, pending, paused |
| `--color-red-400` | blocked, error, critical, offline |

The semantic tokens `--success`, `--warning` and `--destructive` hold these
three as the sRGB values Tailwind 400 renders as (`#05df72`, `#fdc700`,
`#ff6467`) rather than as Tailwind's oklch. Red-400 lies outside sRGB: opaque, a
browser maps it into gamut, but at a tint's 8–40% Chromium premultiplied the
out-of-range channel and painted cyan specks on every anti-aliased corner of a
red box. The 700/300 partners are opaque text and stay as they are.

Everything else is `--color-neutral-*` and `--color-white`. The semantic tokens
(`--background`, `--card`, `--primary`, `--muted`, `--border`, `--input`,
`--ring` and the sidebar set) are defined on `:root` for light and redefined for
dark.

Three of them look alike and are not:

| Token | Light | Dark | What it is |
|---|---|---|---|
| `--border` | `neutral-200` | `neutral-800` | The hairline between surfaces: cards, dividers, table rows. 1.26:1 on white, because it separates and identifies nothing. |
| `--input` | midpoint of `neutral-400` and `neutral-500` | `neutral-500` | The edge of a *control* — a field, an outline button, an unchecked switch track, a segment group — which is what tells a person there is something to operate. WCAG 1.4.11 puts that at 3:1: 3.5 on white, 3.3 on the sidebar, 3.2 on `--muted`; 3.8 on the dark card. |
| `--ring` | `neutral-900` | `neutral-50` | The focus ring: the foreground itself, 17.9:1 on the card. In `neutral-400` it was 2.6:1 — the one indicator a keyboard user cannot do without, drawn in the palest grey in the product. |

In dark mode a field or outline button is filled with `--muted` at 60%, never
with `--input`: a control filled with its own edge colour has no edge.

### Selection is inversion

In a black-and-white product the only highlight that reads at a glance is the
pair the primary button already uses.

- A **highlighted menu item**, from the keyboard or the pointer, is inverted:
  `--primary` fill, `--primary-foreground` text, about 17:1. It used to be
  `--accent` on `--popover`, 1.09:1, and a keyboard user arrowing through a row
  menu could not see which verb Enter would fire.
- A **chosen segment** — the theme toggle, Activity's verdict filter, a rule's
  Block/Allow — is painted on the item itself, inverted and in medium weight;
  the others sit in `--muted-foreground`. There is no sliding indicator.
- The **current screen** in the sidebar is the `--sidebar-accent` surface,
  `--foreground` text in medium weight, and `aria-current="page"`. No rule down
  its edge.
- The **hour being read** in Overview's chart gets a `--muted` column behind it
  while the other bars fade to 40%.

### Using the accents

Tailwind 400 hues are mid-luminance. `text-green-400` on white is roughly 1.9:1
and fails WCAG AA badly. **A 400 colour is a surface, a mark or a border — never
body text on a light background.**

Approved:

- **A status dot** — 8px and round (10px beside Overview's answer and on the
  icon rail), always paired with a word in `--foreground`
  ([§7](#7-accessibility-floor) has the one exception). This is `Status` inside
  `StatusPill` and `StatusChip`. In a column, the state a row is meant to be in
  — a device that is filtering — takes the neutral dot, which is the foreground,
  so the 400s are left for the rows that need a look.
- **A tint** — the 400 at 8–10% behind the content and 24–40% as its border.
  Text on it is the matching 700/300 partner (a `NoticeBanner`'s title,
  `ConfirmDialog`'s consequence) or `--foreground` (Overview's answer, the
  sidebar's paused block, the stale-data banner). Secondary text on a tint is
  `--foreground` at 80%, never `--muted-foreground`, which is 4.49:1 on the
  yellow tint.
- **The edge of a field that failed validation**, with the error in words
  under it.

The one chart, Overview's *Queries by hour*, is monochrome, although its two
series are blocked and answered. Colour marks the exception, never the rule:
twenty-four red bars would be the largest mass of red in the product, on the
screen that reports a household working as it should. There are no chart
tokens either. The strip draws in two neutral utilities, each written with its
dark value beside it in `routes/overview/hour-strip.tsx`, and the legend's
swatches use the same two pairs:

| | Blocked | Answered |
|---|---|---|
| Light | `neutral-900` (the foreground) | `neutral-300` |
| Dark | `neutral-100` | `neutral-600` |

Blocked is stacked at the foot of each hour's own bar, so it reads as a share of
that hour rather than of the day. This is the one place two neutral fills have
to be told apart from each other *and* from the card behind them. Measured, as
contrast ratios against the surface each one sits on:

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
  A destructive button therefore takes the neutral outline treatment, a
  destructive menu item ("Delete list…") is as neutral as its neighbours, and
  the red in a delete flow lives on `ConfirmDialog`'s consequence sentence
  (yellow for a pause, which is a paused appliance, not a lost one),
  which is describing what the appliance will be in after the click.
- **A green confirmation.** A toast that says an action worked is neutral; see
  [§8](#8-behaviour).
- **A left-edge accent strip.** These were removed deliberately. A card is
  separated by its hairline border and by whitespace, and nothing else; a
  selected or current item is marked by its surface and its weight.
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
| Scale | 12 / 14 / 16 / 18 / 20 / 24 px |
| Body | 14px |
| Headings | `-0.011em` tracking |
| Display (24px+) | `-0.02em` |
| Serif | never |

Each step has a job. 12px is labels, meta lines and the chart's legend and
axis; 14px is body and table text; 16px is a card's heading, and a text field
on a phone, below which iOS zooms the page when it takes focus; 18px is a
dialog's title and the address to type into a router; 20px is Overview's
answer; 24px is a page title and a tile's figure.

**Headings are real headings.** A page has one `h1`, its title. A card's title
is an `h2`, 16px semibold, rendered as a heading element rather than the `div`
`CardTitle` draws by default; a group inside a card is an `h3` at 14px medium —
*Household rules* and *Device rules* in Lists' Rules card, *Rules for this
device* in the device form. Overview's answer is the page's first `h2`, at
20px. That outline is how a screen-reader user skims a page, and every page
used to be one `h1` with nothing under it.

Numbers that are compared down a column are tabular, and so is any figure that
changes in place — a countdown, a live count — so its digits do not jitter.
Monospace is for what is read character by character: addresses, domain names,
file paths and variable names. It takes the size of the text around it, with one
exception, the 18px router address on Overview, because it is the one value on
the page someone types into another device. A version, a port or a schema number
is a number, not an address, and is set tabular in Inter. Settings' prose sits
on a 56ch measure.

---

## 4. Shape, elevation and motion

| Token | Value |
|---|---|
| `--radius` | 0.625rem (10px) — cards, panels |
| control radius | 0.5rem (8px) — buttons, inputs, segment groups |
| pill radius | full — status pills, the status chip |
| border | 1px solid — `--border` for surfaces, `--input` for controls |
| shadow | none on cards; overlays (menus, tooltips, dialogs, toasts) carry a soft one at 5%; controls keep Shark's faint 5% edge |
| duration | 150ms interactions, 200ms overlays and the sidebar |
| easing | `cubic-bezier(0.4, 0, 0.2, 1)` |

**Apple-esque here means separation by hairline and whitespace, not by shadow.**
Cards sit flat on the background with a 1px border. `SectionCard` sets
`shadow-none` explicitly, because the underlying `Card` would otherwise bring
one.

**Nothing animates layout.** Collapsing the sidebar animates one property,
`grid-template-columns` on the shell, over 200ms; it used to animate width,
margin, opacity and padding on four kinds of element, each forcing its own
reflow. A segment changes by crossfading its colours over 150ms rather than
sliding an indicator. The focus outline never transitions at all: every
transition list is named rather than `all` or `transition-colors`, which in
Tailwind v4 includes `outline-color` and eased the ring in, and a focus ring
that fades in is one a fast keyboard user does not see.

The one piece of motion that is not a transition is `SectionCard`'s `busy`
rule: a 2px indeterminate bar under the card header, for work that changes
several rows at once and can take tens of seconds — refreshing every list,
downloading a new one — where a spinner inside one 28px icon button is not
visible from across the card. The card is `aria-busy` while it runs. Under
reduced motion the bar is the whole track pulsing in opacity, not a
quarter-width bar stopped at the start, which would read as "25% done".

---

## 5. Layout and spacing

**One gutter: 24px.** `--spacing-gutter` in `index.css`, used as `gap-gutter`
between cards, between stat tiles and between the fields of a form row, and as
`p-gutter` round a card's content and a stat tile's. There is not a second
spacing value competing with it, and adding one is the change most likely to be
asked for and refused. It is **pixels, not rem**, and so is the page padding: text
set to 200% should be twice as big, and the whitespace round it should not. In
rem the two paddings doubled with the text and left a 375px phone's card 181px
for words twice their size; in pixels the gutter is 24px at every text size. Space
that belongs to the text — line gaps, a control's own padding — stays in rem. The
tighter spacings are inside a single control group, and are not gutters: a
domain, its Block/Allow and the button that adds it read as one sentence and
sit 12px apart, and buttons side by side sit 8px apart.

The content column is `max-w-[1200px]`, centred, with page padding that steps
24 → 32 → 40px at `sm` and `lg`, and a card's own padding is the gutter. A stat
tile's inset is the gutter too, so the tiles' text starts on the same edge as
the card under them.

The layout is a persistent left sidebar, collapsible to icons, and a sheet
drawer below `md`. It works down to 375px: the sidebar becomes a sheet, tables
become narrow rows, and there is no horizontal page scroll at any width.

**A grid of cards is laid out by the width it gets, not by the window's.**
Overview's tiles are one column, two from 18rem of container and four from
48rem; its two top-name cards sit side by side from 56rem. The breakpoints are
container queries in rem, so 200% text is a narrower container and the grid
steps down with it.

**A table that stacks gets a purpose-built row, not the generic label/value
card.** Activity, Devices (both tables) and Lists each define one with
`NarrowRow`: the first line identifies the row, the second says what you came
to read, separated by the list's own divider and no second border inside the
section card's. The generic form is still there for tables where every field is
genuinely a label/value pair, but a log or a device list is not one — seven
stacked rows per device was six devices to a phone screen and a half. Measured
at 375px: a list row is 56–81px, a device row 64–89px.

Nothing is dropped in the narrow form that the wide form treats as the point.
Activity's verdict and the list that decided it travel down to 375px, because
"Blocked · HaGeZi Pro" is the sentence the page exists to print. So Activity's
row gives the domain the whole first line and puts the verdict, its reason, the
device and the time under it: on one line where the row has 320px of text, and
where it has less — every phone — the verdict and reason keep a line of their
own and the device and time take a third, rather than the reason being cut.
That row is 83px. Activity switches to it below 768px of card, not of window, so
at 1024px with the sidebar open the log is the narrow form rather than a table
scrolling sideways inside its card.

**A row that opens is not itself a control.** In a table whose rows open —
Devices — the cell that names the row is a real `<button>`, the row's one tab
stop, named for what it does ("Edit Work Laptop") with the visible name inside
that name. The other cells stay cells, read with their column headers. A click
anywhere else on the row opens it too, as a mouse convenience, except a click on
a control, on a menu or dialog the row opened, or one that ends a text
selection. The button fills its cell and draws its focus ring inset, so the
cell's truncation cannot clip it. In a narrow row the title is the button. A
column that holds controls has an "Actions" header for assistive technology and
draws nothing, and a table has exactly one scroll container, so its sticky
header sticks.

Where the card is narrower than 28rem, a `SectionCard` with actions moves them
under the title rather than beside it — measured on the card (`@container/card`),
not the window, and in rem, so 200% text on a desktop stacks them as a phone
does. At 375px the action row is wider than what is left of the card, and at
1024px with 200% text the title was squeezed to "Activity / log" while a button
ran past the card's edge. Overview's platform rows go side by side by the same
measure. A button's label wraps rather than overflow: button heights are
minimums, and only a container narrower than the label — a phone at 200% text —
gives it a second line. On the same screens Activity folds its Device and Verdict
filters behind a *Filters* button that counts the active ones; the domain field
stays, because it is the one people use and `/` has to find it.

In a form, the fields of a row are top-aligned, and a button beside them sits
in a `RowButtonSlot`, a spacer one label-line tall, so the button stays level
with the inputs when an error appears under one of them instead of the whole row
jumping as the person types.

---

## 6. The five screens

The sidebar has five entries and will not grow a sixth without a very good
reason. On a Mac, `⌘1`–`⌘5` jump between them, and the sidebar prints the chord
beside each entry (not on a touch screen, and never as part of the link's name).
Elsewhere nothing is bound and nothing is printed: `Ctrl` + a digit selects a
browser tab in Chrome, Edge and Firefox on Windows, Linux and ChromeOS, `Alt` +
a digit does in Linux browsers, and `Ctrl`+`Alt` is AltGr on most European
layouts, so any of them would take away how a keyboard user leaves the page.
There the five screens are the first stops after the skip link. `⌘B` collapses
the sidebar on a Mac and is not bound elsewhere either, for the same reason:
`Ctrl`+`B` is Firefox's bookmarks sidebar. A bare `/` focuses the screen's
search field, where it has one, on every platform.

| Screen | What it is for |
|---|---|
| **Overview** | Leads with the answer — is the household protected right now — in words, with the one action that changes it. Then the day behind it: four tiles, the queries by hour, the top blocked and top queried names, and the exact addresses to type into a router. |
| **Activity** | Every query as it happens, with the device that asked and the verdict. It stays live, but never moves under someone's hand: while they are in the list, new rows wait above it. Each row's menu, grouped by scope, can allow or block that name for everyone or for that device, name the device that asked, or answer "Why?". |
| **Devices** | Give an address a name, and optionally its own settings: filtering off, every household list, a chosen subset or none, and rules that apply to it alone. |
| **Lists** | The subscribed blocklists, a picker that adds one by strength, the household rules alongside every device's own, and a box that answers what would happen to a name right now. |
| **Settings** | A **read-only** summary of what is stored. Upstreams, binds and retention are set by the operator in the environment, and the UI says so rather than offering a control that will not stick. |

**Overview's first line is the answer.** It is an `h2` with a status dot, one
supporting sentence, and at most one action:

| State | The answer | The action |
|---|---|---|
| Not answering | *Cogwheel is not answering*, red, tinted | Try again |
| Paused | *Protection is paused · 14:58 left*, yellow, tinted | Resume protection |
| Upstream failing | *Lookups are failing*, red, tinted: the upstream has not answered most lookups sent to it in the last minute, so names that are not blocked do not resolve | See the upstream (Settings) |
| No lists / all off | *No blocklists yet* or *Every blocklist is switched off*, yellow, tinted | Go to Lists |
| Lists not downloaded | *Your blocklists have not downloaded yet*, yellow, tinted | Refresh lists |
| No traffic yet | *Cogwheel is ready · no device is using it yet*, neutral | — |
| Protected | *Your household is protected · 649 blocked in the last 24 hours*, green, with *Every device using Cogwheel is filtered except Work Laptop.* | — |

Every clause is one the code checks: the exception is read from the device
list, not assumed. *Lookups are failing* is read from the resolver's own
counters over the last minute — at least three upstream failures, and at least
half of every query the cache could not answer; a healthy upstream fails a
lookup now and then, a stopped one fails every one that is not blocked. Before
it, a stopped upstream showed *Your household is protected* over a network on
which nothing resolved. When the appliance has never answered and nothing is
cached, the answer is the whole page: the address card and the "nothing to show
yet" line were claims about an appliance nobody had heard from. With no traffic yet, the addresses to connect a device come
straight after the answer and one line stands in for the chart and the top
names, rather than a page of zeroes. There is no page-level Refresh lists:
re-downloading every list is list maintenance and lives on Lists, and Overview
offers it only as the remedy for its own first line.

**Protection is on screen at every width.** In the expanded sidebar, under the
five entries, sits the protection panel: the state in words with the number of
lists behind it, and *Pause for* 5, 15 or 60 minutes, each confirmed first
because pausing unfilters every device on the network. The word is the answer's,
shortened, from the same checks in the same order — *Unreachable*, *Paused*,
*Lookups failing*, *No blocklists* / *Blocklists off*, *Not downloaded*, *Ready*,
*Protected* (*Checking* before anything has loaded) — so the sidebar no longer
says *Protected* beside an answer saying no device uses Cogwheel yet. The list
count is printed only once it is known; while the appliance is unreachable
there is no count and no pause control, because neither could be true. While paused it becomes a
tinted block with the countdown and *Resume protection*, which is not confirmed,
because it only puts things back. Collapsed to the icon rail, the mark tile
carries a status dot and one button pauses or resumes. And whenever the sidebar
cannot say it — collapsed, or a drawer on a phone — and the state needs a look
(a warning or a problem; not *Protected*, *Ready* or *Checking*), the top bar
carries the **paused status chip**: the yellow dot,
*Paused · 12:31 left*, and Resume (or the red dot and *Unreachable*). On a phone
the wordmark goes visually hidden to make room. A chip reading "Protected" on
every screen would be chrome, and would teach people not to look at it. The
light / dark / system toggle is at the sidebar's foot.

**Adding a list asks how much to block, not whose list.** The picker is three
choices by strength, each with one line on what it blocks and what it breaks,
and the publisher's list as the detail: *Light* (oisd small — ads, made never to
break a site), *Balanced* (HaGeZi Pro — ads, trackers and malware, rarely breaks
a site) and *Strict* (HaGeZi Pro++ — blocks the most, now and then breaks a site
you use). A fourth, *More lists*, holds the full catalogue and a list by its
address. A tier already subscribed is disabled and says so, the picker opens on
the gentlest one that is not, and the button names what it adds: *Add HaGeZi
Pro*.

Settings being read-only is a design decision, not an unfinished screen. A
setting in two places is a setting that will disagree with itself.

---

## 7. Accessibility floor

Not aspirations. These are the rules a change is checked against.

- **Colour is never the only signal.** Every tone pairs a 400-weight dot with a
  word, and the accessible name states the status in text — `StatusPill` and
  `StatusChip` render a visually hidden "OK: ", "Warning: ", "Problem: " before
  their label precisely for this — except a `verdict` pill, whose word is the
  meaning ("Blocked", a rule's "Block"), which was announced as "Problem:
  Block". The one dot drawn without a word beside it is
  on the icon rail's mark tile, where there is no room for one: its word is in
  the link's name and tooltip, and whenever it is not green the top bar prints
  it in full.
- Contrast: body text and placeholders ≥ 4.5:1, large text ≥ 3:1, and a
  control's edge ≥ 3:1 against its surface, in **both** themes. The 400
  accents are never used as text on a light surface.
- **One focus ring, defined once**: a 2px solid outline in `--ring`, 2px out,
  from a single `:focus-visible` rule rather than per-component classes. It is
  drawn inset where a container would clip it (a row's button), and on the item
  where the focusable element is a hidden input (a segment).
- The whole product is operable from the keyboard — sidebar, tables, menus and
  dialogs all reachable and escapable. A skip link is the first stop and moves
  focus to `<main>` itself. A row menu opens on Enter, Space or the arrow keys
  and returns focus to its trigger. A list of row menus is one tab stop
  (`hooks/use-roving-menus.ts`), moved through with the arrow keys, Page
  Up/Down, Home and End: Activity's fifty, and each of Overview's two top-name
  cards, which put twenty stops between the chart and the address to copy.
  Overview's chart is one slider over the hours. The phone drawer has its own
  Close; a tap on the dimmed page closes it too, but a screen reader has nothing
  to find there.
- Landmarks: the sidebar is an `<aside>` holding the `<nav>`, the top bar is
  the banner, and each page is a `<main>` with the heading outline in
  [§3](#3-typography).
- Every icon-only button is an `IconButton`: an accessible name, and a tooltip
  on mouse hover and keyboard focus, never on touch, where a tap is the action.
- `prefers-reduced-motion: reduce` stops transitions and animations globally;
  the busy rule becomes a still pulse ([§4](#4-shape-elevation-and-motion)).
- **The live query stream is not a live region.** Wrapped in one, the table
  read every column of every arriving row, and the rest of the page was
  unreachable. Instead a visually hidden polite line reports a count every 20
  seconds — *N new queries waiting above the list* while rows are held, *N new
  queries since Live was switched on* otherwise — and says nothing when there is
  nothing new. Toasts announce, and so do a copied address, a checked domain
  and the stale banner, which is put into a live region that is always there.
- Minimum touch target 44×44px on a coarse pointer, for every button, field,
  row menu, segment and menu item; a switch keeps its drawn size and grows an
  invisible 44px hit area; a label around a checkbox or radio is the target, not
  the 16px box inside it; a link that stands alone (the tile's "3 named · 2
  unnamed", a device's name over its rules) is 44px tall. Text fields and
  selects are 16px below `md`, the size under which iOS zooms the page into
  them.

---

## 8. Behaviour

| | |
|---|---|
| **Theme** | Light, dark or system. Persisted to `localStorage` and applied to `data-theme` on `<html>` by an inline script **before first paint**, so there is no flash of the wrong theme. |
| **Live activity** | Server-sent events, handed to the screen in batches at most every 250ms, with filters by device, verdict and domain text answered by the server. The stream stays connected for as long as the screen is open: Live decides what is shown, not what is received. The client reconnects with backoff and shows `connecting` / `connected` / `holding` / `reconnecting` / `paused` explicitly rather than pretending, and buffers at most 500 rows. |
| **Holding rows** | New rows wait above the list, behind *Show N new*, while keyboard focus or an open row menu is in it, a moving mouse is over it (a still one stops holding after 15 seconds, so a log left on a spare screen stays live), the newest row has been scrolled out of sight, the tab is in the background, or Live is off. The button sits in a fixed-height line, so its arriving never shifts the rows it is holding still. Leaving the list lets them in; pressing it from the keyboard lets them in and puts focus on the newest. Up to 500 are kept and the rest counted; if more arrived than that and the log is on, its first page is read again, so there is no gap behind them. |
| **Toasts** | Every mutation confirms or reports failure, with the reason the API gave. A confirmation is neutral: its icon is the foreground, because *Protection paused* succeeded, and a green tick beside it said the household was healthy at the moment it stopped being filtered. Warnings and errors keep their 700/300 partners. A change made in one click and applied to every device at once — adding or removing a household rule — carries **Undo**, and stays ten seconds so it can be reached. An outage is not a toast: the stale banner says it for as long as it lasts. |
| **Optimistic updates** | A switch that saves on its own — a list's Enabled — applies immediately and rolls back **visibly** on error. Turning off a list that a device depends on asks first, and names the device. |
| **Forms** | Every form is a real `<form>`: Enter submits, errors appear under the field that caused them, the field is marked invalid, and focus moves to the first one that is wrong. A device's form stages everything — name, address, filtering, lists and its own rules, each rule marked new, changed or removed (struck through, with Undo) — until Save, and Cancel throws all of it away. A domain field keeps only the host of whatever is pasted into it: `https://www.youtube.com/watch?v=…` lands as `www.youtube.com`, in view, before anything is saved. |
| **Offline** | A failed poll degrades to a banner, not a blank page. The last-known data stays on screen and the banner says *Showing last-known data* with the time of the last answer; when there has never been an answer and nothing is cached it says *Cogwheel is not answering*, and nothing on the page claims a count, a list or an address it has not read. The reason is the API's own sentence, not prefixed with the field that failed. A page reload revalidates the shell, and the server answers a client-side route's revalidation with a 304 — it used to answer with an empty 200, and a reload of `/devices` was a blank page. |
| **Deep links** | Every screen has a URL, and so does opening a device (`/devices?device=<id>`) or naming an address (`/devices?ip=<address>`), which is where Activity's *Name this device…* goes. Activity's filters are in its URL — `?q=` for the domain text, `?verdict=blocked` or `allowed`, `?client=` for an address or `unnamed` — read when it opens and kept in step as they change, which is how Overview's *Show in Activity* lands on that name's blocks. |

---

## 9. Voice

The interface says what happened, in the fewest words that are still true.

- **No status the code cannot verify.** "Not reported" and "Not downloaded
  yet" appear because they are the honest answers, and "Protected" is not said
  of an appliance no device is using yet. A green tick that means "we did not
  check" is worse than no tick.
- **A destructive confirmation names its target**, and who else it touches.
  *Delete "oisd small"?*, not "Are you sure?" — and when a device filters with
  that list alone, *Sam's iPhone uses only this list and will have no list
  filtering.*
- **An error says what to do**, or says plainly that it does not know. The
  rate-limited refresh answers *"Lists were refreshed a moment ago; try again in
  27 seconds"* — a fact and a number, not "Too many requests".
- **No exclamation marks, and no congratulating the user** for configuring a DNS
  server.
