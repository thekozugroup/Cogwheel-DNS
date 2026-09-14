# 04 — Design System & UI Architecture

The binding brief for the from-scratch rebuild of `apps/cogwheel-web`. Where this document and any
other disagree, this one wins.

---

## 1. Non-negotiable requirements

Stated by the product owner, verbatim:

- Built on the design system at **https://shark.vini.one/** (Shark UI). Delete and replace the
  existing UI.
- "clean, minimal, apple esque design with a **sidebar**"
- "**inter** as the main core font"
- "minimalist"
- "any accent colors are using **tailwindcss 400 colors**"
- "main color scheme being **black and white**"
- "**three accents for Red, yellow, green** for indicators of status or warnings etc"
- Refined UI/UX: intuitive and easy to use.

Two consequences follow that are easy to get wrong:

1. Shark UI's own theme ships **chromatic** semantic tokens — `red-500` for destructive,
   `emerald-500` for success, `amber-500` for warning, `blue-500` for info, and five chart hues
   (orange-600 / teal-600 / cyan-900 / amber-400 / amber-500). **All of these must be overridden.**
   Installing Shark and leaving its palette alone fails the brief.
2. "Accents only for indication" means no coloured buttons, no coloured links, no coloured brand
   marks. The primary button is black in light mode and white in dark mode. Colour appears only
   where it reports state.

---

## 2. Stack and setup

Shark UI is built on **Ark UI** (`@ark-ui/react`) and **`tailwind-variants`**, and **requires
Tailwind CSS v4**. The current app is on Tailwind v3 with a `tailwind.config.ts`, so this is a
migration, not an upgrade.

### 2.1 Dependencies

Remove: `tailwindcss@3`, `autoprefixer`, `postcss`, `postcss.config.js`, `tailwind.config.ts`,
every `@radix-ui/*` package, `next-themes`, `class-variance-authority`.

Add:

| Package | Why |
| --- | --- |
| `tailwindcss@^4` | v4 engine |
| `@tailwindcss/vite` | v4 Vite plugin; replaces the PostCSS pipeline |
| `@ark-ui/react` | headless primitives Shark components are built on |
| `tailwind-variants` | variant API Shark components use |
| `tw-animate-css` | animation utilities Shark's style expects |
| `@fontsource-variable/inter` | **self-hosted** Inter |
| `lucide-react` | icons (already present) |
| `clsx`, `tailwind-merge` | `cn()` helper |
| `recharts` | charts (already present) |

### 2.2 Vite config

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: { proxy: { "/api": "http://127.0.0.1:8080" } },
});
```

### 2.3 components.json

```json
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "default",
  "rsc": false,
  "tsx": true,
  "tailwind": { "config": "", "css": "src/index.css", "baseColor": "neutral", "cssVariables": true },
  "aliases": { "components": "@/components", "utils": "@/lib/utils", "ui": "@/components/ui", "lib": "@/lib", "hooks": "@/hooks" },
  "registries": { "@shark": "https://shark.vini.one/r/{name}.json" }
}
```

### 2.4 Installing components

The registry is reachable and serves shadcn-schema JSON. Verified working:

```bash
npx --yes shadcn@latest add @shark/button @shark/card ... --yes --overwrite
```

If the CLI is uncooperative in a sandbox, fetch the registry item and write
`files[].content` directly — each item's JSON carries the full component source:

```bash
curl -sS https://shark.vini.one/r/button.json
```

**Do not hand-write lookalike components.** The requirement is to use Shark UI; the source must
come from the registry.

Components to install (at minimum): `utils`, `button`, `card`, `badge`, `input`, `field`, `label`,
`switch`, `select`, `native-select`, `tabs`, `table`, `dialog`, `alert-dialog`, `toast`, `tooltip`,
`separator`, `skeleton`, `scroll-area`, `sidebar`, `command`, `status`, `progress`, `spinner`,
`segment-group`, `sheet`, `popover`, `menu`, `kbd`, `empty`-equivalent, `hint`, `alert`, `avatar`,
`item`, `chart`, `number-input`, `combobox`.

---

## 3. Theme

### 3.1 Font — Inter, self-hosted

The appliance runs on a LAN and may have **no internet route at all**. The current `index.html`
loads DM Sans, Instrument Serif and JetBrains Mono from `fonts.googleapis.com`; on an offline
network every one of those requests hangs and the UI renders in a fallback face. That is a defect,
not a style choice.

Delete the `<link>` tags. In `src/index.css`:

```css
@import "@fontsource-variable/inter";
@import "tailwindcss";
@import "tw-animate-css";
```

Wire it in `@theme`:

```css
@theme {
  --font-sans: "Inter Variable", ui-sans-serif, system-ui, sans-serif;
  --font-heading: "Inter Variable", ui-sans-serif, system-ui, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, monospace;
}
```

Enable Inter's optical sizing and tabular numerals for metrics:

```css
body { font-family: var(--font-sans); font-optical-sizing: auto; }
.tabular { font-variant-numeric: tabular-nums; }
```

Every number that updates live (query counts, percentages, latencies) gets `.tabular` so digits
do not jitter.

### 3.2 Colour

Base is a neutral black/white ramp. **Exactly three** chromatic values exist in the entire theme,
all Tailwind **400**:

| Token | Value | Meaning |
| --- | --- | --- |
| `--color-green-400` | `oklch(0.792 0.209 151.711)` | healthy, allowed, protected, online |
| `--color-yellow-400` | `oklch(0.852 0.199 91.936)` | degraded, warning, pending, monitor-only |
| `--color-red-400` | `oklch(0.704 0.191 22.216)` | blocked, error, critical, offline |

Light theme:

```css
:root {
  --radius: 0.625rem;

  --background: var(--color-white);
  --foreground: var(--color-neutral-900);
  --card: var(--color-white);
  --card-foreground: var(--color-neutral-900);
  --popover: var(--color-white);
  --popover-foreground: var(--color-neutral-900);

  --primary: var(--color-neutral-900);
  --primary-foreground: var(--color-white);
  --secondary: var(--color-neutral-100);
  --secondary-foreground: var(--color-neutral-900);
  --muted: var(--color-neutral-100);
  --muted-foreground: var(--color-neutral-500);
  --accent: var(--color-neutral-100);
  --accent-foreground: var(--color-neutral-900);

  --border: var(--color-neutral-200);
  --input: var(--color-neutral-300);
  --ring: var(--color-neutral-400);

  /* The only three hues in the system. */
  --destructive: var(--color-red-400);
  --destructive-foreground: var(--color-red-700);
  --success: var(--color-green-400);
  --success-foreground: var(--color-green-700);
  --warning: var(--color-yellow-400);
  --warning-foreground: var(--color-yellow-700);
  /* Shark defines --info (blue). Collapse it onto neutral: no fourth hue. */
  --info: var(--color-neutral-400);
  --info-foreground: var(--color-neutral-700);

  --sidebar: var(--color-neutral-50);
  --sidebar-foreground: var(--color-neutral-600);
  --sidebar-primary: var(--color-neutral-900);
  --sidebar-primary-foreground: var(--color-white);
  --sidebar-accent: var(--color-neutral-150, var(--color-neutral-100));
  --sidebar-accent-foreground: var(--color-neutral-900);
  --sidebar-border: var(--color-neutral-200);
  --sidebar-ring: var(--color-neutral-400);

  /* Charts are monochrome by default; the three accents are reserved for status. */
  --chart-1: var(--color-neutral-900);
  --chart-2: var(--color-neutral-600);
  --chart-3: var(--color-neutral-400);
  --chart-4: var(--color-neutral-300);
  --chart-5: var(--color-neutral-200);
}
```

Dark theme — invert the ramp, keep the same three hues:

```css
:root[data-theme="dark"], :root:not([data-theme="light"]) .dark {
  --background: var(--color-neutral-950);
  --foreground: var(--color-neutral-50);
  --card: var(--color-neutral-900);
  --card-foreground: var(--color-neutral-50);
  --popover: var(--color-neutral-900);
  --popover-foreground: var(--color-neutral-50);

  --primary: var(--color-neutral-50);
  --primary-foreground: var(--color-neutral-900);
  --secondary: var(--color-neutral-800);
  --secondary-foreground: var(--color-neutral-50);
  --muted: var(--color-neutral-800);
  --muted-foreground: var(--color-neutral-400);
  --accent: var(--color-neutral-800);
  --accent-foreground: var(--color-neutral-50);

  --border: var(--color-neutral-800);
  --input: var(--color-neutral-700);
  --ring: var(--color-neutral-600);

  --destructive: var(--color-red-400);
  --destructive-foreground: var(--color-red-300);
  --success: var(--color-green-400);
  --success-foreground: var(--color-green-300);
  --warning: var(--color-yellow-400);
  --warning-foreground: var(--color-yellow-300);
  --info: var(--color-neutral-500);
  --info-foreground: var(--color-neutral-300);

  --sidebar: var(--color-neutral-900);
  --sidebar-foreground: var(--color-neutral-400);
  --sidebar-primary: var(--color-neutral-50);
  --sidebar-primary-foreground: var(--color-neutral-900);
  --sidebar-accent: var(--color-neutral-800);
  --sidebar-accent-foreground: var(--color-neutral-50);
  --sidebar-border: var(--color-neutral-800);
  --sidebar-ring: var(--color-neutral-600);

  --chart-1: var(--color-neutral-50);
  --chart-2: var(--color-neutral-300);
  --chart-3: var(--color-neutral-500);
  --chart-4: var(--color-neutral-600);
  --chart-5: var(--color-neutral-700);
}
```

### 3.3 Using the accents — contrast rules

Tailwind 400 hues are **mid-luminance**. `text-green-400` on white is roughly 1.9:1 and fails WCAG
AA badly. The 400 colour is therefore a **surface, mark, or border**, never body text on a light
background.

Approved patterns:

- **Status dot** — `size-2 rounded-full bg-green-400`, paired with a text label in `--foreground`.
- **Left rule** — `border-l-2 border-red-400` on a row or card.
- **Tint** — `bg-red-400/10` with text in `--destructive-foreground` (the 700 shade), which does
  meet AA.
- **Focus/selection ring** — `ring-2 ring-yellow-400`.
- **Chart series** for a genuinely status-valued series (blocked vs allowed).

Forbidden:

- `text-{color}-400` for anything a user must read.
- Coloured primary buttons. The primary action is `--primary` (black/white).
- **A status colour on a control.** The 400 colours name a *state* — a blocked verdict, a list
  whose last fetch failed, a paused appliance — not an action. A destructive button therefore
  takes the neutral `outline` treatment (the `destructive` Button variant is that treatment), and
  the red in a delete flow lives on `ConfirmDialog`'s consequence sentence, which is describing
  what the appliance will be in after the click.
- Colour as the sole carrier of meaning — see §7.

### 3.4 Shape, elevation, motion

| Token | Value | Note |
| --- | --- | --- |
| `--radius` | `0.625rem` (10px) | cards, panels |
| control radius | `0.5rem` (8px) | buttons, inputs |
| pill radius | `9999px` | badges, status chips |
| border | `1px solid var(--border)` | hairline; the primary separation device |
| shadow | none on cards; `0 1px 2px rgb(0 0 0 / 0.04)` at most | popovers/dialogs may use `0 8px 24px rgb(0 0 0 / 0.12)` |
| duration | 150ms interactions, 200ms overlays | |
| easing | `cubic-bezier(0.4, 0, 0.2, 1)` | |

Apple-esque here means **separation by hairline and whitespace, not by shadow**. Cards sit flat on
the background with a 1px border. Page gutters are generous (24px mobile, 32–40px desktop). Section
rhythm is 32px between major blocks, 16px within a block.

Type scale: `12 / 13 / 14 / 16 / 20 / 24 / 32`px. Body is 14px. Headings use `-0.011em` tracking;
display sizes (24px+) use `-0.02em`. Never use a serif face.

---

## 4. Information architecture

Persistent left sidebar, collapsible to icons, and a `Sheet` drawer below `md`.

```
Cogwheel                         ← wordmark + cogwheel mark, links to Overview
─────────────────────────────
  Overview            ⌘1
  Activity            ⌘2         ← live query stream
  Devices             ⌘3
  Lists               ⌘4         ← subscribed blocklists and household rules
  Settings            ⌘5         ← read-only summary
─────────────────────────────
  [pause control]   Protection active / paused for mm:ss
  [theme toggle]
```

Routes (`react-router-dom`):

| Route | Screen | Primary endpoints |
| --- | --- | --- |
| `/` | Overview | `GET /api/v1/overview`, `POST /api/v1/lists/refresh` |
| `/activity` | Activity | `GET /api/v1/queries`, `GET /api/v1/events/stream` (SSE), `DELETE /api/v1/queries` |
| `/devices` | Devices | `GET/POST /api/v1/devices`, `PUT/DELETE /api/v1/devices/{id}`, `/api/v1/rules` |
| `/lists` | Lists | `/api/v1/lists`, `/api/v1/lists/{id}`, `POST /api/v1/lists/refresh`, `/api/v1/rules`, `GET /api/v1/check` |
| `/settings` | Read-only summary | `GET /api/v1/settings` |

The sidebar pause control uses `POST /api/v1/runtime/pause` and `/resume`. The
authoritative contract for every endpoint is section 3 of
`docs/spec-dnsnet-plus-four.md`; the pre-Phase-3 API and web inventories that
used to sit beside this file are in `docs/archive/`, and section 9 schedules
their rewrite.

---

## 5. Live stream contract

`GET /api/v1/events/stream` is a server-sent-events endpoint with one event
name, `query`. Each frame is a `StreamQueryEvent` in camelCase:

```ts
type StreamQueryEvent = {
  domain: string;
  client: string;              // source IP, or "unknown"
  deviceName: string | null;   // reserved; the server sends null today
  blocked: boolean;
  reason: string | null;       // reserved; the server sends null today
  observedAt: string;          // RFC 3339
};
```

The server sends a `keep-alive` comment every 15 s, refuses the 33rd concurrent
subscriber with 503, and drops frames for a subscriber that falls more than 256
frames behind rather than slowing resolution. The client
(`src/hooks/use-event-stream.ts`) manages the connection itself: reconnect with
backoff (1 s → 30 s), show `connecting` / `open` / `reconnecting` / `paused`
explicitly, buffer at most 500 rows, and hold new rows while paused so a frozen
list can be read.

---

## 6. Component conventions

Build these once in `src/components/app/` and use them everywhere.

| Component | Props |
| --- | --- |
| `PageShell` | `{ children }` — max-width 1200px, responsive gutters |
| `PageHeader` | `{ title, description?, actions? }` |
| `SectionCard` | `{ title, description?, actions?, children, footer? }` |
| `StatTile` | `{ label, value, delta?, tone?: "neutral" \| "good" \| "warn" \| "bad", hint? }` |
| `StatusIndicator` | `{ tone: "good" \| "warn" \| "bad" \| "idle", label, description? }` — dot + text + `aria-label` |
| `DataTable` | `{ columns, rows, empty, loading, onRowClick?, sortable? }` |
| `EmptyState` | `{ icon, title, description, action? }` |
| `LoadingSkeleton` | `{ rows?, variant?: "table" \| "cards" \| "text" }` |
| `ErrorState` | `{ title, detail?, onRetry }` |
| `ConfirmDialog` | `{ title, description, confirmLabel, destructive?, onConfirm }` — must name the exact target |
| `FormField` | `{ label, hint?, error?, children }` |

---

## 7. Accessibility contract

- Every interactive element has a visible focus ring: `focus-visible:ring-2 ring-[--ring] ring-offset-2`.
- Full keyboard operation. Sidebar, tables and dialogs are all reachable and escapable by
  keyboard alone.
- **Colour is never the only signal.** A red dot is always accompanied by text ("Blocked") and/or a
  distinct icon. Screen-reader labels state the status in words.
- Contrast: body text ≥ 4.5:1, large text ≥ 3:1, in both themes. The 400 accents are never used as
  text on light surfaces (§3.3).
- `prefers-reduced-motion: reduce` disables transitions and any auto-scrolling in the live stream.
- Live regions: the query stream uses `aria-live="polite"`; toasts announce.
- Every icon-only button has an `aria-label` and a tooltip.
- Minimum hit target 44×44px on touch.

---

## 8. Quality-of-life features

| Feature | Behaviour |
| --- | --- |
| Live activity | SSE stream with pause/resume and filters by device, verdict and domain text. |
| Pause protection | Pause blocking for 5/15/60 minutes with a visible countdown in the sidebar and a one-click resume. Uses `POST /api/v1/runtime/pause` and `/resume`. |
| Theme | Light / dark / system. Persisted to `localStorage`, applied via `data-theme` on `<html>` before first paint to avoid a flash. Do **not** use `next-themes`. |
| Toasts | Every mutation confirms or reports failure, with the failure reason from the API. |
| Optimistic updates | Toggles apply immediately and roll back visibly on error. |
| Deep links | Every screen and every dialog worth sharing has a URL. |
| Keyboard shortcuts | `⌘1..5` navigate, `/` focuses the screen's search field. |
| Offline behaviour | Poll failures degrade to a banner, not a blank page; last-known data stays on screen and is marked stale. |
| Responsive | Works to 375px. Sidebar becomes a sheet; tables become stacked cards. No horizontal body scroll. |

---

## 9. Definition of done

- `npm run build` (includes `tsc --noEmit`) and `npm run lint` both exit 0.
- No Google Fonts or any other external network request in the built output.
- No `tailwind.config.ts`, no PostCSS config, no `@radix-ui/*`, no `next-themes` remaining.
- No chromatic value anywhere except `red-400`, `yellow-400`, `green-400`.
- Every one of the five screens of section 4 renders its loading, empty, error
  and populated states.
- Sidebar navigation present and keyboard-operable.
