# 03 — Cogwheel Web: Current App Inventory

> **Historical. Describes the tree before the Phase 3 rewrite, and is not
> maintained.** Every name in it — routes, columns, file paths, module layout —
> is pre-Phase-3 and will not be found in the current tree:
> `/api/v1/dashboard`, `/api/v1/resolver-access`, `/api/v1/sources`,
> `/api/v1/sources/refresh`, `/api/v1/runtime`, the `block-profiles` endpoints,
> the `blocklist_profile_override` and `protection_override` columns, the
> `cogwheel-api` crate and the single-file `apps/cogwheel-server/src/main.rs`
> are all gone. Do not navigate today's code with it.
> `docs/spec-dnsnet-plus-four.md` sections 1, 3 and 6 are the contract now;
> section 9 schedules this document's rewrite for Phase 4.

`apps/cogwheel-web` as it stands after the cut to the DNS-filtering core: five
screens over eighteen server routes. This is the regression checklist for the
UI and the map of where each piece of behaviour lives. The pre-cut inventory
(eight screens, a command palette and a domain inspector) is on the
`archive/full-featured` branch.

---

## 0. App shape at a glance

- React 19 + Vite + TypeScript, Tailwind CSS v4, Shark UI (Ark) primitives
  under `src/components/ui/`, self-hosted Inter, `lucide-react` icons.
  Runtime dependencies: `@ark-ui/react`, `@fontsource-variable/inter`, `clsx`,
  `lucide-react`, `react`, `react-dom`, `react-router-dom`, `tailwind-merge`,
  `tailwind-variants`. No charting library.
- `react-router-dom` routes (`src/App.tsx`): `/` eager; `/activity`,
  `/devices`, `/protection`, `/settings` lazy with a skeleton fallback;
  anything else redirects to `/`.
- One `CogwheelProvider` (`src/data/provider.tsx`) owns the control-plane
  snapshot and every mutation; screens read it through `useCogwheel()`.
- The live query stream is a separate hook (`src/hooks/use-event-stream.ts`)
  because it is push, not poll.
- `src/lib/api.ts` is the whole server contract; nothing else calls `fetch`.

```
<ErrorBoundary>
  <CogwheelProvider>
    <Routes>
      <AppLayout>            sidebar + <Outlet/>; ⌘/Ctrl+1..5 and "/" shortcuts
        OverviewScreen | ActivityScreen | DevicesScreen | ProtectionScreen | SettingsScreen
      </AppLayout>
    </Routes>
    <Toaster/>
  </CogwheelProvider>
</ErrorBoundary>
```

---

## 1. Screens — the "do not regress" checklist

### 1.1 Global chrome

- Sidebar (`components/layout/app-sidebar.tsx`): the five `PRIMARY_NAV`
  entries from `lib/nav.ts` with their `⌘n` hints; a `SnoozeControl` (pause
  5 / 15 / 60 minutes, countdown, one-click resume, backed by
  `runtime/pause` and `runtime/resume`); a `ThemeToggle` (light / dark /
  system, persisted under `cogwheel-theme`, applied to `<html data-theme>`
  before first paint).
- `AppLayout`: ⌘/Ctrl+digit navigates; a bare `/` focuses the screen's search
  field; a stale-data banner when the last poll failed.
- Toasts on every mutation, success and failure, with the server's reason.

### 1.2 Overview (`routes/overview.tsx`, `/`)

- Stat tiles: protection state (from `protection_status`, with the pause
  countdown), enabled sources, blocked queries (with the blocked ratio),
  named devices.
- Top queried and top blocked domains (`dashboard.domain_insights`, six each).
- "How to connect devices": the first IPv4 and IPv6 targets from
  `resolverAccess.dns_targets` plus the server's `notes`; an empty state when
  the server reports none.
- Resolver summary: cache hits, fallback served, upstream failures from
  `dashboard.runtime`.
- Actions: refresh blocklists now (`POST /api/v1/sources/refresh`).

### 1.3 Activity (`routes/activity.tsx`, `/activity`)

- Live table over `useEventStream`: domain, client (device name when the IP
  matches a named device, else the IP), verdict, time.
- Controls: pause / resume (rows arriving while paused are counted and merged
  on resume), clear, verdict filter (all / blocked / allowed), device filter,
  domain text filter.
- States: connecting, open, reconnecting (with backoff), paused; a warning
  banner when the stream has never connected; an empty state before the first
  query. Buffer capped at 500 rows.

### 1.4 Devices (`routes/devices.tsx`, `/devices`)

- Table of `settings.devices`: name, IP, policy mode badge (household default
  / custom), profile override, filtered / bypassing pill, allowed-domain count.
- Add / edit form: name, IP address, policy mode; in custom mode also the
  profile override, protection override (inherit / bypass) and a
  comma-separated allowed-domain list. Saves with `POST /api/v1/devices`.
- A warning banner when any device bypasses filtering. No delete (the server
  has no route).

### 1.5 Protection (`routes/protection.tsx`, `/protection`)

Two tabs, selected by `?tab=blocklists|profiles`.

- **Blocklists**: add a source (name, URL, profile, strictness, refresh
  interval; `kind` is always `domains` from this form), search by name or
  URL, enable / disable, delete with a confirmation naming the list, refresh
  all. Rows show the refresh interval, last attempt and due state from
  `blocklist_statuses`. The baseline source cannot be disabled or deleted.
- **Profiles**: saved `block_profiles` with emoji, name, description, the OISD
  presets picked (one per family), extra custom lists by URL and allowlist
  exceptions. Create, edit, delete with confirmation. Stored preference only —
  see `01-backend-api.md` §5.

### 1.6 Settings (`routes/settings.tsx`, `/settings`)

Read-only: counts of blocklists, profiles and named devices with links to the
screen that edits each, and a note that upstream servers, bind addresses and
retention are environment variables on the appliance.

---

## 2. API client — `src/lib/api.ts`

Types mirror the server contracts in `01-backend-api.md` §5 field for field:
`DnsRuntimeSnapshot`, `SourceRecord`, `BlocklistStatus`, `DeviceRecord`,
`BlockProfileListRecord`, `BlockProfileRecord`, `DomainInsightEntry`,
`DomainInsights`, `DashboardSummary`, `SettingsSummary`,
`ResolverAccessStatus`, `RefreshResponse`, `StreamQueryEvent` (camelCase).

`api` methods and the routes they call:

| Method | Route |
| --- | --- |
| `dashboard`, `settings`, `runtimeSnapshot`, `resolverAccess`, `devices`, `sources` | the matching `GET` |
| `pauseRuntime(minutes)`, `resumeRuntime()` | `POST /api/v1/runtime/pause`, `/resume` |
| `refreshSources()` | `POST /api/v1/sources/refresh` |
| `upsertBlocklist(input)`, `setBlocklistEnabled(id, enabled)`, `deleteBlocklist(id)` | `POST /api/v1/settings/blocklists`, `/state`, `/delete` |
| `upsertBlockProfile(input)`, `deleteBlockProfile(id)` | `POST /api/v1/settings/block-profiles`, `/delete` |
| `upsertDevice(input)` | `POST /api/v1/devices` |

`eventsStreamUrl` is the SSE endpoint. `ApiError` carries the status and path;
`errorMessage()` turns any thrown value into toast text. Every read accepts an
`AbortSignal`.

---

## 3. Data layer — `src/data/provider.tsx`, `src/data/context.ts`

- `ControlPlaneSnapshot = { dashboard, settings, resolverAccess }`.
- First paint restores the last successful snapshot from `localStorage`
  (`CACHE_KEYS`, suffixed `_v2` because the dashboard shape changed) and marks
  it stale, then loads everything.
- Polling: only `dashboard` every 5 s (`REFRESH_INTERVAL_MS`), and only while
  the tab is visible; focus and visibility changes poll immediately.
  `settings` and `resolverAccess` reload on mount, on demand and after every
  mutation.
- A partial failure keeps last-known values on screen, sets `stale`, and
  raises one "Showing last-known data" warning per outage.
- `mutate({ key, action, successTitle, failureTitle, optimistic?, after })`:
  sets `busy = key`, applies an optimistic patch, runs the call, toasts, and
  reloads `full` (default), `light` (dashboard only) or `none`; on failure the
  optimistic patch is rolled back visibly.

---

## 4. Shared pieces

- `src/lib/constants.ts` — empty defaults for every snapshot field, the four
  OISD presets and their mutual exclusions, cache keys, the poll interval, the
  500-row activity cap, the snooze options.
- `src/lib/derive.ts` — `protectionState` (tone / label / detail from
  `protection_status` and offline), `pauseSecondsRemaining`, `blockedRatio`,
  `splitDomainList`, `slugify`.
- `src/lib/format.ts` — count / latency / time formatting.
  `src/lib/toast.ts` — the `notify` helpers. `src/lib/utils.ts` — `cn`.
- `src/components/app/` — `PageShell` / `PageHeader` / `PageSections`,
  `SectionCard`, `StatTile`, `StatusIndicator`, `DataTable`, the loading /
  empty / error states, `ConfirmDialog`, `FormField`, `TextField`,
  `SelectField`.
- `src/hooks/` — `use-event-stream`, `use-protection` (pause state and the
  snooze mutation), `use-theme`, `use-is-mobile`.

---

## 5. Build facts

- `npm run build` is `tsc --noEmit -p tsconfig.app.json && vite build`;
  `npm run lint` is ESLint. Both run in CI and in the Dockerfile.
- Output is `dist/`, served by the server from `COGWHEEL_WEB_DIST_DIR` or
  `/app/web` in the image, with brotli/gzip applied by the server.
- No external network request in the built output: the font is bundled and
  there is no CDN `<link>`.
