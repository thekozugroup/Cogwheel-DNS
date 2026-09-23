---
target: Cogwheel web app (apps/cogwheel-web/src)
total_score: 28
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:/home/user/Cogwheel-DNS/apps/cogwheel-web/src"
timestamp: 2026-09-23T18-48-58Z
slug: apps-cogwheel-web-src
---
Method: dual-agent (A: design review · B: detector + browser evidence), isolated sub-agents. B's report reached the parent before A's; A never saw it.

### Design Health Score

| # | Heuristic | Score | Key Issue |
|---|---|---|---|
| 1 | Visibility of System Status | 2 | Paused protection has no signal on 4 of 5 pages on a phone, or anywhere with the sidebar collapsed |
| 2 | Match System / Real World | 3 | "Adblock/Hosts", "unfiltered", "Unnamed clients" leak; "Paused 14:59" reads as a clock time |
| 3 | User Control and Freedom | 3 | Rules commit instantly with no undo, inside a form whose Save/Cancel implies they don't |
| 4 | Consistency and Standards | 3 | Lists uses the generic nested card; "Why?" household-scoped on Overview, device-scoped on Activity |
| 5 | Error Prevention | 2 | "Choose lists" with none ticked saves a zero-list device; deleting a list doesn't warn dependants |
| 6 | Recognition Rather Than Recall | 3 | Per-device rules only visible inside each device's edit form |
| 7 | Flexibility and Efficiency | 3 | No bulk actions; 50 row-menu tab stops; ⌘ shown on Windows/Linux/phones |
| 8 | Aesthetic and Minimalist Design | 3 | Card titles repeat page titles; four equal-weight tiles |
| 9 | Error Recovery | 3 | "Why?" diagnoses but offers no fix |
| 10 | Help and Documentation | 3 | No guidance among 11 presets; no first-run path |
| **Total** | | **28/40** | **Good (bottom of band)** |

### Design Specificity Verdict
LLM: words authored for this product, composition category-interchangeable (sidebar, four equal KPI tiles, chart, two top-10 cards). Partly the pinned brief. Missed opportunity: "is my household protected right now?" gets the same tile as a query count, at 16px beside 24px counters.
Deterministic: 1 static finding (segment-group.tsx:109 width/height transition, vendored, real). Overlay: same pattern in vendored sidebar.tsx:206,219,347 (static scan misses transition-[…]); Settings line length 146–151ch (settings.tsx:44,142; states.tsx:161); nested card on Lists at 375 (data-table.tsx:338, real). False positives: Activity verdict segment, card-footer strips.
Agreement: Lists nested card; Settings width capped on the dl only (value column ~360px short) = same root cause as line length. Every P1 is behavioural and undetectable.
Overlays: injected on all five pages, headless sandbox only.

### Priority Issues
- [P1] Paused protection invisible on phone and with sidebar collapsed — app-sidebar.tsx:121,138 hide the readout; app-layout.tsx:108-117 top bar has none. Fix: top-bar status chip (yellow-400 dot, "Paused · mm:ss left", Resume) when collapsed/mobile; dot on collapsed mark; pause/resume icon in collapsed footer. /impeccable adapt
- [P1] Zero-list device shown healthy — devices.tsx:385-429 allows Choose lists with none; shows "● On · 0 of 2". lists.tsx:263-276 delete confirm ignores dependent devices (Sam's iPhone uses only oisd small). Fix: warn state for !all_lists && lists.length===0; pre-tick enabled lists; refuse empty save; name dependants in delete/disable confirms; title `Delete "<name>"?`. /impeccable harden
- [P1] Surfaces contradict — overview.tsx:299-305 Why? checks household scope, so Top-blocked youtube.com (device rule on Sam's iPhone) answers "Allowed for everyone"; after Clear log, counters survive above "No queries yet" empty states (overview.tsx:153-168,194-201; activity.tsx:442-447). Fix: say where it's blocked and why, link to filtered Activity; cleared-log empty-state variant. /impeccable clarify
- [P2] Tables at in-between widths — Activity 722px in 638px at 1024 hides row menu behind nested scroll (ui/table.tsx:26); Lists at 375 generic nested card with empty 40px header (lists.tsx:240-253, data-table.tsx:336-359). Fix: Activity stackBelow 3xl; Lists purpose-built two-line narrowRow. /impeccable adapt
- [P2] Overview doesn't lead with the answer; first run leads with three dead ends — stat-tile.tsx:64-70, overview.tsx:83-176. Fix: Protection primacy (span two / page header); no-traffic ordering puts Connect first. /impeccable layout

### Persona Red Flags
- Alex: 5-item row menu; 18 tab stops to first row menu, +49 to "Show 50 more" (no roving tabindex, activity.tsx:210); toast lacks undo and hides rule replacement; ⌘ glyph on Windows/Linux, Ctrl+digit shadows browser tabs (nav.ts:18, app-layout.tsx:27-35).
- Sam: tr[role=button] aria-label replaces row content — Filtering "Off" never announced (data-table.tsx:250-252); focus ring ~2.5:1 (index.css:105,146,208-211).
- Casey: pause invisible after drawer closes; Activity filters fill first screen at 375, domain truncates while time keeps width; pasted URL refused in Check a domain (lists.tsx:515, derive.ts:160-162).

### Minor Observations
Green success tick on every toast incl. "Protection paused" (toast.tsx:62,114); Overview Devices 5 vs Devices page (3); titles repeat page titles; "Pick a preset above" but form is below (lists.tsx:245); Delete device ms-auto ineffective (devices.tsx:328,337); "06:12:36 PM" clock (format.ts:43); chart hour detail title-only (overview.tsx:231); "Navigation" label redundant; unnamed clients "500 / 145" unlabelled (devices.tsx:509-512).

### Questions to Consider
- Should Overview's first line be the answer, with tiles as footnotes?
- Should a paused appliance ever look protected — what if pause changed the chrome?
- Is "Why?" a menu item or the product — should every Blocked pill be the Why?
- Eleven presets by publisher, or three by strength?
