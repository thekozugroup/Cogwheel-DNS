# ADR 0002: AI Review and the AI List

## Status

Accepted. The project's owner decided this. It narrows an earlier refusal; it
does not lift it.
[ARCHITECTURE §1](../ARCHITECTURE.md#1-scope-boundary--what-cogwheel-is-not)
and [the spec's §9](../spec-dnsnet-plus-four.md#9-out-of-scope) refused model
classification of domains outright. The owner asked for this feature knowing
that, so this record is where the exception is argued. Both are amended in
the same change to cite this record, and every other document that repeated
the refusal is amended with them.

AI review is **off by default**. A fresh install makes no request to
OpenRouter. No household name leaves the house until someone adds their own
OpenRouter key, picks a model, passes a Test and turns review on. Before that,
the only requests are the ones the set-up form makes when someone uses it,
and they carry nothing of the household's but its key.

## Context

Until now Cogwheel decided in one of two ways: a list you subscribed to names
the domain, or you wrote a rule. ARCHITECTURE §1 put "ML classification of
domains" on its permanently-out-of-scope list because "a household cannot
audit a model's verdict, and 'it looked like a tracker' is not an answer anyone
can act on". It also promised that the appliance makes no outbound request of
its own beyond the upstream resolver and the blocklist URLs. The spec's §9
repeated the refusal, and said that the classifier the project once had was
"not coming back under a different name". CONTRIBUTING pushed any AI-assisted
idea into off-path control-plane code, "if anywhere".

The owner then asked, explicitly, for:

- OpenRouter, with the household's own key ("you bring an api key");
- "systemone style models like Jev, Clef": decision models, which answer a
  typed question with a choice and a confidence, not with text;
- a review of the names a site loads, deciding for each whether it should be
  "blocked, ignored, or whitelisted", "based on the core functionality of the
  site being accessed";
- judging once ("parses once during initial load") and using the result "the
  next time you call the site";
- a "separate one please for these AI identified rules", placed to "fit above
  in priority in case of additional whitelists or blacklists".

That request cannot be met inside the old boundary, so the boundary moves. It
moves only as far as the request needs. What §1 and §9 guarded against stays
refused: a model on the DNS path, a verdict nobody can see or undo, and traffic
nobody asked for.

## Decision

Cogwheel gains an opt-in **AI review** and a separate **AI list**:

- **The model is never on the DNS path.** A reviewer reads the query-log
  writer's batches through a bounded tap that drops rather than waits. It
  groups each device's lookups into *site loads* and picks out the website
  that was opened. It then asks a decision model about the other names that
  load looked up. The first visit is filtered by lists and rules exactly as
  before. Later lookups use the answers, usually within a minute.
- **Verdicts are data compiled into `Policy`.** Answers are stored as rows in
  a new `ai_verdicts` table and compiled into an `AiList`. `evaluate` stays
  pure and does not allocate. On a cache miss the AI tier costs one branch
  when the list is empty and one hash probe when it is not. The cache-hit path
  does not change.
- **The precedence** (`GET /api/v1/check` now names one of thirteen steps):
  device rules > household rules > protected suffixes > **AI list** > list
  `@@` > list block. The AI list is household-wide and applies in every
  filtered scope, including a device on "No lists".
- **No new crate.** The reviewer is the server module `ai/`, so ADR 0001's
  dependency graph is unchanged and `cogwheel-dns-core` gains no dependency.
  The feature's own files are `crates/cogwheel-policy/src/ai.rs`,
  `crates/cogwheel-dns-core/src/invalidate.rs`,
  `crates/cogwheel-storage/src/ai_verdicts.rs`, `apps/cogwheel-server/src/ai/`
  and `apps/cogwheel-server/src/api/ai.rs`.

The decisions, numbered so that code comments and reviews can cite them:

- **D1. The AI tier sits in `evaluate()`, after an explicit protected-suffix
  check. `evaluate_lists()` stays protected suffixes plus lists.** The CNAME
  re-check calls `evaluate_lists`, so it never consults the AI list. No cached
  answer for one name can therefore depend on another name's AI verdict, and
  dropping cached answers by exact name is complete without parsing a single
  cached answer. The cost: an AI block on a name reached only as a CNAME
  target is not enforced through the alias. The cost is small, because the
  reviewer only sees the names devices asked for. A CNAME-cloaked tracker is
  judged on the name the device asked for, which is in the site load.
- **D2. Exact names only, in a dedicated `AiList`, not a `RuleSet`.**
  `RuleSet` matches parents and lets any allow beat any block. Through it, an
  allow of a site's apex would whitelist every tracker under it.
- **D3. One new reason code, `Reason::Ai = 9`** (`ai` on the wire). The
  verdict's arm carries the direction, as it does for the rule tiers, and no
  list slot is credited.
- **D4. An AI allow keeps the CNAME re-check, and it is compiled only over a
  list block that no list `@@` excepts.** The model judged the name, not where
  it points. So `Verdict::rechecks_aliases()` is true for `Allow(NoMatch)` and
  `Allow(Ai)`. A list exception skips the re-check and an AI allow runs it, so
  turning one into the other could make a "whitelist" block. Compiling allows
  only over unexcepted blocks rules that out.
- **D5. The AI list holds only the model's disagreements with the lists.**
  Agreement, an unsure answer, an answer a cap stopped and a cross-site
  conflict are stored as `ignore`, with `why` set to `agrees`, `unsure`,
  `limit` or `contested`. An `ignore` row is never compiled, and the lists
  decide. This keeps cache churn, the attack surface and the Changes view
  small. When a list already blocks a name, the list keeps the credit.
- **D6. Thresholds apply to the model's `confidence`, and a missing one counts
  as no decision.** The bars are in the table below. They are applied again at
  compile time against the live lists. A verdict judged against an older list
  state stops applying when the lists change, and the name is judged again on
  its next sighting.
- **D7. One candidate per request, with at most two questions.** The role
  question is always asked. The effect question ("if it stays blocked, does
  the site break?") is asked only when a list blocks or excepts the name. One
  candidate per request is the documented pattern. Instructions and criteria
  are compile-time constants, and household data appears only as JSON values
  in `state`.
- **D8. When two websites disagree in opposite directions, the lists decide.**
  A block or allow is asked again when it appears in another website's load,
  at most twice in 30 days and once a day. An opposite answer above the plain
  bar turns the row into `ignore` with `why='contested'`, records both
  websites and keeps the row for 90 days, so the conflict is not forgotten.
  DNS has no website context at query time, so one global verdict cannot be
  right for both. A household rule settles it in one click.
- **D9. Every compile reads the AI rows. Every install that keeps the cache
  compares the old AI list with the new one under `rebuild_lock`, and drops
  the cached answers for exactly the names that changed.** A device edit can
  therefore never install verdicts the cache was not told about. The
  installer is woken through `Notify` with a 5 s debounce, so no committed
  verdict is lost and a burst of commits becomes one install.
- **D10. The key lives in `<data dir>/openrouter.key` with mode 0600, never in
  SQLite.** That keeps it out of `.pre-v2`, every `VACUUM INTO` copy and the
  WAL. No route returns it, nothing logs it, and the browser never caches it.
  A key is checked against `GET /api/v1/key` before it is saved, and only the
  credit limit and what remains of it are kept. OpenRouter's `label` is a
  masked copy of the key, so it is never read, stored or forwarded.
  `COGWHEEL_AI__OPENROUTER_API_KEY` wins over a saved key.
- **D11. A guard covers every AI route that writes, spends, causes egress or
  touches the key.** It checks the Host header and URI authority, `Origin`
  and `Sec-Fetch-Site`. Without it, a DNS-rebinding or cross-site page could
  swap in its own key, spend credit or wipe the list.
  `COGWHEEL_SERVER__ALLOWED_HOSTS` admits a reverse proxy. Bodies that can
  carry the key use an extractor that never logs a rejection, because serde's
  error text can quote the value.
- **D12. Set-up lives on Lists, and Settings stays read-only.** It sits in an
  "AI list" card between Subscribed lists and Rules, which is where the list
  sits in precedence. Settings gains a read-only "AI review" card, and the
  sidebar keeps five pages. The key is the one secret the UI accepts, and it
  only ever goes in.
- **D13. AI review's record of browsing lives no longer than the activity
  log.**
  - `COGWHEEL_RETENTION__HISTORY_DAYS=0` makes AI review unavailable and
    empties the AI list at startup.
  - Otherwise the website a verdict was judged for is cleared at
    `HISTORY_DAYS`. An ordinary `ignore` row lives `min(30 days,
    HISTORY_DAYS)`.
  - Clear log forgets both, and empties the reviewer's in-memory site data.
  - Block, allow and contested rows are policy, so they stay (90 days at
    most), with their websites cleared.
  - If AI review was unavailable at boot, startup deletes `ai_enabled`. It
    then stays off until someone turns it on again through the Turn on dialog.
- **D14. Spend has two layers: Cogwheel's daily limit, and the key's own
  credit limit at OpenRouter.**
  - The daily limit is 5¢, 10¢ (the default), 25¢ or $1. Spend is reserved
    before each request and settled after it. A response with no usable
    `usage.cost` is never counted as free.
  - One owner, `AiState::settle`, makes every spend write under one lock, in
    the same transaction as any verdicts it stores.
  - Each request also caps the provider's price at 1.25 × the model's listed
    price.
  - The credit limit holds at OpenRouter even if Cogwheel is wrong. The UI
    suggests giving the key one.
- **D15. Schema v2 is reached by a chained open.** It adds one table and
  changes none. `cogwheel.db.pre-v2` is taken only when the file was v1 when
  it was opened, never for a fresh file or `:memory:`.
- **D16. `COGWHEEL_AI__AVAILABLE=false` is the operator's kill switch.** The
  reviewer never starts, the AI list compiles empty, and the set-up routes
  answer 409.
- **D17. No new crates.** `Cargo.lock` stays at 222 packages. reqwest stays
  without its `json` feature and bodies go through `serde_json`. Retries and
  dispatch use `tokio::sync::Notify` and `JoinSet`, and jitter uses std
  `RandomState`.
- **D18. Off means off, at once.** There is one send gate.
  - `halt()` closes the tap, bumps a generation and aborts the requests in
    flight. It does all of this before it returns.
  - A request that turns review off, removes the key or changes the key or
    model calls it before it answers. Every other stop calls it too: the
    daily limit, a refused key or model, running out of credit, and the
    reviewer dying.
  - Every job checks the gate immediately before it sends.
  - Queued and grouped names are discarded, not drained.
  - Once that request has answered, no new request starts. A request already
    on the wire is cancelled and its answer discarded.
- **D19. A dedicated OpenRouter client, separate from the list fetcher.**
  - It has the user agent `cogwheel-dns/<version>`, a 20 s timeout and a 5 s
    connect timeout.
  - It follows no redirects, so a 3xx can never re-send household names or
    the key to another host.
  - It is HTTPS-only unless the base URL is loopback, and it ignores proxy
    settings for a loopback base, so the offline tests never leave the
    machine. Otherwise the proxy variables are honoured.
  - The base URL is set only in the environment.

### Thresholds and caps

These are constants, not settings. Changing one means amending this record.

| What | Bar or bound |
|---|---|
| A block where no household list decides the name | the model's confidence ≥ 0.85 |
| An override in either direction: an allow over a list block, or a block over a list `@@` | the role answer's confidence ≥ 0.92 **and** the effect answer's ≥ 0.90 in the matching direction ("breaks" for an allow, "works" for a block) |
| Allows over a list | at most 3 per site load and 20 per UTC day; past a cap the answer is stored as `ignore` with `why='limit'` |
| Cross-site re-checks | at most 2 per verdict per 30 days and 1 per day; an opposite answer ≥ 0.85 contests the verdict |
| New names judged | at most 24 per site load, 60 per site key per UTC day and 300 per client per hour |
| Requests | at most 2 in flight and 2,000 per UTC day, at least 1 s apart, within the daily spend limit |
| Re-judging | a block or allow is judged again when a website loads it 30 days or more after its last judgement, and sooner if the household's lists change under it |
| Verdict rows | at most 10,000, oldest first; no row outlives 90 days from its last judgement, and an ordinary `ignore` goes sooner (D13) |

The bars were set from the accuracy OpenRouter publishes for Jev 1.13. In
its batch cookbook, answers with confidence ≥ 0.8 were right 114 times in
122, and answers between 0.5 and 0.8 only 9 in 18. Other models may be more
or less sure of themselves, and the UI says so. A plain block uses 0.85: a
wrong block is visible in Activity and takes one click to undo. An override
undoes a list, which is a choice the household made, so it needs a higher bar
and a second question. Both answers come from the same model reading the same
state, so the second is a second signal, not an independent one. Nothing in
the code, docs or UI copy says otherwise.

## What leaves the house, and when

**By default, nothing.** Until someone uses the AI list's set-up form,
Cogwheel makes no request to OpenRouter.

**From the set-up form, when someone uses it.** The form can make three kinds
of request, whether review is on or off:

- the public model listings (`GET /api/v1/models?output_modalities=decisions`,
  and the same listing with `&zdr=true`). They are fetched without the key or
  any household data and cached for an hour;
- the key check (`GET /api/v1/key`), which carries the key being saved;
- a Test. It sends a fixed public example (`www.wikipedia.org`,
  `www.googletagmanager.com` and two Wikimedia names) and nothing of the
  household's.

**While AI review is on.** Review is on only when all of these hold:

- the operator has not set `AVAILABLE=false`;
- `HISTORY_DAYS` is at least 1;
- there is a key, and a model that passed a Test;
- the household turned review on.

It then sends two kinds of request:

- **Names, after a site load closes.** A device's burst of lookups ends after
  3 s of quiet or 15 s in all, with 4 s allowed for slow answers. Each
  candidate name in it is one Decisions request. The request carries the
  website (a guess), the candidate and up to 24 other names from the same
  load, along with the model id, the constant question text and the provider
  preferences.
- **A key check** at most every 10 minutes, carrying the key and no names.

Each exact name is sent once. It is sent again only when a website loads it
30 days or more after its last judgement, when the household's lists have
changed under it, or for a cross-site re-check. Repeat visits send nothing.
The pace is bounded by the table above.

**Never.** A request never carries:

- client IP addresses or device names;
- the query type or timestamps;
- which device asked;
- `session_id`, `user` or `trace`;
- referrer or title headers.

A name is sent only if it is shareable:

- it is shaped like a public domain;
- no label starts with `_`;
- it is not under `arpa`, `local`, `lan`, `home`, `internal` or another
  private suffix;
- it has no embedded IPv4 address and no identifier-like label;
- it is not at or under one of the appliance's own names, and not
  protected;
- no household rule covers it.

A household rule is how a household keeps a name of its own, and everything
under it, out of AI review. Allow is the usual choice. Some names are never
even offered to the reviewer:

- names decided by a rule;
- protected names;
- lookups made during a pause;
- devices with filtering off;
- CNAME-decided names;
- any lookup other than A, AAAA and HTTPS.

**To whom.** Requests go to `openrouter.ai` over HTTPS, and through it to the
company that runs the chosen model. The base URL is set only in the
environment, so nobody on the LAN can redirect the key. Every request sends
`provider.data_collection: "deny"`. It also sends `provider.zdr: true`, unless
`COGWHEEL_AI__ZERO_RETENTION=false`. Cogwheel asks for providers that neither
collect nor keep what they are sent, but it cannot check that they comply,
and the UI says so. When checked on 2026-10-08, 9 of the 15 decision models,
Jev 1.13 and Clef among them, had a zero-retention provider. While the default
stands, the model picker greys out the rest.

**Who pays.** The household's OpenRouter account, within the daily limit.

**When it stops.** At once (D18).

## How auditability is kept

ARCHITECTURE §1 objected that a household cannot audit a model's verdict.
That is still true of the model's reasoning, and this record does not claim
otherwise: a decision model returns a choice and a confidence, and no account
of why. What the household can audit is every verdict, and the limits on what
any verdict can do.

- **Stored.** Every judged name is one row in `ai_verdicts`, at most 10,000
  rows. A row holds:
  - the verdict and why;
  - the model's choice and confidence;
  - the effect answer and its confidence;
  - what the household's lists said when the name was judged;
  - the website it was judged for, until `HISTORY_DAYS` passes;
  - the dated model snapshot that answered;
  - when it was judged.
- **Visible.** The AI list card's Changes view shows every block and allow,
  applied or not. For each one not applied, it shows why: review is off, the
  lists changed, the lists agree, or it fell below the bar. Every row is a
  click away. A confidence is always the model's ("the model was 93% sure"),
  never Cogwheel's.
- **Attributable.** Activity marks a name the AI list decided with
  `Reason::Ai`. `GET /api/v1/check` returns the row behind a name whenever one
  exists, including when a rule or a protected suffix outranked it or it fell
  below its bar. It never invents provenance.
- **Reversible.** Any of these undoes a verdict:
  - a household or device rule, which beats it; a household rule is one
    click from Activity;
  - Forget, for one verdict;
  - Clear, for all of them;
  - turning review off, which empties the list in force and drops the cached
    answers for every name it decided;
  - the operator's `AVAILABLE=false`, which compiles it empty.
- **Outranked.** Device rules, household rules and the protected suffixes all
  sit above the AI list. A model can never block a name the household
  allowed. It can never take out the resolver, time and connectivity-check
  names the protected suffixes keep reachable.
- **Off by default.** It never comes back on by itself after it was made
  unavailable.

The reasoning cannot be audited, but these limit what it can do:

- **Thresholds** on the model's confidence, applied again at compile time
  against the live lists.
- **Exact matching**, so a crafted name earns a verdict for itself and nothing
  else.
- **Disagreements only.** Where the model agrees with the lists, it changes
  nothing.
- **Overrides are hard to win.** Overriding a list in either direction needs
  two answers above a high bar, capped per load and per day.
- **Conflicts go to the lists.** A cross-site conflict hands the name back to
  them.
- **Pages cannot vouch for themselves.** The website is never judged in its
  own load, and a blocked name is never taken as the website, so a click on a
  list-blocked link cannot whitelist itself. A name whose own site was opened
  is judged only in that site's loads, so a hostile page cannot get another
  site's names judged in its context.

**The residual risk** is recorded in SECURITY.md. On a hostile site, a
list-blocked tracker named convincingly as the site's own CDN can win an
override in that site's context. The override is:

- household-wide and for that exact name only;
- one of at most 20 a day;
- visible in Changes;
- withdrawn if another site's context calls it a tracker;
- one click to undo.

## Boundary Rules

- No model call, other network call or storage write on the DNS path. The
  reviewer and the installer are control-plane tasks. Readiness never
  includes them. If either dies, DNS keeps serving the verdicts already
  installed.
- The AI list stays below every rule and the protected suffixes, above every
  subscribed list, exact-name only, and out of `evaluate_lists`.
- Off by default. It resumes only on consent, and off means off at once.
- The reviewer, the OpenRouter client and the AI handlers never log a domain
  name, a request or response body, or the key.
- The key is never returned, logged, stored in SQLite or shown in part.
- The feature is counted as one unit under the spec's §12.1. Its own files
  have a budget of 3,900 lines, of which at most 175 may sit in
  `cogwheel-policy` and `cogwheel-dns-core`. RSS grows by nothing while review
  is off and by at most 5 MB while it is on. If the feature is ever cut, it
  is cut in one place, and the core returns to its own budget.

## Alternatives Rejected

- **The AI list as a row in `sources`.** It would take one of the 64 list
  slots. It would need a fourth `kind` that the frozen v1 schema's `CHECK`
  does not allow. And it would land at list precedence, where any list's
  `@@` beats an AI block, below the place the owner asked for.
- **A tier in `evaluate_lists`.** A cached answer would then depend on its
  aliases' AI verdicts. Invalidation would have to parse cached answers' CNAME
  chains, at about 100 ms per install on a Raspberry Pi, and would drop every
  CNAME-blocked entry each time. It would need an `AiCname` reason. And it
  would turn `ListAllow` (which skips the re-check) into an AI allow (which
  runs it), so a whitelist could block.
- **Above the protected suffixes.** They keep the resolver, time servers and
  connectivity checks reachable whatever a list says. Only a rule someone
  wrote on purpose may override them, not one wrong answer.
- **Verdicts on suffixes.** An allow of a site's apex would whitelist every
  tracker beneath it. A block judged from one name would take out names never
  judged. Exact-name invalidation would stop being complete.
- **Batching candidates in one request.** It is not the documented pattern,
  and its text references into `state` are unverified.
- **Chat models.** They follow instructions, including any planted in a
  domain name, answer in free text that would have to be parsed, and give no
  calibrated confidence to set a bar on. Decision models return a typed
  choice and a confidence, use no tools, and return no text to follow.
- **A local model.** One that could judge domains would not fit the appliance's
  RAM budget (RSS ≤ 45 MB) on the hardware it targets.
- **Uploading the subscribed lists for review.** That is about 10⁵ names with
  no site context to judge them against. "Review dns lists" is met by judging
  each name a site loads, including those the lists block.
- **The key in SQLite.** It would be copied into `.pre-v2`, every `VACUUM
  INTO` backup and the WAL.
- **An environment-only key.** Turning review on would mean a redeploy, and
  the set-up the owner asked for (bring a key, pick a model, test it) would
  not exist. The variable is kept, and it wins, for operators who want the key
  out of the UI's reach.
- **Same-site-only allows.** They would rule out the whitelisting that was
  asked for: a site's payments, consent manager or shared CDN.
- **Skipping the AI list for "No lists" devices.** It would put the AI list
  below a device's list choice, against the owner's precedence. It is
  disclosed instead: "No lists" means your rules and the AI list. A device
  that should get nothing automated can have filtering off.
- **The `psl` crate.** No new crates (D17). Site keys only group names,
  score the website guess, count caps and apply the rule that a site's names
  are judged in its own loads. They never decide policy, so a short table of
  multi-tenant suffixes and two-letter-TLD second levels is enough.
- **Flushing the whole DNS cache on every install.** Installs can come every
  few seconds while names are being judged, and each flush would empty every
  device's cache. D1 makes the exact-name sweep complete, so a flush buys
  nothing.

## Deferred

- **Per-device opt-in or opt-out.** It changes `ScopeSignature` in the
  server's `state.rs`, and the shortcut that lets devices share the
  household's scope. Until then, devices with filtering off already skip the
  AI list.
- **Batching, measured.** Several candidates per request may come later, once
  its references into `state` are verified and measured against Jev and Clef.

## Consequences

- ARCHITECTURE §1 no longer says Cogwheel does not classify. It says it does
  not unless you turn on AI review, and the promise of no outbound request
  names this one opt-in exception. The spec's §9 narrows to ML classification
  on the DNS path, or without an explicit opt-in. CONTRIBUTING still refuses a
  model API on the DNS path. New AI ideas extend this record or argue a new
  one.
- The database moves to schema v2. An image built before v2 refuses an
  upgraded file. Rolling back means restoring `cogwheel.db.pre-v2`, which
  loses the AI list and every change made since the upgrade.
- The AI list is the second most sensitive data on the box, after the query
  log. Like the log, anyone who can reach the control plane can read it.
- Anyone on the LAN who can reach the control plane can replace a key saved
  in the UI, and receive the household's names from then on. The mitigations
  are an environment key, `AVAILABLE=false` and a credit limit on the key.
- The website is a guess. DNS carries no referrer, and NAT or bridged
  networking can merge devices into one.
