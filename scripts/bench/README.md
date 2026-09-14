# Cogwheel bench harness

Four stdlib-only Python 3 scripts that produce the numbers in spec
[`docs/spec-dnsnet-plus-four.md`](../../docs/spec-dnsnet-plus-four.md) §12
("Before / after") and satisfy §11's benchmark gate B. Nothing here needs
`pip install` anything -- that is deliberate, so this directory can be
dropped onto a bare Raspberry Pi OS install in Phase 4 and just run.

| File | What it is |
|---|---|
| `dnsproto.py` | Minimal RFC 1035 (+ EDNS0) wire encode/decode shared by everything below. Not a script -- no CLI. |
| `stats.py` | Percentile/summary-statistics helpers, also shared. Not a script. |
| `stub_upstream.py` | A fake upstream resolver: instant, deterministic answers so benchmark numbers don't depend on the real internet being fast that day. |
| `dnsbench.py` | Single-query-at-a-time latency client: cold-miss, cache-hit, blocked, and first-time-blocked-miss distributions. |
| `mpbench.py` | Multiprocess closed-loop throughput: QPS, latency percentiles, and (given a server PID) CPU cost per query. |
| `run.py` | The full gate-B driver: starts the stub + a list HTTP server + the release binary, seeds a list and a rule, and runs every measurement in spec §12 plus the correctness checks §11 calls for. |
| `test_helpers.py` | `unittest` suite for `dnsproto.py`, `stats.py`, and `stub_upstream.py`'s response builder. No network. |

## Quick self-test (no Cogwheel binary needed)

The fastest way to prove your Python install can run these scripts at all,
before pointing `run.py` at a real binary:

```sh
cd scripts/bench
python3 -m py_compile *.py
python3 -m unittest discover -s .

# start the fake upstream, then measure against it directly
python3 stub_upstream.py --port 35399 &
STUB=$!
python3 dnsbench.py --host 127.0.0.1 --port 35399 --cold-miss-count 100 --cache-hit-repeat 500
python3 mpbench.py  --host 127.0.0.1 --port 35399 --workers 4 --queries 5000 --prime --pid $STUB
kill $STUB
```

`dnsbench.py` and `mpbench.py` against the stub don't measure anything
about Cogwheel -- the stub isn't a resolver that blocks or caches anything
-- they exist to prove the *client and its statistics math* are correct.
On a 4-vCPU sandbox this comfortably clears the stub's own "~30k QPS"
sustain target with `mpbench.py --workers 4 --queries 25000` (workers x
queries per worker = total): four single-threaded closed-loop clients
against one single-threaded `stub_upstream.py` measured 38.5k round trips/s
overall, i.e. the fake upstream is not the bottleneck at that load.

## Fetching the real list for local runs

`run.py` needs an actual blocklist, not a synthetic one -- the whole point
of the "rules_loaded >= 55000" gate is proving the real ~56k-line index
Cogwheel ships by default performs, and a small hand-written test list
would tell you nothing about that. Fetch it yourself; it is not committed
here (it's ~1.2 MB of third-party data that changes daily, and vendoring a
stale copy would make every future run compare against the wrong list):

```sh
curl -fsSL -o /tmp/oisd-small.txt https://small.oisd.nl
```

Recorded for reference (fetched 2026-09-13, this WILL differ on any later
fetch -- oisd regenerates the list roughly hourly): **55,950 lines total,
55,939 of them `||domain^` block rules** (the rest are the ABP header
comment lines `[Adblock Plus]` / `! Title: ...` / etc.). Spec §11 gate B's
"~55,850 ABP lines" and the "`rules_loaded >= 55000`" floor both describe
this same list at roughly this same size.

## Running the full gate-B driver

Build the release binary and run:

```sh
cargo build --release --locked -p cogwheel-server
python3 scripts/bench/run.py \
    --label phase3 \
    --list-file /tmp/oisd-small.txt \
    --http-port 38080 --dns-port 35353 \
    --db /tmp/cogwheel-bench.db \
    --out /tmp/bench-results
```

This is a slow, thorough run, not a quick smoke test -- expect a few
minutes, most of it the deliberate 75 s wait built into the prune-cap
phase. It:

1. Starts `stub_upstream.py` on loopback and a `python3 -m http.server`
   serving your list file, then the release binary wired to both via the
   `COGWHEEL_*` environment (spec §8) matching gate B: loopback binds,
   `COGWHEEL_UPSTREAM__SERVERS` pointed at the stub, `null_ip` blocking by
   default.
2. Waits for `/health/ready`, `POST`s the list and a household block rule
   for `ads.example.com` (the same fixture `verify-install.sh` and
   `pi-acceptance.sh` already use), and waits for
   `overview.lists.rules_loaded >= 55000`.
3. Runs every §12 measurement (cold-miss/cache-hit/blocked/first-time-
   blocked-miss latency, throughput, RSS, CPU per query, binary size) plus
   the extra correctness checks gate B calls for: AAAA-after-A (a cached A
   answer must never leak into an AAAA response for the same name),
   CNAME-cloak blocking (a list entry covering the CNAME *target* must block
   the name that points at it), a hung upstream (`SIGSTOP` the stub; cache hits must
   stay under 5 ms even with misses stuck behind it; `SIGCONT` after),
   `blocked_total` exactness (the counter's delta must equal exactly the
   number of answers actually served blocked), database growth per logged
   row, and `GET /queries` / `GET /overview` latency once the log has real
   volume in it.
4. Restarts the server twice more, each against its own fresh database:
   once with `COGWHEEL_RETENTION__HISTORY_DAYS=0` to compare
   server-internal cache-hit latency against the first run (proving query
   logging isn't adding hot-path cost), and once with a small
   `QUERY_LOG_MAX_ROWS` and the 60 s `PRUNE_INTERVAL_SECS` floor to prove
   the prune actually enforces the cap.
5. Writes `<out>/bench_<label>.json`, prints a summary table, and exits
   non-zero with a clear message if the binary is missing, a route 404s
   (most likely meaning the server isn't on the Phase 3 API yet), or an
   assertion fails -- see "Failure modes" below.

Every child process (the stub, the list HTTP server, all three server
lifecycles) is tracked and killed by PID on the way out, whether `run.py`
finishes normally, hits an unhandled exception, or is interrupted
(`SIGINT`/`SIGTERM`) -- verified in this session by watching
`ss -ltnup`/`ps` before and after, including a deliberately-broken run that
died mid-phase.

Tune the workload with the optional flags (`--cold-miss-count`,
`--throughput-workers` / `--throughput-queries`, `--growth-rows`,
`--prune-max-rows`, `--prune-wait-secs`, ...) -- `--help` lists all of them
with their defaults, which match spec §12's own workload sizes (4 workers x
25,000 queries for throughput, etc).

### What this has been validated against

`run.py` has been run end to end against the real release
`cogwheel-server` on the Phase 3 API, and the numbers it produced are the
ones in spec §12's "after" column. Also checked:

- `python3 -m py_compile` on every file here.
- The full `test_helpers.py` suite (37 tests: wire format round-trips,
  compression-pointer following and loop rejection, percentile/summary
  math, and `stub_upstream.py`'s response builder for every case it
  handles -- plain A/AAAA, the `cname.test` CNAME chain, unhandled qtypes,
  and malformed input).
- `stub_upstream.py` and `dnsbench.py` against each other, and
  `stub_upstream.py` and `mpbench.py` against each other (throughput, CPU
  accounting via `/proc/<pid>/stat`, graceful failure against a closed
  port and an unreadable PID).

Three measurement bugs that only a real server could expose were found and
fixed on that first real run, all of them in this harness rather than in
Cogwheel:

- **The CNAME-cloak check asserted the wrong thing.** It put the cloak
  target behind a *household rule*, but spec §6 step 11 re-runs only steps
  8-10 over CNAME targets -- protected suffixes and the list tier -- because
  a user's rule names the query, not the aliases behind it. The fixture is
  now a one-line `data:` list, and `cname_blocks_total` moving by one
  confirms step 11 actually fired rather than the answer merely looking
  blocked.
- **Database growth double-counted the WAL.** Summing `<db>` and `<db>-wal`
  counts a page once in the WAL and again in the main file after it
  checkpoints, which reported 176 B/row against a table whose real settled
  cost is ~88 B/row. Sizes are now taken after a `wal_checkpoint(TRUNCATE)`,
  and `db_bytes_per_row_settled` divides the whole finished database by every
  row in it, which does not depend on where a 4 KiB page boundary happens to
  land inside a 3,000-row window.
- **The HISTORY_DAYS=0 comparison was not like-for-like.**
  `cache_hit_latency_avg_ns` is cumulative over the process lifetime, so the
  main run's value was dominated by the 100,000 hits of its throughput phase
  while the logging-off run only ever saw 1,000 -- making logging-off look
  1.3 us *slower*. Both phases now report
  `cache_hit_server_internal_window_ns`, bracketed around the same scenario
  at the same repeat count.

## `dnsbench.py` on its own

```sh
python3 dnsbench.py --host 127.0.0.1 --port 35353 \
    --cold-miss-count 200 --cache-hit-repeat 1000 \
    --blocked-domain ads.example.com --blocked-repeat 500 --block-mode null_ip \
    --blocklist-file /tmp/oisd-small.txt --blocklist-sample 500
```

`--blocked-domain` and `--blocklist-file` are each optional and switch on
their own scenario; cold-miss and cache-hit always run and need nothing but
a live UDP responder, which is what makes running this against
`stub_upstream.py` directly a meaningful test of the client itself. Exits
non-zero if literally every query failed (wrong port, nothing listening).

`--block-mode` must match the server's `COGWHEEL_BLOCKING__MODE` --
`null_ip` (0.0.0.0/`::`), `nxdomain`, `nodata` (NOERROR, no answers), or
`refused` -- otherwise the "was this actually blocked?" assertion is
checking for the wrong shape of answer and every blocked-domain probe will
read as a mismatch even though the server did the right thing.

## `mpbench.py` on its own

```sh
python3 mpbench.py --host 127.0.0.1 --port 35353 --workers 4 --queries 25000 --prime --pid $(pgrep cogwheel-server)
```

`--pid` is optional; without it you get QPS and latency percentiles but no
`server_cpu` block. `cpu_us_per_query` and `cores_busy` come from
`/proc/<pid>/stat`'s `utime`+`stime`, which on Linux is quantized to
whatever `SC_CLK_TCK` is (usually 100 Hz = 10 ms per tick) -- at low query
counts the whole delta can be one or two ticks, which is why the number
comes out suspiciously round (e.g. exactly 100 µs/query). Use a query count
in the tens of thousands (the default is `--queries 25000` *per worker*)
so the tick-quantization error is small relative to the total.

## Reading `bench_<label>.json`

Top level:

```jsonc
{
  "label": "...", "generated_at": "...", "binary": "...", "binary_size_bytes": 0,
  "list_file": "...", "list_line_count": 0, "http_port": 0, "dns_port": 0,
  "main": { /* everything from the default-retention run -- see below */ },
  "history_days_zero": {
    "logging_reported_off": true,
    "cache_hit_server_internal_ns": 0.0
  },
  "prune_cap": {
    "max_rows_configured": 0, "rows_inserted": 0,
    "rows_after_prune_wait": 0, "within_cap": true
  }
}
```

`main` (the primary, default-retention lifecycle) carries most of spec
§12's rows:

| JSON path under `main` | §12 row |
|---|---|
| `startup_ms` | (new in Phase 3: exec -> `/health/ready`) |
| `list_activation_ms` | "List activation" |
| `rss_idle_after_load_kb` / `rss_hwm_after_load_kb` | "RSS with oisd small loaded" |
| `rss_after_bench_kb` / `rss_hwm_after_bench_kb` | (new: RSS after the full measurement battery, not just idle) |
| `cache_hit_server_internal_ns` | "Cache hit, server-internal" (lifetime mean, the §12 row) |
| `cache_hit_server_internal_window_ns` | the same, over the hit scenario alone -- what `history_days_zero` compares against |
| `dnsbench.cache_hit.ms.{p50,p95,p99}` | "Cache hit, client p50 / p99" |
| `dnsbench.blocked.ms.{p50,p95,p99}` | "Blocked p50 / p99" |
| `dnsbench.blocked.all_blocked_correctly` | (assertion backing that row, not a number) |
| `dnsbench.first_time_blocked_miss.ms.p50` | "First-time blocked miss (55,852 rules)" |
| `dnsbench.cold_miss.ms.*` | (new: first-lookup latency for an *allowed* name) |
| `throughput.qps` | "Throughput (4x25,000)" |
| `throughput.server_cpu.cpu_us_per_query` | "Server CPU per query" |
| `blocked_total.exact` | "`blocked_total` accuracy" |
| `aaaa_after_a.correct` | (spec §10 "cache key omits qtype" regression) |
| `cname_cloak.blocked` | (spec §6 step 11, CNAME target re-evaluation) |
| `hung_upstream.stayed_under_5ms` | (spec §5.2 miss hand-off: hits must never queue behind misses) |
| `db_growth_bytes_per_row` | (spec §7's "~55 B/row on disk" estimate), measured over `--growth-rows` |
| `db_bytes_per_row_settled` | the same cost measured as the whole finished database over every row in it |
| `query_log_rows_total` / `db_total_bytes` | what that ratio is taken from |
| `queries_endpoint_ms.p50` | `GET /api/v1/queries?limit=200` latency |
| `overview_endpoint_ms.p50` | `GET /api/v1/overview` latency |

`binary_size_bytes` at the top level is spec §12's "Binary (x86_64,
stripped)" row.

## What changed in this harness during Phase 3

Two of these rows are not directly comparable with the numbers spec §12
records for Phase 2, because the way they are taken changed here. Nothing
else did -- in particular the cold-miss, cache-hit, blocked and
first-time-blocked-miss scenarios are the same `dnsbench` calls with the same
defaults, so those rows compare straight across.

- **`db_growth_bytes_per_row`** now checkpoints the WAL before it measures,
  and measures the main database file rather than the sum of the file and its
  WAL. The old sum double-counted every page that had been checkpointed since
  the run began (the WAL keeps its size after a checkpoint drains it), which
  reported 176 B/row for a table whose settled cost was ~88. `db_bytes_per_row_settled`
  was added beside it: the finished file divided by every row in it, which is
  what actually answers "what will the 250,000-row cap cost on disk?".
- **`cache_hit_server_internal_ns`** is still the lifetime mean the Overview
  exposes, but `cache_hit_server_internal_window_ns` was added and is what the
  `HISTORY_DAYS=0` phase is compared against. The lifetime mean is dominated
  by whichever workload ran most: the main run's 100,000 throughput hits
  against the logging-off run's 1,000, which made logging-off look *slower*.
- The **CNAME-cloak fixture** is now a one-line `data:` list rather than a
  household rule, because §6 step 11 re-runs only steps 8-10 over a CNAME
  target -- the protected suffixes and the list tier, never the rule tiers.
  The old fixture tested a path the spec does not have. It adds a second
  enabled list before the latency scenarios run; that costs one more mask bit
  and nothing else.

Phase 3 also put a query log under every one of these numbers for the first
time: each answered query now hands an entry to a writer task that batches
into SQLite every five seconds. Compare a Phase 3 latency row against Phase 2
with that in mind -- Phase 2 measured a resolver that persisted nothing.

## Failure modes

- **Binary missing or not executable**: `run.py` exits 2 immediately with a
  message naming the exact `cargo build` command, before starting anything.
- **A route 404s**: `run.py` exits 3 with a message naming the path and a
  reminder that this driver targets the Phase 3 API. Every child process
  already started (stub, list server, whatever server lifecycle was
  mid-flight) is still killed on the way out.
- **Everything else unhandled**: exit 1 with the exception message; cleanup
  still runs. This is deliberately the least specific path -- if you hit it
  routinely for one particular failure, that failure probably deserves its
  own `BenchError` with a clearer message, not a wider `except`.
- **`dnsbench.py` / `mpbench.py` run standalone** against a target that
  never answers a single query: both exit 1 (not the exit-0-with-empty-
  stats they'd otherwise give you) with a message to stderr, after still
  writing whatever JSON they have.
