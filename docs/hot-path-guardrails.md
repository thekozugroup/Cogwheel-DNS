# DNS Hot-Path Guardrails

Cogwheel keeps the DNS request path deterministic and local: the only network
call a query can make is to the configured upstream resolver.

Current guardrails:

- `crates/cogwheel-dns-core` contains the listeners, the request path, the
  response cache, per-client policy selection and CNAME uncloaking, and
  nothing else. It depends on `cogwheel-policy` only.
- Fetching blocklists over HTTP lives in `crates/cogwheel-lists` and the
  server, never in the hot path.
- The test `hot_path_crates_remain_llm_and_network_independent` in
  `crates/cogwheel-dns-core/src/lib.rs` fails if the crate's manifest gains a
  known HTTP-client or LLM-style dependency such as `reqwest`, `ureq`, `surf`,
  `async-openai`, `openai-api-rs`, `ollama-rs`, `rig-core` or `langchain-rust`.

Design expectation:

- Answering a query must never depend on a remote model, a web service or a
  storage write. `PolicyEngine::evaluate` is pure; the cache and the counters
  are in memory.
- A blocklist refresh that fails leaves the policy already in force serving.
- New cloud-backed or AI-assisted features belong in off-path control-plane
  code, never in `cogwheel-dns-core`.
