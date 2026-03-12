# DNS Hot-Path Guardrails

Cogwheel keeps the DNS request path deterministic, local, and free from networked AI dependencies.

Current guardrails:

- `crates/cogwheel-dns-core` contains the request path, cache, policy evaluation, and local classifier hook only.
- `crates/cogwheel-classifier` is limited to local scoring logic and serialization support.
- A regression test in `crates/cogwheel-dns-core/src/lib.rs` fails if either hot-path crate adds known HTTP-client or LLM-style dependencies such as `reqwest`, `ureq`, `surf`, `async-openai`, `openai-api-rs`, `ollama-rs`, `rig-core`, or `langchain-rust`.

Design expectation:

- DNS queries must never depend on a remote model call.
- Classifier decisions must remain local and deterministic for a given input and settings set.
- New AI-assisted or cloud-backed features belong in off-path control-plane services, never in `cogwheel-dns-core`.
