//! The Cogwheel DNS appliance: a DNS forwarder that filters, and the control plane that
//! configures it.
//!
//! Startup order is the interesting part of this file. Storage opens first because everything
//! else reads it; the policy is compiled from the on-disk list cache *before* the listeners
//! bind, so the first query a household makes is already filtered; and the first network fetch
//! happens afterwards, in the background, which is why `/health/ready` answers 200 on a machine
//! with no egress at all.

mod api;
mod config;
mod http;
mod policy_build;
mod prune;
mod querylog;
mod refresh;
mod state;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use cogwheel_dns_core::{DnsRuntime, DnsRuntimeConfig, build_resolver, reserve_descriptor_table};
use cogwheel_policy::Policy;
use cogwheel_storage::Storage;
use config::AppConfig;
use policy_build::Rebuild;
use state::{Cached, RefreshGate, ScopeAllocator, ServerState, TOP_DOMAIN_TTL};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
cogwheel-server -- the Cogwheel DNS appliance

Usage:
  cogwheel-server            run the server
  cogwheel-server --version  print the version and exit
  cogwheel-server --help     print this message and exit

There are no other flags. Everything is configured by environment variable:
COGWHEEL_PROFILE, COGWHEEL_SERVER__*, COGWHEEL_STORAGE__*, COGWHEEL_UPSTREAM__*,
COGWHEEL_BLOCKING__*, COGWHEEL_UPDATER__*, COGWHEEL_RETENTION__*. On an installed
appliance those live in /etc/cogwheel/cogwheel.env. See DEPLOYMENT.md for the
full list.
";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    /// Start the server.
    Run,
    /// Write this to stdout and exit 0.
    Print(String),
    /// Write this to stderr and exit 2.
    Fail(String),
}

/// Decide what to do with the command line before any side effect happens.
///
/// The important property is that an argument this binary does not understand is a hard error
/// rather than something it ignores. An earlier build fell through to "start the server" for
/// every unknown argument, so `cogwheel-server --version` on an appliance printed nothing and
/// quietly bound a SECOND resolver next to the one the service was already running. For a
/// process whose whole job is to take over a network's DNS, refusing to start is the only safe
/// response to input it cannot parse.
fn parse_cli(args: &[String]) -> CliAction {
    let Some(first) = args.first() else {
        return CliAction::Run;
    };
    match first.as_str() {
        "--version" | "-V" => {
            CliAction::Print(format!("cogwheel-server {}\n", env!("CARGO_PKG_VERSION")))
        }
        "--help" | "-h" => CliAction::Print(USAGE.to_owned()),
        other => CliAction::Fail(format!(
            "cogwheel-server: unrecognised argument: {other}\n\n{USAGE}"
        )),
    }
}

/// Descriptors the table is grown to at boot: 512 misses in flight, each holding up to three
/// upstream sockets per attempt, plus the TCP fallbacks, listeners and HTTP connections — the
/// next doubling is never reached.
const DESCRIPTOR_TABLE_SLOTS: usize = 4096;

/// How long an outbound list fetch may take in total, and to connect.
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the DNS listeners are given to finish an in-flight query on shutdown.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    // Before the runtime exists: once it has workers, growing the descriptor table costs an RCU
    // grace period per doubling, paid on whichever worker's `socket()` call crosses the
    // boundary — under a retry wave, on all of them at once.
    let descriptors = reserve_descriptor_table(DESCRIPTOR_TABLE_SLOTS);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build runtime")?
        .block_on(run(descriptors))
}

async fn run(descriptors: usize) -> Result<()> {
    // Before init_tracing: `--version` should print a version and nothing else, not a version
    // wrapped in JSON log lines.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    match parse_cli(&args) {
        CliAction::Run => {}
        CliAction::Print(message) => {
            print!("{message}");
            return Ok(());
        }
        CliAction::Fail(message) => {
            eprint!("{message}");
            std::process::exit(2);
        }
    }

    init_tracing();
    tracing::debug!(descriptors, "descriptor table reserved");
    let config = Arc::new(AppConfig::from_env()?);
    tracing::info!(
        profile = config.profile.as_str(),
        block_mode = config.block_mode.as_str(),
        upstreams = config.upstream_servers.join(","),
        "starting"
    );

    let storage = Storage::open(&config.database_url).await?;
    let readiness = Arc::new(http::Readiness::default());
    readiness.mark_storage_ready();

    let resolver = build_resolver(&config.upstream_servers)?;
    // The runtime boots on an empty policy — every name resolves — and takes the compiled one
    // below before the listeners bind, so it is never actually queried through this.
    let (runtime, log_rx) = DnsRuntime::new(resolver, Arc::new(Policy::empty(config.block_mode)));

    // Broadcast shutdown to everything that would otherwise outlive the signal: the DNS accept
    // loops, the background tasks, and every open SSE stream. Without it, a graceful HTTP stop
    // waits forever on a stream that never ends on its own.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state = ServerState {
        lists_dir: Arc::new(config.lists_dir()),
        config: Arc::clone(&config),
        storage,
        runtime: Arc::clone(&runtime),
        readiness: Arc::clone(&readiness),
        events: querylog::EventBus::new(),
        device_names: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
        indexed_lists: Arc::new(RwLock::new(Vec::new())),
        scopes: Arc::new(Mutex::new(ScopeAllocator::new())),
        rebuild_lock: Arc::new(tokio::sync::Mutex::new(())),
        refresh_gate: Arc::new(RefreshGate::default()),
        top_domains: Arc::new(Cached::new(TOP_DOMAIN_TTL)),
        connect_targets: Arc::new(Cached::new(TOP_DOMAIN_TTL)),
        http: reqwest::Client::builder()
            .user_agent(concat!("cogwheel-dns/", env!("CARGO_PKG_VERSION")))
            .timeout(FETCH_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .context("build the list fetcher")?,
        shutdown: shutdown_rx.clone(),
    };

    api::runtime::restore(&state).await;
    // Compiled from the cached bodies alone (§2.7). No network, so a boot behind a dead link
    // still filters, and readiness does not depend on reaching a list server.
    let compiled = policy_build::rebuild(&state, Rebuild::Lists).await?;
    readiness.mark_policy_ready();
    if compiled.rules_loaded == 0 {
        tracing::warn!(
            lists = compiled.slots,
            "no list entries are cached yet; nothing is blocked until the first refresh lands"
        );
    }

    let dns_handle = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        let dns_config = DnsRuntimeConfig {
            udp_bind_addr: config.dns_udp_bind_addr,
            tcp_bind_addr: config.dns_tcp_bind_addr,
        };
        let readiness = Arc::clone(&readiness);
        let shutdown = shutdown_rx.clone();
        async move {
            runtime
                .serve_with_ready_signal(
                    dns_config,
                    move || {
                        readiness.mark_dns_ready();
                        tracing::info!("dns listeners bound");
                    },
                    shutdown,
                )
                .await
        }
    });

    let log_handle = tokio::spawn(querylog::writer(state.clone(), log_rx));
    tokio::spawn(prune::task(state.clone()));
    let refresh_handle = tokio::spawn(refresh::scheduler(state.clone()));

    let listener = tokio::net::TcpListener::bind(config.http_bind_addr)
        .await
        .context("bind http listener")?;
    tracing::info!(addr = %config.http_bind_addr, "control plane listening");

    // Fan the signal out the moment it arrives, so the DNS listeners and every open SSE stream
    // begin winding down at the same time the HTTP server stops accepting.
    let shutdown_signal = async move {
        wait_for_signal().await;
        let _ = shutdown_tx.send(true);
    };

    // Borrowed so the select does not consume it: after the HTTP server drains we still need to
    // await the DNS task, and an early DNS failure must still abort startup.
    let mut dns_handle = dns_handle;
    tokio::select! {
        result = &mut dns_handle => result.context("dns task join failure")??,
        result = refresh_handle => result.context("refresh task join failure")?,
        result = axum::serve(listener, http::app(state))
            .with_graceful_shutdown(shutdown_signal) => result.context("http server failure")?,
    }

    // The HTTP server has drained. Give the DNS listeners a bounded window to finish whatever
    // query they were part-way through; returning without waiting would drop it, which is the
    // opposite of a graceful stop. Bounded because a stuck upstream must not stop the process
    // from exiting — supervisors escalate to SIGKILL.
    match tokio::time::timeout(DRAIN_TIMEOUT, dns_handle).await {
        Ok(Ok(Ok(()))) => tracing::info!("dns listeners drained"),
        Ok(Ok(Err(error))) => tracing::warn!(%error, "dns listeners stopped with an error"),
        Ok(Err(error)) => tracing::warn!(%error, "dns task join failure during shutdown"),
        Err(_) => tracing::warn!("dns drain timed out; exiting anyway"),
    }
    // The writer flushes what it is holding when the shutdown signal reaches it. Waiting for
    // that is the difference between a clean stop and one that loses the last few seconds of the
    // query log — the one thing in this process that is not reconstructible.
    match tokio::time::timeout(DRAIN_TIMEOUT, log_handle).await {
        Ok(Ok(())) => tracing::debug!("query log flushed"),
        Ok(Err(error)) => tracing::warn!(%error, "query log writer join failure"),
        Err(_) => tracing::warn!("query log did not flush in time; exiting anyway"),
    }
    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolve on SIGINT or SIGTERM. `docker stop` and `systemctl stop` both send SIGTERM, so this
/// is the normal stop path for the appliance rather than an edge case.
async fn wait_for_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            // With no handler the other arm must still work, so park forever rather than
            // resolving immediately and triggering a spurious shutdown.
            Err(error) => {
                tracing::warn!(%error, "could not install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive(tracing::level_filters::LevelFilter::INFO.into()),
        )
        .json()
        .init();
}
