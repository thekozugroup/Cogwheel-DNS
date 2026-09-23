//! The UDP and TCP listeners, and what happens between a datagram arriving and bytes going back.
//!
//! Split out from the runtime itself because these are the parts with a socket in hand: a hit and
//! a block are answered inside the receive loop, and only a miss that has to ask the upstream is
//! handed to a task. Everything that decides *what* the answer is lives beside `DnsRuntime`.

use super::response::{error_response_for_payload, servfail};
use super::{
    Admitted, CachedWire, DnsRuntime, DnsRuntimeConfig, MAX_UDP_WORKERS, Probe, RD_BIT, UDP_BUFFER,
    bump,
};
use anyhow::{Context, Result};
use cogwheel_policy::{Reason, Verdict};
use hickory_proto::op::Message;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

/// What an operator reads when a DNS listener will not bind.
///
/// This is the single failure a household install actually meets: on a stock Linux host
/// `systemd-resolved` holds port 53 before Cogwheel ever starts, and the container then restarts
/// in a loop. Three documents exist to translate that, and until now the string they were
/// translating was `bind udp socket` / `Address already in use` -- which names neither the port,
/// nor the process that has it, nor the fix, all three of which are in scope right here.
fn bind_failure(err: std::io::Error, listener: &str, addr: SocketAddr) -> anyhow::Error {
    let port = addr.port();
    let guidance = match err.kind() {
        // The systemd-resolved advice is only true of port 53, and an operator who has already
        // moved Cogwheel off 53 is the one person guaranteed not to be looking at the stub
        // resolver. Naming it anyway would send them to fix something that is not their problem.
        std::io::ErrorKind::AddrInUse if port == 53 => {
            "Something else on this host already has port 53, and on a stock Linux host that is \
             systemd-resolved's stub listener. Free it with `sudo /etc/cogwheel/install.sh \
             --fix-port-53`, or `sudo sh scripts/install.sh --fix-port-53` from a checkout. \
             `sudo ss -lnptu '( sport = :53 )'` names whatever holds it. To leave it where it is \
             and move Cogwheel instead, set COGWHEEL_SERVER__DNS_UDP_BIND_ADDR and \
             COGWHEEL_SERVER__DNS_TCP_BIND_ADDR to an unprivileged port such as 0.0.0.0:5353."
                .to_string()
        }
        std::io::ErrorKind::AddrInUse => format!(
            "Something else on this host already has that port. \
             `sudo ss -lnptu '( sport = :{port} )'` names it. Stop that, or set \
             COGWHEEL_SERVER__DNS_UDP_BIND_ADDR and COGWHEEL_SERVER__DNS_TCP_BIND_ADDR to a port \
             nothing else wants."
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "Binding port {port} needs CAP_NET_BIND_SERVICE, and this process does not have it. \
             The shipped docker-compose.yml grants that capability and the systemd unit from \
             scripts/install-native.sh sets it in the bounding set; a hand-rolled deployment has \
             to do the same. To bind an unprivileged port (1024 or above) instead, set \
             COGWHEEL_SERVER__DNS_UDP_BIND_ADDR and COGWHEEL_SERVER__DNS_TCP_BIND_ADDR."
        ),
        std::io::ErrorKind::AddrNotAvailable => "No interface on this host has that address. Set \
             COGWHEEL_SERVER__DNS_UDP_BIND_ADDR and COGWHEEL_SERVER__DNS_TCP_BIND_ADDR to an \
             address this host holds, or to 0.0.0.0 for all of them."
            .to_string(),
        _ => "Set COGWHEEL_SERVER__DNS_UDP_BIND_ADDR and COGWHEEL_SERVER__DNS_TCP_BIND_ADDR to \
             bind somewhere else."
            .to_string(),
    };
    anyhow::Error::new(err).context(format!(
        "could not bind the {listener} on {addr}. {guidance}"
    ))
}

impl DnsRuntime {
    pub async fn serve(self: Arc<Self>, config: DnsRuntimeConfig) -> Result<()> {
        let (_tx, never) = watch::channel(false);
        self.serve_with_ready_signal(config, || {}, never).await
    }

    /// Serve DNS, invoking `on_ready` once both listeners are bound.
    ///
    /// The callback is what lets `/health/ready` report a real signal instead of returning 200 the
    /// moment the process starts: binding is the point at which this node can actually answer.
    pub async fn serve_with_ready_signal<F>(
        self: Arc<Self>,
        config: DnsRuntimeConfig,
        on_ready: F,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        // Bind before spawning the loops so a bind failure is reported as a startup error rather
        // than surfacing later as a dead task.
        let udp_socket = Arc::new(
            UdpSocket::bind(config.udp_bind_addr)
                .await
                .map_err(|err| bind_failure(err, "DNS UDP listener", config.udp_bind_addr))?,
        );
        let tcp_listener = TcpListener::bind(config.tcp_bind_addr)
            .await
            .map_err(|err| bind_failure(err, "DNS TCP listener", config.tcp_bind_addr))?;
        on_ready();

        // Several loops share the one socket so a hit on one core is answered while another is
        // parsing; a single loop was the serial bottleneck this replaces.
        let workers = std::thread::available_parallelism()
            .map_or(1, |cores| cores.get())
            .min(MAX_UDP_WORKERS);
        let udp_loops: Vec<_> = (0..workers)
            .map(|_| tokio::spawn(self.clone().recv_loop(udp_socket.clone(), shutdown.clone())))
            .collect();
        let tcp = tokio::spawn(self.clone().accept_tcp(tcp_listener, shutdown));
        for udp in udp_loops {
            udp.await??;
        }
        tcp.await??;
        Ok(())
    }

    pub(crate) async fn recv_loop(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut buffer = [0u8; UDP_BUFFER];
        loop {
            // Select only on the receive point. A hit being answered runs to completion below
            // before the loop comes back here, so shutdown drains in-flight work rather than
            // cancelling it and dropping the client's answer.
            let (size, peer) = tokio::select! {
                result = socket.recv_from(&mut buffer) => result?,
                _ = shutdown.changed() => {
                    tracing::info!("udp listener stopping");
                    return Ok(());
                }
            };
            let payload = &buffer[..size];
            if let Err(error) = self.handle_udp(&socket, payload, peer).await {
                tracing::warn!(%error, "failed to handle udp dns query");
                if let Ok(bytes) = error_response_for_payload(payload).to_vec() {
                    // The client is retrying either way; a second failure adds nothing.
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        }
    }

    /// One UDP datagram: answer a hit or a block here, hand the rest to a task, never wait on
    /// the upstream.
    async fn handle_udp(
        self: &Arc<Self>,
        socket: &Arc<UdpSocket>,
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<()> {
        let started = Instant::now();
        let admitted = match self.admit(payload, peer.ip(), started) {
            Ok(admitted) => admitted,
            Err(rejection) => {
                socket.send_to(&rejection.to_vec()?, peer).await?;
                return Ok(());
            }
        };
        match self.probe(&admitted.key, started) {
            Probe::Hit(entry) => {
                self.count_hit(&entry);
                let bytes = wire_for(&entry, &admitted.request, admitted.edns_max);
                // Sampled before the send: the latency counters measure this server's own
                // work, and the loopback delivery plus the client's wake-up is the kernel's.
                self.stats.record_hit(started.elapsed());
                socket
                    .send_to(&bytes, peer)
                    .await
                    .context("send udp response")?;
                // Logged after the answer is out, per §5.2: resolving the list name and waking
                // the writer task are bookkeeping, and nothing about them is worth adding to
                // the time a stub waits.
                self.log(&admitted, entry.verdict);
            }
            Probe::Miss(stale) => {
                let verdict = self.decide(&admitted);
                // A block is answered here, in the loop, and not handed to a task. The whole of
                // it is a policy lookup and one encode — there is no upstream in a block, so
                // there is nothing to wait for, and deferring it would add a scheduling hop to
                // the one query shape a blocklist exists for. It also leaves the miss permits
                // for the misses that can actually park on the network.
                if verdict.is_blocked() {
                    self.finish_udp_miss(socket, admitted, verdict, stale, peer)
                        .await;
                    return Ok(());
                }
                let Ok(permit) = Arc::clone(&self.miss_permits).try_acquire_owned() else {
                    bump(&self.stats.dropped_total);
                    socket
                        .send_to(&servfail(&admitted.request).to_vec()?, peer)
                        .await?;
                    return Ok(());
                };
                let runtime = Arc::clone(self);
                let socket = Arc::clone(socket);
                tokio::spawn(async move {
                    let _permit = permit;
                    runtime
                        .finish_udp_miss(&socket, admitted, verdict, stale, peer)
                        .await;
                });
            }
        }
        Ok(())
    }

    async fn finish_udp_miss(
        &self,
        socket: &UdpSocket,
        admitted: Admitted,
        verdict: Verdict,
        stale: Option<Arc<CachedWire>>,
        peer: SocketAddr,
    ) {
        let (bytes, verdict) = match self.resolve_miss(&admitted, verdict, stale).await {
            Ok(wire) => (
                wire_for(&wire, &admitted.request, admitted.edns_max),
                wire.verdict,
            ),
            Err(error) => {
                tracing::warn!(%error, domain = %admitted.key.domain, "failed to resolve query");
                match servfail(&admitted.request).to_vec() {
                    Ok(bytes) => (bytes, Verdict::allow(Reason::NoMatch)),
                    Err(error) => {
                        tracing::warn!(%error, "failed to encode servfail");
                        return;
                    }
                }
            }
        };
        self.stats.record_miss(admitted.started.elapsed());
        if let Err(error) = socket.send_to(&bytes, peer).await {
            tracing::warn!(%error, "failed to send udp dns response");
        }
        self.log(&admitted, verdict);
    }

    async fn accept_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            let (stream, peer) = tokio::select! {
                result = listener.accept() => result?,
                _ = shutdown.changed() => {
                    tracing::info!("tcp listener stopping");
                    return Ok(());
                }
            };
            let runtime = self.clone();
            tokio::spawn(async move {
                if let Err(error) = runtime.handle_tcp_stream(stream, peer).await {
                    tracing::warn!(%error, "failed to handle tcp dns query");
                }
            });
        }
    }

    async fn handle_tcp_stream(&self, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let mut len_buffer = [0u8; 2];
        stream.read_exact(&mut len_buffer).await?;
        let length = usize::from(u16::from_be_bytes(len_buffer));
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;
        let response = match self.answer_tcp(&payload, peer.ip()).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "failed to resolve tcp dns query");
                error_response_for_payload(&payload).to_vec()?
            }
        };
        let length = u16::try_from(response.len()).context("tcp response exceeds 64 KiB")?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        Ok(())
    }

    /// TCP is the retry path for a truncated UDP answer, so it never truncates, and it runs the
    /// miss inline: a connection is already a per-client resource, so no permit is needed.
    async fn answer_tcp(&self, payload: &[u8], client: IpAddr) -> Result<Vec<u8>> {
        let started = Instant::now();
        let admitted = match self.admit(payload, client, started) {
            Ok(admitted) => admitted,
            Err(rejection) => return Ok(rejection.to_vec()?),
        };
        let (wire, hit) = match self.probe(&admitted.key, started) {
            Probe::Hit(entry) => {
                self.count_hit(&entry);
                (entry, true)
            }
            Probe::Miss(stale) => {
                let verdict = self.decide(&admitted);
                (self.resolve_miss(&admitted, verdict, stale).await?, false)
            }
        };
        let bytes = wire_for(&wire, &admitted.request, usize::MAX);
        if hit {
            self.stats.record_hit(started.elapsed());
        } else {
            self.stats.record_miss(started.elapsed());
        }
        self.log(&admitted, wire.verdict);
        Ok(bytes)
    }
}

/// The bytes to send for `request`: the cached answer, or its TC form when the answer would not
/// fit the client's datagram, with the header patched to this request.
pub(crate) fn wire_for(entry: &CachedWire, request: &Message, max_payload: usize) -> Vec<u8> {
    let bytes = match &entry.truncated {
        Some(truncated) if entry.bytes.len() > max_payload => truncated,
        _ => &entry.bytes,
    };
    let mut out = bytes.to_vec();
    patch_header(
        &mut out,
        request.metadata.id,
        request.metadata.recursion_desired,
    );
    out
}

/// Make a cached response answer this request: its id, and its RD bit (RFC 1035 §4.1.1 says
/// the response copies it from the query).
pub(crate) fn patch_header(bytes: &mut [u8], id: u16, recursion_desired: bool) {
    if let Some([hi, lo, flags]) = bytes.first_chunk_mut::<3>() {
        [*hi, *lo] = id.to_be_bytes();
        *flags = (*flags & !RD_BIT) | (u8::from(recursion_desired) * RD_BIT);
    }
}
