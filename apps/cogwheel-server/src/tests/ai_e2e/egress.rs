//! F01 end to end: a name whose lookup failed, or came back with an address inside the house,
//! never reaches a request to OpenRouter, even under a domain no suffix list knows. Real DNS
//! listeners in front of a loopback upstream, the runtime's own log entries through the query-log
//! writer and the tap, the reviewer's pipeline, and the scripted OpenRouter that records what it
//! was sent.

use super::isolation::{ask, serve_dns, write_entries};
use super::{answer, rig};
use crate::ai::burst::{LATE, QUIET};
use crate::ai::tests::review::at;
use crate::tests::openrouter_stub::{CONSENT, DECISIONS};
use cogwheel_dns_core::{DnsRuntime, build_resolver};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

const WEBSITE: &str = "www.news-site.com";

/// A loopback upstream: A records from its zone, NXDOMAIN for every name it does not have.
struct Upstream {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn serve(records: &[(&str, [u8; 4])]) -> Self {
        let mut zone: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
        for (name, address) in records {
            zone.entry((*name).to_owned())
                .or_default()
                .push(Ipv4Addr::from(*address));
        }
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind the upstream");
        let address = socket.local_addr().expect("the upstream's address");
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                if let Some(reply) = reply(&buffer[..size], &zone) {
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        });
        Self { address, task }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The reply to one query, spelled on the wire by hand: this crate has no DNS library of its own,
/// and one question with A records is all it takes.
fn reply(query: &[u8], zone: &HashMap<String, Vec<Ipv4Addr>>) -> Option<Vec<u8>> {
    let header = query.get(..12)?;
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*query.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        labels.push(std::str::from_utf8(query.get(at..at + length)?).ok()?);
        at += length;
    }
    let qtype = query.get(at..at + 2)?;
    let question = query.get(12..at + 4)?;
    let known = zone.get(&labels.join(".").to_ascii_lowercase());
    let addresses = known
        .filter(|_| qtype == [0, 1])
        .map_or(&[][..], Vec::as_slice);

    let mut reply = header[..2].to_vec();
    // QR with the query's RD; then RA, and NOERROR or NXDOMAIN.
    reply.push(0x80 | (header[2] & 0x01));
    reply.push(if known.is_some() { 0x80 } else { 0x83 });
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&u16::try_from(addresses.len()).ok()?.to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(question);
    for address in addresses {
        // The question's name by pointer, A, IN, five minutes, four bytes.
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4]);
        reply.extend_from_slice(&address.octets());
    }
    Some(reply)
}

/// A device opens a website, and in the same few seconds looks up two names of the household's
/// own — under `smith-home.net`, which no suffix list names — and a search-domain guess that does
/// not exist. All four pass `sendable`; only the answers give them away, and none is sent.
#[tokio::test]
async fn a_name_that_resolved_privately_or_not_at_all_is_never_sent() {
    let script = (0..2)
        .map(|_| (DECISIONS, answer("block", 0.95, 0.00002)))
        .collect();
    let mut rig = rig(script, &CONSENT).await;
    let upstream = Upstream::serve(&[
        (WEBSITE, [203, 0, 113, 10]),
        ("img.news-cdn.com", [198, 51, 100, 7]),
        ("pixel.tracker-site.com", [192, 0, 2, 44]),
        ("printer.smith-home.net", [192, 168, 1, 30]),
        // One private address among public ones is enough.
        ("nas.smith-home.net", [203, 0, 113, 77]),
        ("nas.smith-home.net", [10, 0, 0, 5]),
    ])
    .await;
    let resolver = build_resolver(&[upstream.address.to_string()]).expect("a resolver");
    let (runtime, mut log_rx) = DnsRuntime::new(resolver, rig.state().runtime.current_policy());
    rig.harness.state.runtime = runtime;
    let mut tap = rig.harness.take_tap();
    let (address, stop, dns) = serve_dns(rig.state()).await;

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a client socket");
    let lookups = [
        (WEBSITE, true),
        ("printer.smith-home.net", false),
        ("img.news-cdn.com", true),
        // The device's search domain tried first, as a stub with one configured does.
        ("www.news-site.com.smith-home.net", false),
        ("pixel.tracker-site.com", true),
        ("nas.smith-home.net", false),
    ];
    let mut entries = Vec::new();
    for (id, (name, public)) in (1..).zip(lookups) {
        ask(&socket, address, id, name).await;
        let entry = tokio::time::timeout(Duration::from_secs(5), log_rx.recv())
            .await
            .expect("logged")
            .expect("the log channel is open");
        assert_eq!((&*entry.domain, entry.answered_public), (name, public));
        entries.push(entry);
    }
    let last = entries
        .iter()
        .map(|entry| entry.ts)
        .max()
        .unwrap_or_default();

    // The writer offers what it drains to the tap; the worker pushes what the tap gives it.
    write_entries(rig.state(), entries).await;
    let mut offered = Vec::new();
    while let Ok(seen) = tap.try_recv() {
        offered.push(seen.domain.to_string());
        rig.pipeline.push(seen);
    }
    assert_eq!(
        offered,
        [WEBSITE, "img.news-cdn.com", "pixel.tracker-site.com"]
    );
    let t = i64::from(last) + QUIET + LATE;
    let policy = rig.state().runtime.current_policy();
    rig.pipeline.tick(at(t), &policy);
    assert_eq!(
        rig.pipeline.waiting(),
        2,
        "the two public names, and no other"
    );
    rig.run(t, t + 20).await;

    let decisions: Vec<_> = rig
        .stub
        .requests()
        .into_iter()
        .filter(|request| request.target == DECISIONS)
        .collect();
    assert_eq!(decisions.len(), 2);
    let mut candidates = Vec::new();
    for request in &decisions {
        let body = request.json();
        assert_eq!(body["state"]["website"], WEBSITE);
        candidates.push(
            body["state"]["candidate"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        );
        let text = String::from_utf8_lossy(&request.body);
        for private in ["smith-home", "printer", "nas.", "192.168", "10.0.0.5"] {
            assert!(!text.contains(private), "{private} left the house: {text}");
        }
    }
    candidates.sort();
    assert_eq!(candidates, ["img.news-cdn.com", "pixel.tracker-site.com"]);

    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(5), dns)
        .await
        .expect("the DNS listeners stopped")
        .expect("and stopped cleanly");
}
