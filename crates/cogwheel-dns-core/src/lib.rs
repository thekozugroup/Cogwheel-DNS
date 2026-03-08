use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cogwheel_classifier::{Classification, ClassifierSettings, classify_domain};
use cogwheel_policy::{BlockMode, DecisionKind, PolicyEngine, RuleAction, normalize_domain};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::TokioResolver;
use moka::future::Cache;
use serde::Serialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_CNAME_UNCLOAK_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct DnsRuntimeConfig {
    pub udp_bind_addr: SocketAddr,
    pub tcp_bind_addr: SocketAddr,
}

type ClassificationObserver = Arc<dyn Fn(ClassificationEvent) + Send + Sync>;

#[derive(Clone)]
pub struct DnsRuntime {
    resolver: TokioResolver,
    policy: Arc<RwLock<Arc<PolicyEngine>>>,
    classifier_settings: Arc<RwLock<ClassifierSettings>>,
    classification_observer: Arc<RwLock<Option<ClassificationObserver>>>,
    cache: Cache<String, CachedLookup>,
    fallback_cache: Cache<String, CachedLookup>,
    stats: Arc<DnsRuntimeStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassificationEvent {
    pub domain: String,
    pub client_ip: Option<String>,
    pub classification: Classification,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct CachedLookup {
    response: Message,
}

#[derive(Debug, Default)]
pub struct DnsRuntimeStats {
    upstream_failures_total: AtomicU64,
    fallback_served_total: AtomicU64,
    cache_hits_total: AtomicU64,
    cname_uncloaks_total: AtomicU64,
    cname_blocks_total: AtomicU64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnsRuntimeSnapshot {
    pub upstream_failures_total: u64,
    pub fallback_served_total: u64,
    pub cache_hits_total: u64,
    pub cname_uncloaks_total: u64,
    pub cname_blocks_total: u64,
}

impl DnsRuntime {
    pub fn new(
        resolver: TokioResolver,
        policy: Arc<PolicyEngine>,
        classifier_settings: ClassifierSettings,
    ) -> Self {
        Self {
            resolver,
            policy: Arc::new(RwLock::new(policy)),
            classifier_settings: Arc::new(RwLock::new(classifier_settings)),
            classification_observer: Arc::new(RwLock::new(None)),
            cache: Cache::new(10_000),
            fallback_cache: Cache::new(10_000),
            stats: Arc::new(DnsRuntimeStats::default()),
        }
    }

    pub fn replace_policy(&self, policy: Arc<PolicyEngine>) {
        if let Ok(mut guard) = self.policy.write() {
            *guard = policy;
        }
        self.cache.invalidate_all();
        self.fallback_cache.invalidate_all();
    }

    pub fn classifier_settings(&self) -> ClassifierSettings {
        self.classifier_settings
            .read()
            .expect("classifier settings lock poisoned")
            .clone()
    }

    pub fn replace_classifier_settings(&self, settings: ClassifierSettings) {
        if let Ok(mut guard) = self.classifier_settings.write() {
            *guard = settings;
        }
    }

    pub fn set_classification_observer(&self, observer: ClassificationObserver) {
        if let Ok(mut guard) = self.classification_observer.write() {
            *guard = Some(observer);
        }
    }

    pub fn snapshot(&self) -> DnsRuntimeSnapshot {
        DnsRuntimeSnapshot {
            upstream_failures_total: self.stats.upstream_failures_total.load(Ordering::Relaxed),
            fallback_served_total: self.stats.fallback_served_total.load(Ordering::Relaxed),
            cache_hits_total: self.stats.cache_hits_total.load(Ordering::Relaxed),
            cname_uncloaks_total: self.stats.cname_uncloaks_total.load(Ordering::Relaxed),
            cname_blocks_total: self.stats.cname_blocks_total.load(Ordering::Relaxed),
        }
    }

    pub async fn probe_domain(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ResponseCode> {
        let request = build_probe_request(domain, record_type)?;
        let response = self.handle_wire_query(&request.to_vec()?, None).await?;
        Ok(response.response_code())
    }

    pub async fn serve(self: Arc<Self>, config: DnsRuntimeConfig) -> Result<()> {
        let udp = tokio::spawn(self.clone().serve_udp(config.udp_bind_addr));
        let tcp = tokio::spawn(self.clone().serve_tcp(config.tcp_bind_addr));
        udp.await??;
        tcp.await??;
        Ok(())
    }

    async fn serve_udp(self: Arc<Self>, bind_addr: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind udp socket")?;
        let mut buffer = [0u8; 4096];
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await?;
            let response = self
                .handle_wire_query(&buffer[..size], Some(peer))
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "failed to handle udp dns query");
                    error_response_for_payload(&buffer[..size])
                });
            let response_bytes = response.to_vec()?;
            socket.send_to(&response_bytes, peer).await?;
        }
    }

    async fn serve_tcp(self: Arc<Self>, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .context("bind tcp listener")?;
        loop {
            let (stream, peer) = listener.accept().await?;
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
        let length = u16::from_be_bytes(len_buffer) as usize;
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).await?;
        let response = self.handle_wire_query(&payload, Some(peer)).await?;
        let response_bytes = response.to_vec()?;
        stream
            .write_all(&(response_bytes.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&response_bytes).await?;
        Ok(())
    }

    async fn handle_wire_query(
        &self,
        payload: &[u8],
        client_addr: Option<SocketAddr>,
    ) -> Result<Message> {
        let request = Message::from_vec(payload)?;
        let query = request
            .queries()
            .first()
            .cloned()
            .context("dns query missing question")?;
        let name = query.name().to_utf8();
        let domain = name.trim_end_matches('.').to_ascii_lowercase();

        let classifier_settings = self.classifier_settings();
        if let Some(classification) = classify_domain(&domain, &classifier_settings) {
            tracing::debug!(domain, score = classification.score, "domain classified");
            if classification.score >= classifier_settings.threshold {
                self.emit_classification_event(&domain, client_addr, classification);
            }
        }

        if let Some(cached) = self.cache.get(&domain).await {
            self.stats.cache_hits_total.fetch_add(1, Ordering::Relaxed);
            return Ok(response_for_request(&request, &cached.response));
        }

        let engine = self.policy.read().expect("policy lock poisoned").clone();
        let decision = engine.evaluate(&domain);
        let allow_matched = decision
            .matched_rule
            .as_ref()
            .is_some_and(|rule| matches!(rule.action, RuleAction::Allow));

        let response = match decision.kind {
            DecisionKind::Blocked(mode) => build_blocked_response(&request, mode),
            DecisionKind::Allowed => {
                if !allow_matched {
                    if let Some(mode) = self.uncloaked_block_mode(&domain, &engine).await? {
                        let response = build_blocked_response(&request, mode);
                        self.cache
                            .insert(
                                domain,
                                CachedLookup {
                                    response: response.clone(),
                                },
                            )
                            .await;
                        return Ok(response);
                    }
                }

                match self.resolve_upstream(&request, &domain).await {
                    Ok(response) => {
                        self.fallback_cache
                            .insert(
                                domain.clone(),
                                CachedLookup {
                                    response: response.clone(),
                                },
                            )
                            .await;
                        response
                    }
                    Err(error) => {
                        self.stats
                            .upstream_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        if let Some(fallback) = self.fallback_cache.get(&domain).await {
                            self.stats
                                .fallback_served_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(%domain, %error, "serving fallback DNS response after upstream failure");
                            response_for_request(&request, &fallback.response)
                        } else {
                            return Err(error);
                        }
                    }
                }
            }
        };

        self.cache
            .insert(
                domain,
                CachedLookup {
                    response: response.clone(),
                },
            )
            .await;
        Ok(response)
    }

    fn emit_classification_event(
        &self,
        domain: &str,
        client_addr: Option<SocketAddr>,
        classification: Classification,
    ) {
        let event = build_classification_event(domain, client_addr, classification);
        let observer = self
            .classification_observer
            .read()
            .expect("classification observer lock poisoned")
            .clone();
        if let Some(observer) = observer {
            observer(event);
        }
    }

    async fn resolve_upstream(&self, request: &Message, domain: &str) -> Result<Message> {
        let query = request
            .queries()
            .first()
            .context("dns query missing question")?;
        let lookup = self.resolver.lookup(domain, query.query_type()).await?;
        let mut response = build_base_response(request, ResponseCode::NoError);
        for record in lookup.records() {
            response.add_answer(record.clone());
        }
        Ok(response)
    }

    async fn uncloaked_block_mode(
        &self,
        domain: &str,
        engine: &PolicyEngine,
    ) -> Result<Option<BlockMode>> {
        let mut current = domain.to_string();
        let mut seen = HashSet::new();

        for _ in 0..MAX_CNAME_UNCLOAK_DEPTH {
            if !seen.insert(current.clone()) {
                return Ok(None);
            }

            let lookup = match self.resolver.lookup(&current, RecordType::CNAME).await {
                Ok(lookup) => lookup,
                Err(_) => return Ok(None),
            };

            let Some(target) = lookup.records().iter().find_map(extract_cname_target) else {
                return Ok(None);
            };

            self.stats
                .cname_uncloaks_total
                .fetch_add(1, Ordering::Relaxed);
            let normalized_target = normalize_domain(&target);
            let decision = engine.evaluate(&normalized_target);
            if let DecisionKind::Blocked(mode) = decision.kind {
                self.stats
                    .cname_blocks_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Some(mode));
            }

            current = normalized_target;
        }

        Ok(None)
    }
}

fn extract_cname_target(record: &Record) -> Option<String> {
    match record.data() {
        RData::CNAME(target) => Some(target.0.to_utf8()),
        _ => None,
    }
}

fn build_classification_event(
    domain: &str,
    client_addr: Option<SocketAddr>,
    classification: Classification,
) -> ClassificationEvent {
    ClassificationEvent {
        domain: domain.to_string(),
        client_ip: client_addr.map(|addr| addr.ip().to_string()),
        observed_at: classification.observed_at,
        classification,
    }
}

fn build_probe_request(domain: &str, record_type: RecordType) -> Result<Message> {
    let mut message = Message::new();
    message.set_id(0);
    message.set_message_type(MessageType::Query);
    message.set_recursion_desired(true);
    message.add_query(Query::query(Name::from_ascii(domain)?, record_type));
    Ok(message)
}

fn response_for_request(request: &Message, cached: &Message) -> Message {
    let mut response = cached.clone();
    response.set_id(request.id());
    response
}

fn error_response_for_payload(payload: &[u8]) -> Message {
    match Message::from_vec(payload) {
        Ok(request) => Message::error_msg(request.id(), request.op_code(), ResponseCode::ServFail),
        Err(_) => Message::error_msg(0, hickory_proto::op::OpCode::Query, ResponseCode::ServFail),
    }
}

fn build_base_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_authoritative(false);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_response_code(code);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    response
}

fn build_blocked_response(request: &Message, mode: BlockMode) -> Message {
    match mode {
        BlockMode::NxDomain => build_base_response(request, ResponseCode::NXDomain),
        BlockMode::NoData => build_base_response(request, ResponseCode::NoError),
        BlockMode::Refused => build_base_response(request, ResponseCode::Refused),
        BlockMode::NullIp => build_ip_response(
            request,
            Some(Ipv4Addr::new(0, 0, 0, 0)),
            Some(Ipv6Addr::UNSPECIFIED),
        ),
        BlockMode::CustomIp { ipv4, ipv6 } => build_ip_response(request, ipv4, ipv6),
    }
}

fn build_ip_response(request: &Message, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Message {
    let mut response = build_base_response(request, ResponseCode::NoError);
    for query in request.queries() {
        let name = query.name().clone();
        match query.query_type() {
            hickory_proto::rr::RecordType::A => {
                if let Some(address) = ipv4 {
                    response.add_answer(Record::from_rdata(name, 60, RData::A(A(address))));
                }
            }
            hickory_proto::rr::RecordType::AAAA => {
                if let Some(address) = ipv6 {
                    response.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(address))));
                }
            }
            _ => {}
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_snapshot_starts_at_zero() {
        let stats = DnsRuntimeStats::default();
        let snapshot = DnsRuntimeSnapshot {
            upstream_failures_total: stats.upstream_failures_total.load(Ordering::Relaxed),
            fallback_served_total: stats.fallback_served_total.load(Ordering::Relaxed),
            cache_hits_total: stats.cache_hits_total.load(Ordering::Relaxed),
            cname_uncloaks_total: stats.cname_uncloaks_total.load(Ordering::Relaxed),
            cname_blocks_total: stats.cname_blocks_total.load(Ordering::Relaxed),
        };
        assert_eq!(
            snapshot,
            DnsRuntimeSnapshot {
                upstream_failures_total: 0,
                fallback_served_total: 0,
                cache_hits_total: 0,
                cname_uncloaks_total: 0,
                cname_blocks_total: 0,
            }
        );
    }

    #[test]
    fn extract_cname_target_reads_record_data() {
        use hickory_proto::rr::Name;
        use hickory_proto::rr::rdata::CNAME;

        let alias = Name::from_ascii("tracker.example.com").expect("valid test name");
        let record = Record::from_rdata(
            Name::from_ascii("alias.example.com").expect("valid owner name"),
            60,
            RData::CNAME(CNAME(alias)),
        );

        assert_eq!(
            extract_cname_target(&record),
            Some("tracker.example.com".to_string())
        );
    }

    #[test]
    fn build_probe_request_sets_expected_question() {
        let request = build_probe_request("example.com", RecordType::A).expect("probe request");
        assert_eq!(request.message_type(), MessageType::Query);
        assert_eq!(request.queries().len(), 1);
        assert_eq!(request.queries()[0].query_type(), RecordType::A);
    }

    #[test]
    fn cached_response_adopts_request_id() {
        let mut request = Message::new();
        request.set_id(42);
        let mut cached = Message::new();
        cached.set_id(7);

        let response = response_for_request(&request, &cached);
        assert_eq!(response.id(), 42);
    }

    #[test]
    fn error_response_uses_original_request_id() {
        let request = build_probe_request("example.com", RecordType::A).expect("probe request");
        let response = error_response_for_payload(&request.to_vec().expect("wire request"));
        assert_eq!(response.id(), request.id());
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn build_classification_event_preserves_client_ip() {
        let observed_at = Utc::now();
        let event = build_classification_event(
            "tracker.example",
            Some(SocketAddr::from(([192, 168, 1, 4], 5353))),
            Classification {
                score: 0.98,
                reasons: vec!["entropy".to_string()],
                observed_at,
            },
        );

        assert_eq!(event.domain, "tracker.example");
        assert_eq!(event.client_ip.as_deref(), Some("192.168.1.4"));
        assert_eq!(event.observed_at, observed_at);
        assert_eq!(event.classification.score, 0.98);
    }
}
