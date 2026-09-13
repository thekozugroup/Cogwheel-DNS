//! Parsing for upstream resolver specifications.
//!
//! Until now an upstream was a bare `ip:port` spoken in cleartext on port 53,
//! which means the ISP — and anyone else on the path — sees the name of every
//! site every device in the house asks for. Blocking trackers while handing
//! that same list to the network operator is a strange place to stop, so an
//! upstream can now also be DNS-over-TLS or DNS-over-HTTPS.
//!
//! # Syntax
//!
//! ```text
//! 1.1.1.1                                        cleartext, port 53
//! 1.1.1.1:53                                     cleartext, explicit port
//! udp://1.1.1.1:53                               the same, written out
//! tls://1.1.1.1#cloudflare-dns.com               DNS-over-TLS, port 853
//! https://1.1.1.1#cloudflare-dns.com/dns-query   DNS-over-HTTPS, port 443
//! ```
//!
//! The `#name` is the name the server's certificate must match, and it is
//! REQUIRED for `tls` and `https`. That is deliberate. The obvious alternative
//! — writing `tls://cloudflare-dns.com` and looking the name up — needs a
//! bootstrap resolver, and a bootstrap query is a cleartext query: the very
//! thing being fixed would leak on every restart. Naming the address and the
//! certificate separately removes the bootstrap entirely, and it is the same
//! shape `systemd-resolved` uses for exactly this reason.
//!
//! A certificate name with no address to check it against would be worse than
//! cleartext, because it looks encrypted; there is no mode here that skips
//! verification.

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Port used when a cleartext upstream does not name one.
pub const DEFAULT_UDP_PORT: u16 = 53;
/// Port used when a DNS-over-TLS upstream does not name one (RFC 7858).
pub const DEFAULT_TLS_PORT: u16 = 853;
/// Port used when a DNS-over-HTTPS upstream does not name one (RFC 8484).
pub const DEFAULT_HTTPS_PORT: u16 = 443;
/// Path used when a DNS-over-HTTPS upstream does not name one (RFC 8484).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

/// How to talk to an upstream resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    /// Cleartext DNS over UDP with a TCP fallback. Visible to the network.
    Udp,
    /// DNS-over-TLS, RFC 7858.
    Tls,
    /// DNS-over-HTTPS, RFC 8484.
    Https,
}

impl UpstreamProtocol {
    /// Whether queries over this transport are hidden from the local network.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Tls | Self::Https)
    }

    const fn scheme(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tls => "tls",
            Self::Https => "https",
        }
    }

    const fn default_port(self) -> u16 {
        match self {
            Self::Udp => DEFAULT_UDP_PORT,
            Self::Tls => DEFAULT_TLS_PORT,
            Self::Https => DEFAULT_HTTPS_PORT,
        }
    }
}

/// One fully-resolved upstream, ready to be turned into a transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamEndpoint {
    /// Address to connect to. Always a literal address, never a name.
    pub addr: SocketAddr,
    /// Transport to speak.
    pub protocol: UpstreamProtocol,
    /// Name the server certificate must match. Present iff encrypted.
    pub server_name: Option<String>,
    /// DoH query path. Present only for [`UpstreamProtocol::Https`].
    pub path: Option<String>,
}

/// Why an upstream specification could not be used.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpstreamError {
    #[error("upstream specification is empty")]
    Empty,
    #[error("unknown upstream scheme '{0}'; expected udp, tls or https")]
    UnknownScheme(String),
    #[error(
        "'{0}' is not an IP address. An encrypted upstream must be given as an address plus the \
         certificate name, e.g. tls://1.1.1.1#cloudflare-dns.com — a hostname alone would need a \
         cleartext lookup to resolve, which is what encrypting the upstream is meant to prevent"
    )]
    NotAnAddress(String),
    #[error(
        "{0} upstream '{1}' has no certificate name. Add one with '#', e.g. \
         tls://1.1.1.1#cloudflare-dns.com — without a name there is nothing to validate the \
         server's certificate against"
    )]
    MissingServerName(&'static str, String),
    #[error("cleartext upstream '{0}' carries a certificate name, but nothing is encrypted here")]
    UnexpectedServerName(String),
    #[error("cleartext upstream '{0}' carries a URL path, which plain DNS has no use for")]
    UnexpectedPath(String),
}

impl UpstreamEndpoint {
    /// Parse one upstream specification. See the module docs for the syntax.
    ///
    /// # Errors
    ///
    /// Returns [`UpstreamError`] when the specification names an unknown
    /// scheme, is not an address, or omits a certificate name an encrypted
    /// transport requires.
    pub fn parse(spec: &str) -> Result<Self, UpstreamError> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(UpstreamError::Empty);
        }

        let (protocol, rest) = match spec.split_once("://") {
            Some(("udp", rest)) => (UpstreamProtocol::Udp, rest),
            Some(("tls", rest)) => (UpstreamProtocol::Tls, rest),
            Some(("https", rest)) => (UpstreamProtocol::Https, rest),
            Some((scheme, _)) => return Err(UpstreamError::UnknownScheme(scheme.to_string())),
            None => (UpstreamProtocol::Udp, spec),
        };

        // The path may be written on either side of the '#'. Both
        // `https://1.1.1.1#name/dns-query` and `https://1.1.1.1/dns-query#name`
        // are things people reasonably type, and rejecting one of them teaches
        // nothing, so accept both.
        let (left, right) = match rest.split_once('#') {
            Some((left, right)) => (left, Some(right)),
            None => (rest, None),
        };

        let (authority, mut path) = split_path(left);
        let mut server_name = None;
        if let Some(right) = right {
            let (name, name_side_path) = split_path(right);
            if name.is_empty() {
                return Err(UpstreamError::MissingServerName(
                    protocol.scheme(),
                    spec.to_string(),
                ));
            }
            server_name = Some(name.to_string());
            if path.is_none() {
                path = name_side_path;
            }
        }

        let addr = parse_authority(authority, protocol.default_port())?;

        match protocol {
            UpstreamProtocol::Udp => {
                if server_name.is_some() {
                    return Err(UpstreamError::UnexpectedServerName(spec.to_string()));
                }
                if path.is_some() {
                    return Err(UpstreamError::UnexpectedPath(spec.to_string()));
                }
            }
            UpstreamProtocol::Tls | UpstreamProtocol::Https => {
                if server_name.is_none() {
                    return Err(UpstreamError::MissingServerName(
                        protocol.scheme(),
                        spec.to_string(),
                    ));
                }
            }
        }

        if protocol == UpstreamProtocol::Https && path.is_none() {
            path = Some(DEFAULT_DOH_PATH.to_string());
        }
        if protocol == UpstreamProtocol::Tls {
            // A path means nothing to DoT; silently keeping one would make the
            // round-tripped form differ from what was configured.
            path = None;
        }

        Ok(Self {
            addr,
            protocol,
            server_name,
            path,
        })
    }

    /// Whether this upstream hides queries from the local network.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.protocol.is_encrypted()
    }
}

/// Split a trailing `/path` off, returning `("authority", Some("/path"))`.
///
/// An IPv6 literal is bracketed, so no `/` inside it can be confused for the
/// start of a path.
fn split_path(value: &str) -> (&str, Option<String>) {
    match value.split_once('/') {
        Some((head, tail)) => (head, Some(format!("/{tail}"))),
        None => (value, None),
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<SocketAddr, UpstreamError> {
    if authority.is_empty() {
        return Err(UpstreamError::Empty);
    }
    // Try the fully-specified form first: "1.1.1.1:853", "[2606:4700::1111]:853".
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Then a bare address, taking the transport's default port. A bracketed
    // IPv6 literal with no port ("[2606:4700::1111]") is accepted too.
    let bare = authority
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(authority);
    bare.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, default_port))
        .map_err(|_| UpstreamError::NotAnAddress(authority.to_string()))
}

impl fmt::Display for UpstreamEndpoint {
    /// Renders the canonical form, which re-parses to an equal value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}", self.protocol.scheme(), self.addr)?;
        if let Some(name) = &self.server_name {
            write!(formatter, "#{name}")?;
        }
        if let Some(path) = &self.path {
            write!(formatter, "{path}")?;
        }
        Ok(())
    }
}

/// The options every upstream resolver is built with.
///
/// Pinned rather than left to hickory's defaults because three of them decide
/// how this resolver behaves when the upstream is unwell, and the defaults are
/// tuned for a client library, not a forwarder in front of a household:
///
/// - `timeout` 2 s and `attempts` 2 bound a dead upstream to four seconds
///   before the miss falls back to a stale answer or SERVFAIL, instead of the
///   default ten.
/// - `cache_size` 0 switches hickory's own LRU off. There is one cache in this
///   process, the runtime's, and it is the one that applies the TTL clamp;
///   a second cache underneath it would hand back answers the clamp never saw.
/// - `try_tcp_on_error` retries over TCP when UDP fails, which is how a
///   truncated or filtered UDP path still resolves.
/// - `preserve_intermediates` keeps CNAME records in `Lookup::answers()`. The
///   CNAME re-check reads the aliases out of the answer it already has; without
///   this flag it would need a second round trip per name.
pub fn resolver_options() -> ResolverOpts {
    // Field-by-field because `ResolverOpts` is `#[non_exhaustive]`; a struct literal with
    // `..Default::default()` is refused across crates.
    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_secs(2);
    options.attempts = 2;
    options.cache_size = 0;
    options.try_tcp_on_error = true;
    options.preserve_intermediates = true;
    options
}

/// Build the upstream resolver from the configured server specifications.
///
/// # Errors
///
/// Returns an error when a specification does not parse or the resolver
/// cannot be constructed.
pub fn build_resolver(servers: &[String]) -> Result<TokioResolver> {
    let mut name_servers = Vec::new();
    let mut encrypted = 0usize;

    for server in servers {
        let endpoint = UpstreamEndpoint::parse(server)
            .with_context(|| format!("invalid upstream server: {server}"))?;

        // hickory 0.26 models an upstream as one address carrying a list of connections, rather
        // than one entry per protocol. The port moved onto the connection, so it has to be copied
        // across from the configured address or every upstream would silently fall back to 53.
        let connections = match endpoint.protocol {
            UpstreamProtocol::Udp => {
                let mut udp = ConnectionConfig::udp();
                udp.port = endpoint.addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = endpoint.addr.port();
                vec![udp, tcp]
            }
            // No cleartext fallback is added alongside an encrypted transport, and that is the
            // whole point. A fallback would mean that anything making TLS fail -- a captive
            // portal, a middlebox, an expired certificate -- silently downgrades every query in
            // the house back onto the wire in plaintext, which is precisely the outcome the
            // operator configured this to avoid. If DoT is broken, resolution should fail
            // visibly and get fixed, not quietly succeed in the clear.
            UpstreamProtocol::Tls => {
                let server_name = endpoint
                    .server_name
                    .clone()
                    .context("DoT upstream without a certificate name reached the resolver")?;
                let mut tls = ConnectionConfig::tls(Arc::from(server_name.as_str()));
                tls.port = endpoint.addr.port();
                encrypted += 1;
                vec![tls]
            }
            UpstreamProtocol::Https => {
                let server_name = endpoint
                    .server_name
                    .clone()
                    .context("DoH upstream without a certificate name reached the resolver")?;
                let path = endpoint.path.clone().map(|path| Arc::from(path.as_str()));
                let mut https = ConnectionConfig::https(Arc::from(server_name.as_str()), path);
                https.port = endpoint.addr.port();
                encrypted += 1;
                vec![https]
            }
        };

        tracing::info!(
            upstream = %endpoint,
            protocol = ?endpoint.protocol,
            encrypted = endpoint.is_encrypted(),
            "configured upstream resolver"
        );
        name_servers.push(NameServerConfig::new(endpoint.addr.ip(), true, connections));
    }

    // Said once, plainly, rather than left for the operator to infer. Cleartext is still the
    // default because it is what works on every network without configuration, but running a
    // tracker blocker while handing the full browsing history of the house to whoever carries
    // the packets deserves to be stated rather than assumed.
    if encrypted == 0 {
        tracing::warn!(
            "all upstream resolvers are cleartext DNS on port 53; every domain this network \
             looks up is visible to the local network and to the ISP. Configure DNS-over-TLS \
             with e.g. COGWHEEL_UPSTREAM__SERVERS=tls://1.1.1.1#cloudflare-dns.com"
        );
    } else if encrypted < name_servers.len() {
        // Mixing is a real footgun: hickory will happily use whichever responds, so a single
        // cleartext entry in the list quietly leaks a share of the queries.
        tracing::warn!(
            encrypted,
            total = name_servers.len(),
            "some upstream resolvers are encrypted and some are cleartext; queries will be \
             spread across both, so a share of them still travel in plaintext"
        );
    }

    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(resolver_options())
        .build()
        .context("build upstream resolver")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(spec: &str) -> UpstreamEndpoint {
        UpstreamEndpoint::parse(spec).expect("should parse")
    }

    #[test]
    fn a_bare_address_is_cleartext_on_port_53() {
        let endpoint = parse("1.1.1.1");
        assert_eq!(endpoint.addr.to_string(), "1.1.1.1:53");
        assert_eq!(endpoint.protocol, UpstreamProtocol::Udp);
        assert!(!endpoint.is_encrypted());
    }

    /// Every existing install has `1.1.1.1:53,1.0.0.1:53` written into
    /// /etc/cogwheel/cogwheel.env. Upgrading must not require editing it.
    #[test]
    fn the_previously_shipped_format_still_parses() {
        for spec in [
            "1.1.1.1:53",
            "1.0.0.1:53",
            "9.9.9.9:53",
            "[2606:4700::1111]:53",
        ] {
            let endpoint = parse(spec);
            assert_eq!(endpoint.protocol, UpstreamProtocol::Udp);
            assert_eq!(endpoint.addr.port(), 53);
        }
    }

    #[test]
    fn tls_defaults_to_port_853_and_keeps_the_certificate_name() {
        let endpoint = parse("tls://1.1.1.1#cloudflare-dns.com");
        assert_eq!(endpoint.addr.to_string(), "1.1.1.1:853");
        assert_eq!(endpoint.protocol, UpstreamProtocol::Tls);
        assert_eq!(endpoint.server_name.as_deref(), Some("cloudflare-dns.com"));
        assert!(endpoint.is_encrypted());
    }

    #[test]
    fn https_defaults_to_port_443_and_the_rfc_8484_path() {
        let endpoint = parse("https://1.1.1.1#cloudflare-dns.com");
        assert_eq!(endpoint.addr.to_string(), "1.1.1.1:443");
        assert_eq!(endpoint.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn a_doh_path_is_accepted_on_either_side_of_the_name() {
        let after = parse("https://1.1.1.1#dns.example.org/resolve");
        let before = parse("https://1.1.1.1/resolve#dns.example.org");
        assert_eq!(after.path.as_deref(), Some("/resolve"));
        assert_eq!(before.path.as_deref(), Some("/resolve"));
        assert_eq!(after, before);
    }

    #[test]
    fn ipv6_literals_work_bracketed_with_and_without_a_port() {
        assert_eq!(
            parse("tls://[2606:4700:4700::1111]:853#cloudflare-dns.com")
                .addr
                .port(),
            853
        );
        assert_eq!(
            parse("tls://[2606:4700:4700::1111]#cloudflare-dns.com")
                .addr
                .port(),
            853
        );
        assert_eq!(parse("2606:4700:4700::1111").addr.port(), 53);
    }

    /// The whole point of naming the address separately: resolving a hostname
    /// would need a cleartext bootstrap query, leaking on every restart.
    #[test]
    fn a_hostname_alone_is_refused_and_the_error_says_why() {
        let error = UpstreamEndpoint::parse("tls://cloudflare-dns.com").expect_err("should refuse");
        let message = error.to_string();
        assert!(message.contains("not an IP address"), "{message}");
        assert!(
            message.contains("tls://1.1.1.1#cloudflare-dns.com"),
            "{message}"
        );
    }

    /// Encrypting to a certificate nobody checks is worse than cleartext,
    /// because it looks safe. There is no verification-skipping mode.
    #[test]
    fn encrypted_upstreams_require_a_certificate_name() {
        for spec in ["tls://1.1.1.1", "https://1.1.1.1", "tls://1.1.1.1#"] {
            let error = UpstreamEndpoint::parse(spec).expect_err("should refuse");
            assert!(
                matches!(error, UpstreamError::MissingServerName(..)),
                "{spec} produced {error:?}"
            );
        }
    }

    #[test]
    fn a_cleartext_upstream_may_not_carry_a_certificate_name_or_path() {
        assert!(matches!(
            UpstreamEndpoint::parse("udp://1.1.1.1#cloudflare-dns.com"),
            Err(UpstreamError::UnexpectedServerName(_))
        ));
        assert!(matches!(
            UpstreamEndpoint::parse("udp://1.1.1.1/dns-query"),
            Err(UpstreamError::UnexpectedPath(_))
        ));
    }

    #[test]
    fn an_unknown_scheme_is_named_in_the_error() {
        let error = UpstreamEndpoint::parse("quic://1.1.1.1#example.com").expect_err("refuse");
        assert_eq!(error, UpstreamError::UnknownScheme("quic".to_string()));
    }

    #[test]
    fn empty_input_is_refused() {
        assert_eq!(UpstreamEndpoint::parse("   "), Err(UpstreamError::Empty));
    }

    #[test]
    fn the_rendered_form_parses_back_to_the_same_endpoint() {
        for spec in [
            "1.1.1.1:53",
            "tls://1.1.1.1#cloudflare-dns.com",
            "https://9.9.9.9#dns.quad9.net",
            "https://1.1.1.1#dns.example.org/resolve",
            "tls://[2606:4700:4700::1111]:853#cloudflare-dns.com",
        ] {
            let endpoint = parse(spec);
            let rendered = endpoint.to_string();
            assert_eq!(
                parse(&rendered),
                endpoint,
                "round trip of {spec} via {rendered}"
            );
        }
    }

    #[test]
    fn a_resolver_builds_from_the_shipped_default_and_refuses_a_bad_spec() {
        let servers = ["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()];
        assert!(build_resolver(&servers).is_ok());
        let error = build_resolver(&["tls://cloudflare-dns.com".to_string()]).expect_err("refuse");
        assert!(
            error.to_string().contains("invalid upstream server"),
            "{error}"
        );
    }

    /// The four options that change how an outage feels are pinned on purpose;
    /// a hickory default drifting under us must show up here, not on a Pi.
    #[test]
    fn resolver_options_are_pinned() {
        let options = resolver_options();
        assert_eq!(options.timeout, Duration::from_secs(2));
        assert_eq!(options.attempts, 2);
        assert_eq!(options.cache_size, 0);
        assert!(options.try_tcp_on_error);
        assert!(options.preserve_intermediates);
    }
}
