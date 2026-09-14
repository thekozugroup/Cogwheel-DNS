//! Fetching and parsing blocklist sources into [`cogwheel_policy::ListIndex`] entries.
//!
//! This is a control-plane crate — it talks HTTP, so it is deliberately not on the DNS hot
//! path. The pipeline the server drives with it:
//!
//! 1. [`fetch_source_body`] does a conditional GET and returns either [`FetchOutcome::NotModified`]
//!    or the body with its validators for the next request.
//! 2. [`parse_list`] turns a body into [`ParsedList`] entries, tolerating bad lines rather than
//!    failing the whole list.
//! 3. [`verify_list`] refuses a list whose bad-line ratio says the parser and the file disagree
//!    (the wrong `kind`, a truncated download, an HTML error page served as 200).
//! 4. [`build_index`] compiles the surviving lists into one [`ListIndex`]; [`protected_hits`]
//!    reports which protected names a list would have blocked, as a note — protection is
//!    enforced at evaluation, so this never rejects anything.
//!
//! # Untrusted input
//!
//! A source's body is attacker-influenced: the operator picks the URL, but whoever controls
//! that URL controls the payload. [`fetch_source_body`] enforces [`MAX_SOURCE_BODY_BYTES`] for
//! exactly this reason — see its docs for the incident that established the bound.

#![warn(missing_docs)]

use base64::Engine;
use cogwheel_policy::{Action, ListIndex, PROTECTED_SUFFIXES, Pattern, normalize_domain};
use reqwest::Client;
use reqwest::header::{ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};
use url::Url;

/// The line format a source is parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// `/etc/hosts` format (`<ip> <host> [<host>…]`); every host on the line is blocked exactly.
    Hosts,
    /// One domain per line, covering its subdomains; `*.host` means the same as `host`.
    Domains,
    /// Adblock Plus filter syntax: `||host^` blocks, `@@||host^` excepts. Modifier (`$`),
    /// cosmetic (`#`) and regex (`/…/`) rules are rejected rather than approximated.
    Adblock,
}

impl SourceKind {
    /// The API and database spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::Domains => "domains",
            Self::Adblock => "adblock",
        }
    }
}

impl std::str::FromStr for SourceKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, ()> {
        match value {
            "hosts" => Ok(Self::Hosts),
            "domains" => Ok(Self::Domains),
            "adblock" => Ok(Self::Adblock),
            _ => Err(()),
        }
    }
}

/// Largest blocklist body accepted from a remote source.
///
/// Blocklists are attacker-influenced input: the operator supplies a URL, but whoever controls that
/// URL controls the payload. Measured before this bound existed, a 44 MB list drove resident memory
/// from 27 MB to 695 MB — roughly 16x amplification, because the body string, the parsed rules,
/// verification's copy of them and the compiled artifact all coexist. A 616 MB body peaked at 10 GB
/// and would have been an OOM kill on the 4 GB Raspberry Pi this product targets.
///
/// 32 MiB comfortably exceeds the largest lists in real use (StevenBlack's hosts file is ~3 MB,
/// HaGeZi Pro ~5 MB) while keeping worst-case amplification inside the budget of the smallest
/// supported device.
pub const MAX_SOURCE_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// A list is refused when more than this share of its non-comment lines fail to parse.
pub const MAX_INVALID_RATIO: f32 = 0.20;

/// Why a source body was rejected before parsing.
#[derive(Debug)]
pub enum FetchError {
    /// Transport or status failure.
    Http(reqwest::Error),
    /// The body exceeded [`MAX_SOURCE_BODY_BYTES`].
    TooLarge {
        /// Bytes read before the limit tripped, or the advertised length.
        bytes: u64,
        /// The limit that was exceeded.
        limit: u64,
    },
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => write!(f, "{error}"),
            Self::TooLarge { bytes, limit } => write!(
                f,
                "blocklist body of {bytes} bytes exceeds the {limit} byte limit"
            ),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<reqwest::Error> for FetchError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

/// What a conditional fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The server answered 304: the cached body is still current.
    NotModified,
    /// A fresh body, with the validators to send next time (as the server spelled them).
    Body {
        /// The list text, lossily decoded as UTF-8.
        text: String,
        /// The response's `ETag`, if any.
        etag: Option<String>,
        /// The response's `Last-Modified`, if any.
        last_modified: Option<String>,
    },
}

/// Fetch a source body, refusing anything over [`MAX_SOURCE_BODY_BYTES`].
///
/// `etag` and `last_modified` are the validators stored from the previous successful fetch;
/// they become `If-None-Match` / `If-Modified-Since`, and a 304 comes back as
/// [`FetchOutcome::NotModified`] so a daily refresh of an unchanged list costs one round trip
/// and no parse. A `data:` URL is decoded locally (base64 or percent-encoding) and is never
/// "not modified".
///
/// The body is streamed and the running total checked per chunk, so an oversized or
/// `Content-Length`-lying response is abandoned mid-transfer rather than buffered in full.
pub async fn fetch_source_body(
    client: &Client,
    url: &Url,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Result<FetchOutcome, FetchError> {
    if url.scheme() == "data" {
        return Ok(FetchOutcome::Body {
            text: parse_data_url(url),
            etag: None,
            last_modified: None,
        });
    }

    let mut request = client.get(url.clone());
    // A validator the database holds that is not a legal header value would fail the whole
    // request at send time; dropping it just makes this one fetch unconditional.
    if let Some(value) = etag.and_then(|etag| HeaderValue::from_str(etag).ok()) {
        request = request.header(IF_NONE_MATCH, value);
    }
    if let Some(value) = last_modified.and_then(|stamp| HeaderValue::from_str(stamp).ok()) {
        request = request.header(IF_MODIFIED_SINCE, value);
    }

    let response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(FetchOutcome::NotModified);
    }
    let mut response = response.error_for_status()?;

    // Reject early when the server is honest about an oversized body.
    if let Some(length) = response.content_length()
        && length > MAX_SOURCE_BODY_BYTES
    {
        return Err(FetchError::TooLarge {
            bytes: length,
            limit: MAX_SOURCE_BODY_BYTES,
        });
    }

    let header_string = |name| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let etag = header_string(ETAG);
    let last_modified = header_string(LAST_MODIFIED);

    // Content-Length may be absent or a lie, so enforce the bound while streaming.
    let mut body = Vec::with_capacity(64 * 1024);
    while let Some(chunk) = response.chunk().await? {
        if body.len() as u64 + chunk.len() as u64 > MAX_SOURCE_BODY_BYTES {
            return Err(FetchError::TooLarge {
                bytes: body.len() as u64 + chunk.len() as u64,
                limit: MAX_SOURCE_BODY_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(FetchOutcome::Body {
        text: String::from_utf8_lossy(&body).into_owned(),
        etag,
        last_modified,
    })
}

/// Decode the body of a `data:` URL, base64 or percent-encoded.
///
/// `Url::parse` leaves the payload percent-encoded, and every character an ABP or hosts line is
/// made of — `|`, `^`, `@`, the space between an address and its name — is reserved, so decoding
/// only the newlines would let two of the three list formats through as literal `%7C%7C…` and
/// then blame the operator for the format.
fn parse_data_url(url: &Url) -> String {
    let path = url.path();
    let Some((metadata, encoded)) = path.split_once(',') else {
        return String::new();
    };
    if metadata.ends_with(";base64") {
        return String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap_or_default(),
        )
        .unwrap_or_default();
    }
    percent_encoding::percent_decode_str(encoded)
        .decode_utf8_lossy()
        .into_owned()
}

/// One list's entries after parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedList {
    /// Every entry, normalised, in file order (duplicates included).
    pub entries: Vec<(Action, Pattern, Box<str>)>,
    /// Lines that were neither blank, a comment, nor parseable for the list's kind.
    pub invalid_lines: usize,
}

impl ParsedList {
    /// The share of meaningful lines that failed to parse; `0.0` for an empty list.
    pub fn invalid_ratio(&self) -> f32 {
        let total = self.entries.len() + self.invalid_lines;
        if total == 0 {
            0.0
        } else {
            self.invalid_lines as f32 / total as f32
        }
    }
}

/// Hosts-file names that map to the machine itself; every hosts file lists them and none of
/// them is an ad.
const LOCALHOST_FAMILY: [&str; 12] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

/// Parse a list body into entries, tolerating bad lines instead of failing.
///
/// Blank lines and lines starting with `#` or `!` are skipped. Every other line is parsed for
/// `kind`; one the parser rejects counts in [`ParsedList::invalid_lines`] rather than aborting,
/// so one malformed line in an otherwise-good list does not lose the rest of it. What each
/// kind accepts is documented on [`SourceKind`]; entries are normalised with
/// [`normalize_domain`].
pub fn parse_list(kind: SourceKind, body: &str) -> ParsedList {
    let mut parsed = ParsedList::default();
    for line in body.lines() {
        let line = line.trim();
        // `[` is an ABP section header (`[Adblock Plus 2.0]`), not a rule: counting it as an
        // invalid line put every list one line closer to the 20% rejection threshold.
        if line.is_empty() || line.starts_with(['#', '!', '[']) {
            continue;
        }
        let ok = match kind {
            SourceKind::Hosts => parse_hosts_line(line, &mut parsed.entries),
            SourceKind::Domains => parse_domain_line(line, &mut parsed.entries),
            SourceKind::Adblock => parse_adblock_line(line, &mut parsed.entries),
        };
        if !ok {
            parsed.invalid_lines += 1;
        }
    }
    parsed
}

/// `<ip> <host> [<host>…] [# comment]`: one exact entry per host, minus the localhost family.
fn parse_hosts_line(line: &str, entries: &mut Vec<(Action, Pattern, Box<str>)>) -> bool {
    let mut fields = strip_inline_comment(line).split_whitespace();
    let Some(address) = fields.next() else {
        return false;
    };
    // A line whose first field is not an address is some other format fed in as hosts; letting
    // it through would index the second word of every line and report a healthy rule count.
    if address.parse::<std::net::IpAddr>().is_err() {
        return false;
    }
    let mut hosts = fields.map(normalize_domain).peekable();
    // `127.0.0.1 localhost` is a valid line that contributes nothing.
    let mut valid = hosts.peek().is_some();
    let hosts = hosts
        .filter(|host| !LOCALHOST_FAMILY.contains(&host.as_str()))
        .inspect(|host| valid &= is_hostname_like(host))
        .collect::<Vec<_>>();
    if !valid {
        return false;
    }
    entries.extend(
        hosts
            .into_iter()
            .map(|host| (Action::Block, Pattern::Exact, host.into_boxed_str())),
    );
    true
}

/// A bare host, or `*.host`, covering its subdomains.
fn parse_domain_line(line: &str, entries: &mut Vec<(Action, Pattern, Box<str>)>) -> bool {
    let host = normalize_domain(strip_inline_comment(line));
    let host = host.strip_prefix("*.").unwrap_or(&host);
    if !is_hostname_like(host) {
        return false;
    }
    entries.push((Action::Block, Pattern::Suffix, Box::from(host)));
    true
}

/// `||host^` and `@@||host^`, plus a bare host as an exact match. Anything carrying a modifier
/// (`$`), a cosmetic filter (`#`) or a regex (leading `/`) is a rule DNS cannot honour.
fn parse_adblock_line(line: &str, entries: &mut Vec<(Action, Pattern, Box<str>)>) -> bool {
    if line.contains(['#', '$']) || line.starts_with('/') {
        return false;
    }
    let (action, rule) = match line.strip_prefix("@@") {
        Some(rest) => (Action::Allow, rest),
        None => (Action::Block, line),
    };
    let (pattern, host) = match rule.strip_prefix("||").and_then(|r| r.strip_suffix('^')) {
        Some(host) => (Pattern::Suffix, host.strip_prefix("*.").unwrap_or(host)),
        None => (Pattern::Exact, rule),
    };
    let host = normalize_domain(host);
    if !is_hostname_like(&host) {
        return false;
    }
    entries.push((action, pattern, host.into_boxed_str()));
    true
}

fn strip_inline_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

/// Loose enough for punycode and underscore labels, strict enough that a URL, a filter
/// modifier or a stray IP-plus-host line never becomes an entry.
fn is_hostname_like(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Refuse a list the parser could not make sense of.
///
/// More than [`MAX_INVALID_RATIO`] bad lines means the `kind` is wrong, the download was
/// truncated, or the server returned an error page as 200; an empty list is refused for the
/// same reason. The caller keeps serving the previous body and records the error against that
/// list only — other lists are unaffected.
///
/// # Errors
///
/// The reason, phrased for the list's `last_error` column.
pub fn verify_list(parsed: &ParsedList) -> Result<(), String> {
    let total = parsed.entries.len() + parsed.invalid_lines;
    if total == 0 {
        return Err("the list has no entries".to_owned());
    }
    let ratio = parsed.invalid_ratio();
    if ratio > MAX_INVALID_RATIO {
        return Err(format!(
            "{} of {total} lines could not be parsed ({:.0}% > {:.0}%); is the format right?",
            parsed.invalid_lines,
            ratio * 100.0,
            MAX_INVALID_RATIO * 100.0
        ));
    }
    Ok(())
}

/// Compile lists into one [`ListIndex`], the `n`th list taking slot `n`.
///
/// The caller orders enabled sources by id so slots are stable between rebuilds; a single
/// `(name, list)` pair builds the throwaway index [`protected_hits`] needs for a per-list note.
pub fn build_index<'a>(lists: impl IntoIterator<Item = (&'a str, &'a ParsedList)>) -> ListIndex {
    let mut builder = ListIndex::builder();
    for (slot, (name, list)) in lists.into_iter().enumerate() {
        let Ok(slot) = u8::try_from(slot) else {
            break;
        };
        builder.name(slot, name);
        for (action, pattern, domain) in &list.entries {
            builder.insert(slot, *action, *pattern, domain);
        }
    }
    builder.build()
}

/// The [`PROTECTED_SUFFIXES`] an index would block if protection were not enforced: a block
/// bit set and no exception. Surfaced as a note on the list, never as a rejection.
pub fn protected_hits(index: &ListIndex) -> Vec<&'static str> {
    PROTECTED_SUFFIXES
        .into_iter()
        .filter(|suffix| {
            let masks = index.lookup(suffix);
            masks.block != 0 && masks.allow == 0
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn entries(parsed: &ParsedList) -> Vec<(Action, Pattern, &str)> {
        parsed
            .entries
            .iter()
            .map(|(action, pattern, domain)| (*action, *pattern, &**domain))
            .collect()
    }

    #[test]
    fn adblock_suffix_and_allow_parse() {
        let parsed = parse_list(
            SourceKind::Adblock,
            "[Adblock Plus 2.0]\n! comment\n||Ads.example.com^\n@@||cdn.example.com^\n||*.wild.example^\nbare.example\n",
        );
        assert_eq!(
            entries(&parsed),
            vec![
                (Action::Block, Pattern::Suffix, "ads.example.com"),
                (Action::Allow, Pattern::Suffix, "cdn.example.com"),
                (Action::Block, Pattern::Suffix, "wild.example"),
                (Action::Block, Pattern::Exact, "bare.example"),
            ]
        );
        assert_eq!(
            parsed.invalid_lines, 0,
            "a `[Adblock Plus]` header is skipped like a comment, not counted against the list"
        );
    }

    #[test]
    fn cosmetic_modifier_and_regex_rules_are_rejected() {
        let parsed = parse_list(
            SourceKind::Adblock,
            "example.com##.ad-banner\n||tracker.example^$third-party\n/banner[0-9]+/\n||ok.example^\n||host.example/path^\n",
        );
        assert_eq!(
            entries(&parsed),
            vec![(Action::Block, Pattern::Suffix, "ok.example")]
        );
        assert_eq!(parsed.invalid_lines, 4);
    }

    #[test]
    fn hosts_lines_yield_an_exact_entry_per_host() {
        let parsed = parse_list(
            SourceKind::Hosts,
            "# hosts\n0.0.0.0 ads.example Tracker.example  # inline\n127.0.0.1 more.example\nnot-an-ip host.example\n",
        );
        assert_eq!(
            entries(&parsed),
            vec![
                (Action::Block, Pattern::Exact, "ads.example"),
                (Action::Block, Pattern::Exact, "tracker.example"),
                (Action::Block, Pattern::Exact, "more.example"),
            ]
        );
        assert_eq!(parsed.invalid_lines, 1);
    }

    #[test]
    fn the_localhost_family_is_skipped_silently() {
        let parsed = parse_list(
            SourceKind::Hosts,
            "127.0.0.1 localhost localhost.localdomain\n::1 ip6-localhost ip6-loopback\n0.0.0.0 0.0.0.0\n255.255.255.255 broadcasthost\n0.0.0.0 ads.example\n",
        );
        assert_eq!(
            entries(&parsed),
            vec![(Action::Block, Pattern::Exact, "ads.example")]
        );
        assert_eq!(parsed.invalid_lines, 0);
    }

    #[test]
    fn domain_lines_cover_subdomains_and_accept_wildcards() {
        let parsed = parse_list(
            SourceKind::Domains,
            "ads.example\n*.wild.example\n0.0.0.0 hosts-style.example\n||abp.example^\n",
        );
        assert_eq!(
            entries(&parsed),
            vec![
                (Action::Block, Pattern::Suffix, "ads.example"),
                (Action::Block, Pattern::Suffix, "wild.example"),
            ]
        );
        assert_eq!(
            parsed.invalid_lines, 2,
            "other formats do not parse as domains"
        );
    }

    #[test]
    fn data_url_body_parses() {
        let body = parse_data_url(
            &Url::parse("data:text/plain,ads.example.com%0Atracker.example.com")
                .expect("valid data url"),
        );
        assert_eq!(body, "ads.example.com\ntracker.example.com");
        let body = parse_data_url(
            &Url::parse("data:text/plain;base64,YWRzLmV4YW1wbGU=").expect("valid data url"),
        );
        assert_eq!(body, "ads.example");
    }

    /// `||`, `^`, `@` and the space in a hosts line are all reserved characters, so a decoder
    /// that only handled newlines left every format but `domains` unparseable over `data:`.
    #[test]
    fn data_url_bodies_decode_every_reserved_character() {
        let adblock = parse_data_url(
            &Url::parse("data:text/plain,%7C%7Cads.example%5E%0A%40%40%7C%7Cshop.example%5E")
                .expect("valid data url"),
        );
        assert_eq!(adblock, "||ads.example^\n@@||shop.example^");
        let parsed = parse_list(SourceKind::Adblock, &adblock);
        assert_eq!(parsed.invalid_lines, 0);
        assert_eq!(
            entries(&parsed),
            vec![
                (Action::Block, Pattern::Suffix, "ads.example"),
                (Action::Allow, Pattern::Suffix, "shop.example"),
            ]
        );

        let hosts = parse_data_url(
            &Url::parse("data:text/plain,0.0.0.0%20ads.example%0A0.0.0.0%20trk.example")
                .expect("valid data url"),
        );
        let parsed = parse_list(SourceKind::Hosts, &hosts);
        assert_eq!(parsed.invalid_lines, 0);
        assert_eq!(verify_list(&parsed), Ok(()));
    }

    #[test]
    fn invalid_ratio_gate_is_fixed_at_twenty_percent() {
        let bad = parse_list(SourceKind::Adblock, "||good.example^\n$badmodifier\n");
        assert!(bad.invalid_ratio() > MAX_INVALID_RATIO);
        let error = verify_list(&bad).expect_err("half the lines are bad");
        assert!(error.contains("1 of 2"), "{error}");

        let ok = parse_list(
            SourceKind::Adblock,
            "||a.example^\n||b.example^\n||c.example^\n||d.example^\n$bad\n",
        );
        assert_eq!(verify_list(&ok), Ok(()));

        assert!(verify_list(&parse_list(SourceKind::Hosts, "# nothing\n")).is_err());
    }

    #[test]
    fn protected_hits_report_blocks_without_an_exception() {
        let blocking = parse_list(SourceKind::Adblock, "||gstatic.com^\n||ntp.org^\n");
        let index = build_index([("one", &blocking)]);
        assert_eq!(
            protected_hits(&index),
            vec!["connectivitycheck.gstatic.com", "pool.ntp.org", "ntp.org"]
        );

        let rescued = parse_list(SourceKind::Adblock, "@@||connectivitycheck.gstatic.com^\n");
        let index = build_index([("one", &blocking), ("two", &rescued)]);
        assert_eq!(protected_hits(&index), vec!["pool.ntp.org", "ntp.org"]);
        assert_eq!(index.names().len(), 2);
        assert_eq!(index.name(1).map(|n| &**n), Some("two"));
    }

    #[test]
    fn source_kind_round_trips() {
        for kind in [SourceKind::Hosts, SourceKind::Domains, SourceKind::Adblock] {
            assert_eq!(kind.as_str().parse::<SourceKind>(), Ok(kind));
        }
        assert_eq!("html".parse::<SourceKind>(), Err(()));
    }

    /// A one-shot HTTP server on loopback that records the request and replies with `response`.
    fn serve_once(response: &'static str) -> (Url, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).expect("read request");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            String::from_utf8_lossy(&request).into_owned()
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/list.txt")).expect("valid url");
        (url, handle)
    }

    fn client() -> Client {
        Client::builder().no_proxy().build().expect("client")
    }

    #[test]
    fn a_conditional_fetch_sends_validators_and_honours_304() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let (url, server) = serve_once("HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n");
        let outcome = runtime
            .block_on(fetch_source_body(
                &client(),
                &url,
                Some("\"v1\""),
                Some("Mon, 01 Jan 2024 00:00:00 GMT"),
            ))
            .expect("fetch");
        assert_eq!(outcome, FetchOutcome::NotModified);
        let request = server.join().expect("server thread").to_ascii_lowercase();
        assert!(request.contains("if-none-match: \"v1\""), "{request}");
        assert!(
            request.contains("if-modified-since: mon, 01 jan 2024 00:00:00 gmt"),
            "{request}"
        );
    }

    #[test]
    fn a_fresh_body_carries_its_validators() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let (url, server) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nETag: \"v2\"\r\nLast-Modified: Tue, 02 Jan 2024 00:00:00 GMT\r\n\r\n||ads.example^",
        );
        let outcome = runtime
            .block_on(fetch_source_body(&client(), &url, None, None))
            .expect("fetch");
        assert_eq!(
            outcome,
            FetchOutcome::Body {
                text: "||ads.example^".to_owned(),
                etag: Some("\"v2\"".to_owned()),
                last_modified: Some("Tue, 02 Jan 2024 00:00:00 GMT".to_owned()),
            }
        );
        let request = server.join().expect("server thread").to_ascii_lowercase();
        assert!(!request.contains("if-none-match"), "{request}");
    }

    #[test]
    fn a_data_url_is_always_a_fresh_body() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let url = Url::parse("data:text/plain,ads.example").expect("valid data url");
        let outcome = runtime
            .block_on(fetch_source_body(&client(), &url, Some("\"x\""), None))
            .expect("fetch");
        assert_eq!(
            outcome,
            FetchOutcome::Body {
                text: "ads.example".to_owned(),
                etag: None,
                last_modified: None,
            }
        );
    }
}
