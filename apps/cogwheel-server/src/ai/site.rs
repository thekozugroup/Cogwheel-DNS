//! What may leave the house (§6.3), and which website a name belongs to (§6.4). Pure.
//!
//! [`sendable`] is the first half of the check every name in a request passes: the website, the
//! candidate and each name sent with them. The reviewer adds the second half, that no household
//! rule covers the name. It refuses anything private, service-shaped or protected, and anything
//! that could carry an address or an identifier, so what goes out is a public website's name and
//! nothing about the household. Client addresses and device names never reach the request
//! builder at all: its only inputs are names.
//!
//! A site key is used for grouping a site load, scoring its anchor, the per-site caps and the
//! home-context rule. It is never used for policy, so the approximation below (no public-suffix
//! crate) can only cost a grouping, never a verdict.

use cogwheel_policy::{is_domain_shaped, is_protected};

/// The appliance's own names, normalised (§6.3 rule 8): what `AiState::own_names` returns.
pub type OwnNames = [String];

/// The longest name that is sent. Real websites' names are far shorter; long ones are mostly
/// generated.
pub const MAX_NAME: usize = 120;
/// The longest label in a name that is sent.
pub const MAX_LABEL: usize = 40;

/// Names that are never a public website, at or under any of these on a label boundary:
/// special-use and private-use suffixes, the homegrown ones routers hand out, and the local
/// domains router vendors ship, under which a household's devices are named after their owners
/// (`jonas-macbook.fritz.box`). All of `arpa` is here, so reverse lookups, `home.arpa` and
/// `resolver.arpa` are too.
pub const PRIVATE_SUFFIXES: [&str; 22] = [
    "arpa",
    "local",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
    "private",
    "localdomain",
    "localhost",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
    "router",
    "gateway",
    "domain",
    "workgroup",
    // Telekom's `speedport.ip`, and AVM's FRITZ!Box.
    "ip",
    "fritz.box",
    "fritz.nas",
];

/// Public suffixes whose names each lead to one home, never to a website the household opened:
/// wildcard-address services, which spell an address in the name in any notation
/// (`c0a80105.nip.io`, `fd00--1.sslip.io`), and the remote-access and dynamic-DNS services a
/// household reaches its own devices through (`nas.tail1a2b.ts.net`, `smith.duckdns.org`). A
/// household's own domain is not here, and no list could hold them all: a household rule keeps
/// it out (USING.md).
pub const HOME_SUFFIXES: [&str; 15] = [
    "nip.io",
    "sslip.io",
    "xip.io",
    "traefik.me",
    "localtest.me",
    "lvh.me",
    "plex.direct",
    "ts.net",
    "myfritz.net",
    "synology.me",
    "quickconnect.to",
    "duckdns.org",
    "ddns.net",
    "no-ip.org",
    "dyndns.org",
];

// Identifier-like labels (§6.3 rule 7). A session, device or account id in a name would tie a
// request to someone, so a label that looks generated is not sent. The first two rules spare the
// last two labels, where a registered name is; the third applies everywhere.
/// A label at least this long with at least [`ID_DIGITS`] digits.
const ID_LENGTH: usize = 16;
const ID_DIGITS: usize = 6;
/// A run of at least this many hex characters with at least [`HEX_DIGITS`] digits: UUIDs, hashes.
const HEX_RUN: usize = 12;
const HEX_DIGITS: usize = 3;
/// A label at least this long that is at least half digits, wherever it is.
const NUMERIC_LENGTH: usize = 20;

/// Whether `name` (normalised) may be sent to OpenRouter (§6.3).
pub fn sendable(name: &str, own: &OwnNames) -> bool {
    if !is_domain_shaped(name) || name.len() > MAX_NAME {
        return false;
    }
    let count = name.split('.').count();
    for (position, label) in name.split('.').enumerate() {
        // A service label (`_dmarc`, `_dns`) names a record, not a website.
        if label.len() > MAX_LABEL || label.starts_with('_') {
            return false;
        }
        if opaque(label, position + 2 >= count) {
            return false;
        }
    }
    // A numeric or one-letter "top-level domain" is an address or a typo, not a website.
    let tld = name.rsplit('.').next().unwrap_or_default();
    let tld_shaped = (2..=24).contains(&tld.len()) && tld.bytes().all(|b| b.is_ascii_lowercase());
    if !tld_shaped && !tld.starts_with("xn--") {
        return false;
    }
    !PRIVATE_SUFFIXES
        .iter()
        .chain(&HOME_SUFFIXES)
        .any(|suffix| at_or_under(name, suffix))
        && !is_protected(name)
        && !embeds_ipv4(name)
        && !own.iter().any(|own| at_or_under(name, own))
}

/// Whether `name` is `suffix` or under it, on a label boundary.
fn at_or_under(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// Whether a label looks generated rather than chosen (§6.3 rule 7). `registered` is true for the
/// last two labels, which are spared the first two rules.
fn opaque(label: &str, registered: bool) -> bool {
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    if label.len() >= NUMERIC_LENGTH && digits * 2 >= label.len() {
        return true;
    }
    if registered {
        return false;
    }
    if label.len() >= ID_LENGTH && digits >= ID_DIGITS {
        return true;
    }
    let (mut run, mut run_digits) = (0, 0);
    for byte in label.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            run_digits += usize::from(byte.is_ascii_digit());
            if run >= HEX_RUN && run_digits >= HEX_DIGITS {
                return true;
            }
        } else {
            (run, run_digits) = (0, 0);
        }
    }
    false
}

/// Whether `name` carries an IPv4 address: four consecutive tokens, split on `.` and `-`, each a
/// number from 0 to 255 (`10-0-0-5.nip.io`, `192.168.1.2.sslip.io`, `1-2-3-4.cdn.example.net`).
fn embeds_ipv4(name: &str) -> bool {
    let mut octets = 0;
    for token in name.split(['.', '-']) {
        let octet = (1..=3).contains(&token.len())
            && token.bytes().all(|b| b.is_ascii_digit())
            && token.parse::<u16>().is_ok_and(|value| value <= 255);
        octets = if octet { octets + 1 } else { 0 };
        if octets == 4 {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------------- site keys

/// Platforms whose subdomains belong to different people: the site is the tenant's name.
pub const MULTI_TENANT: [&str; 18] = [
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "blogspot.com",
    "wordpress.com",
    "myshopify.com",
    "cloudfront.net",
    "azurewebsites.net",
    "s3.amazonaws.com",
    "fastly.net",
    "akamaized.net",
];

/// Second-level labels under a two-letter country code that are registries, not sites:
/// `bbc.co.uk`, `example.com.au`.
const SECOND_LEVEL: [&str; 13] = [
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic",
];

/// The site `name` belongs to, as a suffix of it: under a [`MULTI_TENANT`] suffix, that suffix
/// plus one label; under `<registry>.<cc>`, the last three labels; otherwise the last two.
pub fn site_key(name: &str) -> &str {
    for tenant in MULTI_TENANT {
        if name == tenant {
            return name;
        }
        if let Some(prefix) = name.strip_suffix(tenant)
            && let Some(prefix) = prefix.strip_suffix('.')
        {
            return &name[label_start(prefix)..];
        }
    }
    let labels: Vec<&str> = name.rsplitn(4, '.').collect();
    let keep = match labels.as_slice() {
        [tld, second, _, ..] if tld.len() == 2 && SECOND_LEVEL.contains(second) => 3,
        _ => 2,
    };
    last_labels(name, keep)
}

/// Where the last label of `prefix` starts, which is where the tenant's label starts in the name.
fn label_start(prefix: &str) -> usize {
    prefix.rfind('.').map_or(0, |dot| dot + 1)
}

/// The last `count` labels of `name`, or all of it if it has no more.
fn last_labels(name: &str, count: usize) -> &str {
    name.rmatch_indices('.')
        .nth(count - 1)
        .map_or(name, |(dot, _)| &name[dot + 1..])
}
