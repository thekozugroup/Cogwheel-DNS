//! `site.rs`: what may be sent (§6.3), and site keys (§6.4), which group and never decide.

use crate::ai::site::{MAX_NAME, sendable, site_key};

/// No names of the appliance's own.
const NONE: [String; 0] = [];

#[test]
fn ordinary_public_names_are_sendable() {
    for name in [
        "www.news-site.com",
        "cdn.news-site.com",
        "a.et.news-site.com",
        "fonts.gstatic.com",
        "securepubads.g.doubleclick.net",
        "static.files.bbci.co.uk",
        "d3c3cq33003psk.cloudfront.net",
        "1.example-cdn.net",
        "v1-2-3.api.example.com",
        "xn--80ak6aa92e.com",
        "example.xn--p1ai",
        "user-content.github.io",
    ] {
        assert!(sendable(name, &NONE), "{name}");
    }
}

#[test]
fn private_and_service_names_are_never_sendable() {
    let long = format!("{}.com", "a".repeat(MAX_NAME - 4 + 1));
    assert_eq!(long.len(), MAX_NAME + 1);
    for name in [
        "nas.lan",
        "lan",
        "printer.local",
        "router.home.arpa",
        "home.arpa",
        "5.1.168.192.in-addr.arpa",
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
        "_dns.resolver.arpa",
        "_dmarc.x.com",
        "_443._tcp.www.example.com",
        "box.internal",
        "files.corp",
        "me.localhost",
        "a.test",
        "www.example",
        "abc.onion",
        "x.y.alt",
        // A single label, and a numeric or one-letter top-level domain.
        "localhost",
        "intranet",
        "host.123",
        "a.b.c",
        // Protected: resolver bootstrap and connectivity checks.
        "captive.apple.com",
        "dns.google",
        "connectivitycheck.gstatic.com",
        // Not names at all, or too long to be a website's.
        "",
        "Www.Example.com",
        "has space.com",
        "a..b.com",
        &long,
        &format!("{}.com", "a".repeat(41)),
    ] {
        assert!(!sendable(name, &NONE), "{name:?}");
    }
    assert!(sendable(&format!("{}.com", "a".repeat(40)), &NONE));
}

#[test]
fn identifier_labels_and_embedded_addresses_are_never_sendable() {
    for name in [
        // A UUID, a long hex run, an id with many digits.
        "550e8400-e29b-41d4-a716-446655440000.telemetry.example-cdn.net",
        "3f2a9c41d7e8b6a05c1d.api.example.com",
        "a1b2c3d4e5f6.cdn.example.com",
        "user4815162342xyz.sessions.example.com",
        // At least half digits and 20 long, even as the registered name.
        "12345678901234567890.com",
        "www.a1234567890123456789.com",
        // An IPv4 address in the name.
        "10-0-0-5.nip.io",
        "192.168.1.2.sslip.io",
        "1-2-3-4.example-cdn.net",
        "ec2-54-12-0-255.compute-1.amazonaws.com",
    ] {
        assert!(!sendable(name, &NONE), "{name}");
    }
    // Close, but not quite: three octets, an octet over 255, hex with no digits.
    for name in [
        "10-0-0.example.net",
        "300-1-1-1.example.net",
        "deadbeefcafe.example.com",
        "abc123def45.example.com",
    ] {
        assert!(sendable(name, &NONE), "{name}");
    }
}

#[test]
fn the_appliances_own_names_are_never_sendable() {
    let own = [
        "cogwheel.lan.example.com".to_owned(),
        "dns.home-net.org".to_owned(),
    ];
    for name in [
        "cogwheel.lan.example.com",
        "api.cogwheel.lan.example.com",
        "dns.home-net.org",
    ] {
        assert!(!sendable(name, &own), "{name}");
    }
    // Only on a label boundary.
    assert!(sendable("mydns.home-net.org", &own));
    assert!(sendable("home-net.org", &own));
}

#[test]
fn site_keys_group_second_level_and_multi_tenant_suffixes() {
    for (name, key) in [
        ("www.example.com", "example.com"),
        ("a.b.c.example.com", "example.com"),
        ("example.com", "example.com"),
        ("def.io", "def.io"),
        ("cdn.def.io", "def.io"),
        // A registry under a country code is not a site.
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("bbc.co.uk", "bbc.co.uk"),
        ("static.files.bbci.co.uk", "bbci.co.uk"),
        ("shop.example.com.au", "example.com.au"),
        ("co.uk", "co.uk"),
        // A three-letter top-level domain is not a country code.
        ("www.example.com.net", "com.net"),
        // Each tenant of a multi-tenant platform is its own site.
        ("user.github.io", "user.github.io"),
        ("docs.user.github.io", "user.github.io"),
        ("github.io", "github.io"),
        ("my-app.pages.dev", "my-app.pages.dev"),
        (
            "d111111abcdef8.cloudfront.net",
            "d111111abcdef8.cloudfront.net",
        ),
        ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
        // Only on a label boundary.
        ("notgithub.io", "notgithub.io"),
        ("localhost", "localhost"),
    ] {
        assert_eq!(site_key(name), key, "{name}");
    }
}
