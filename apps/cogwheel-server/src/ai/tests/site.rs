//! `site.rs::site_key` (§6.4): grouping only, never policy.

use crate::ai::site::site_key;

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
