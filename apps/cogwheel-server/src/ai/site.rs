//! Which website a name belongs to, for grouping only (§6.4). Pure.
//!
//! A site key is used for grouping a site load, scoring its anchor, the per-site caps and the
//! home-context rule. It is never used for policy, so the approximation below (no public-suffix
//! crate) can only cost a grouping, never a verdict. Eligibility (`sendable`) arrives with the
//! reviewer.

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
