//! Everything the appliance can be told, read once from the environment (§8).
//!
//! Configuration is environment-only by design: an installed box keeps it in
//! `/etc/cogwheel/.env` (Docker, either way it was installed) or
//! `/etc/cogwheel/cogwheel.env` (native systemd), nothing in the control plane writes it back, and
//! `GET /api/v1/settings` is read-only. Unknown variables are ignored, but a variable that is
//! set and cannot be parsed stops startup — a resolver that quietly falls back to a default
//! bind address is a resolver nobody on the network can find.

use crate::ai::key::SecretKey;
use cogwheel_dns_core::UpstreamEndpoint;
use cogwheel_policy::BlockMode;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use url::{Host, Url};

/// Refresh interval floor (§8): a list server is somebody else's, and a tighter loop than this
/// is impolite at best and rate-limited at worst.
const MIN_REFRESH_INTERVAL_SECS: u64 = 300;

/// Prune interval floor (§8). A one-second interval would have the appliance deleting across
/// its largest table continuously.
const MIN_PRUNE_INTERVAL_SECS: u64 = 60;

/// Where AI review sends names when nothing says otherwise (ADR 0002).
const DEFAULT_AI_BASE_URL: &str = "https://openrouter.ai";

/// What a `ConfigError` says instead of the value of a variable that holds a secret.
const HIDDEN: &str = "(hidden)";

/// Where this instance is deployed, which is only ever a shorthand for a set of defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Loopback ports that need no privileges and cannot collide with a running appliance.
    Dev,
    /// The appliance: every interface, the ports the installer redirects :53 to.
    #[default]
    Home,
}

impl Profile {
    /// The name this profile is spelled with in the environment.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Home => "home",
        }
    }
}

impl FromStr for Profile {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, ()> {
        match value {
            "dev" => Ok(Self::Dev),
            // `smb` was a third profile that differed only in which ports it bound; installs
            // that still set it get the home defaults rather than a startup failure.
            "home" | "smb" => Ok(Self::Home),
            _ => Err(()),
        }
    }
}

/// A variable that is set to something this build cannot use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    variable: &'static str,
    value: String,
    expected: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is {:?}, which is not {}",
            self.variable, self.value, self.expected
        )
    }
}

impl std::error::Error for ConfigError {}

/// The whole configuration, read once in `main` and shared read-only from there on.
///
/// Flat, and one struct: every field is one environment variable, nothing here is optional, and
/// grouping them into `server`/`storage`/`retention` sub-structs only meant a longer path at each
/// of the sixty places that read one.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub profile: Profile,
    pub http_bind_addr: SocketAddr,
    pub dns_udp_bind_addr: SocketAddr,
    pub dns_tcp_bind_addr: SocketAddr,
    /// The port the connect instructions print, which differs from the bound one whenever
    /// something in front of the process redirects 53.
    pub advertised_dns_port: u16,
    /// Addresses to advertise; empty means "ask the host" (§3 route 3).
    pub advertised_dns_targets: Vec<String>,
    /// The list body cache of §2.6 lives beside this file.
    pub database_url: String,
    pub upstream_servers: Vec<String>,
    pub block_mode: BlockMode,
    pub refresh_interval_secs: u64,
    /// Days of raw log rows. `0` means the log is never written at all; the hourly rollups, which
    /// are counts and not browsing history, are kept either way.
    pub history_days: u32,
    pub max_rows: u64,
    pub prune_interval_secs: u64,
    /// `false` is the operator's kill switch for AI review (ADR 0002): the reviewer never starts,
    /// the AI list compiles empty, and the AI writes answer 409.
    pub ai_available: bool,
    /// An OpenRouter key from the environment. It wins over one saved in the UI, which then
    /// cannot change it.
    pub ai_api_key: Option<SecretKey>,
    /// Where OpenRouter is. Environment-only, and never settable through the API, so nobody on
    /// the network can point the bearer key somewhere else.
    pub ai_base_url: Url,
    /// Ask OpenRouter for zero-data-retention providers only (`provider.zdr`).
    pub ai_zero_retention: bool,
    /// Extra hostnames the AI routes' guard accepts: a reverse proxy's name, lowercased.
    pub allowed_hosts: Vec<String>,
}

impl AppConfig {
    /// Read the process environment.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first variable that is set to something unusable.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|key| std::env::var(key).ok())
    }

    /// Read from an arbitrary source, which is what the tests use.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first variable that is set to something unusable.
    pub fn from_source<F>(get: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let profile = match get("COGWHEEL_PROFILE") {
            Some(value) => Profile::from_str(&value).map_err(|()| ConfigError {
                variable: "COGWHEEL_PROFILE",
                value,
                expected: "one of dev, home, smb",
            })?,
            None => Profile::default(),
        };
        let mut config = Self::for_profile(profile);

        if let Some(value) = parse(&get, "COGWHEEL_SERVER__HTTP_BIND_ADDR", "an ip:port")? {
            config.http_bind_addr = value;
        }
        if let Some(value) = parse(&get, "COGWHEEL_SERVER__DNS_UDP_BIND_ADDR", "an ip:port")? {
            config.dns_udp_bind_addr = value;
        }
        if let Some(value) = parse(&get, "COGWHEEL_SERVER__DNS_TCP_BIND_ADDR", "an ip:port")? {
            config.dns_tcp_bind_addr = value;
        }
        // Defaulted after the binds are known, so overriding only the UDP port still advertises
        // the port people actually have to type.
        config.advertised_dns_port = parse(
            &get,
            "COGWHEEL_SERVER__ADVERTISED_DNS_PORT",
            "a port number",
        )?
        .unwrap_or(config.dns_udp_bind_addr.port());
        config.advertised_dns_targets = get("COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS")
            .map(|value| split_list(&value))
            .unwrap_or_default();

        if let Some(value) = get("COGWHEEL_STORAGE__DATABASE_URL") {
            config.database_url = value;
        }
        if let Some(value) = get("COGWHEEL_UPSTREAM__SERVERS") {
            let servers = split_list(&value);
            if servers.is_empty() {
                return Err(ConfigError {
                    variable: "COGWHEEL_UPSTREAM__SERVERS",
                    value,
                    expected: "a comma-separated list of at least one upstream",
                });
            }
            // Parsed here as well as in the resolver builder: a typo in an upstream spec is the
            // difference between forwarding and not, and it should fail at startup with the bad
            // value quoted rather than as a resolver error minutes later.
            for server in &servers {
                UpstreamEndpoint::parse(server).map_err(|_| ConfigError {
                    variable: "COGWHEEL_UPSTREAM__SERVERS",
                    value: server.clone(),
                    expected: "an ip:port, tls://ip#name or https://ip#name/path upstream",
                })?;
            }
            config.upstream_servers = servers;
        }
        if let Some(value) = get("COGWHEEL_BLOCKING__MODE") {
            // Spelled forgivingly: an env file that picked up a trailing space, or somebody who
            // wrote the mode with a hyphen, is not a reason to leave a household without DNS.
            let spelling = value.trim().to_ascii_lowercase().replace('-', "_");
            config.block_mode = BlockMode::from_str(&spelling).map_err(|()| ConfigError {
                variable: "COGWHEEL_BLOCKING__MODE",
                value,
                expected: "one of null_ip, nxdomain, nodata, refused",
            })?;
        }
        // The two intervals take a floor rather than a rejection: both are politeness bounds — on
        // somebody else's list server, and on the appliance's own SD card — not something an
        // operator can get wrong in a way worth refusing to boot over.
        if let Some(value) = parse::<u64, _>(
            &get,
            "COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS",
            "a number of seconds",
        )? {
            config.refresh_interval_secs = value.max(MIN_REFRESH_INTERVAL_SECS);
        }
        if let Some(value) = parse::<u64, _>(
            &get,
            "COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS",
            "a number of seconds",
        )? {
            config.prune_interval_secs = value.max(MIN_PRUNE_INTERVAL_SECS);
        }
        if let Some(value) = parse(&get, "COGWHEEL_RETENTION__HISTORY_DAYS", "a number of days")? {
            config.history_days = value;
        }
        if let Some(value) = parse(
            &get,
            "COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS",
            "a number of rows",
        )? {
            config.max_rows = value;
        }

        if let Some(value) = flag(&get, "COGWHEEL_AI__AVAILABLE")? {
            config.ai_available = value;
        }
        if let Some(value) = get("COGWHEEL_AI__OPENROUTER_API_KEY") {
            // Never the value, not even in the error that stops startup: it is printed, and
            // `docker logs` is not a place a key should end up.
            config.ai_api_key = SecretKey::from_env(&value).map_err(|()| ConfigError {
                variable: "COGWHEEL_AI__OPENROUTER_API_KEY",
                value: HIDDEN.to_owned(),
                expected: "an OpenRouter key: at most 512 visible ASCII characters, no spaces",
            })?;
        }
        if let Some(value) = get("COGWHEEL_AI__BASE_URL") {
            config.ai_base_url = ai_base_url(&value).ok_or_else(|| ConfigError {
                variable: "COGWHEEL_AI__BASE_URL",
                // A URL with credentials in it is refused, and not repeated either.
                value: if value.contains('@') {
                    HIDDEN.to_owned()
                } else {
                    value.clone()
                },
                expected: "an https:// address (or http:// to this machine) with no path, query \
                           or credentials",
            })?;
        }
        if let Some(value) = flag(&get, "COGWHEEL_AI__ZERO_RETENTION")? {
            config.ai_zero_retention = value;
        }
        if let Some(value) = get("COGWHEEL_SERVER__ALLOWED_HOSTS") {
            config.allowed_hosts = allowed_hosts(&value)?;
        }

        Ok(config)
    }

    /// The defaults a profile stands for, before any explicit variable is applied.
    pub fn for_profile(profile: Profile) -> Self {
        let (host, http_port, dns_port) = match profile {
            Profile::Dev => (IpAddr::V4(Ipv4Addr::LOCALHOST), 30080, 30053),
            Profile::Home => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080, 5353),
        };
        Self {
            profile,
            http_bind_addr: SocketAddr::new(host, http_port),
            dns_udp_bind_addr: SocketAddr::new(host, dns_port),
            dns_tcp_bind_addr: SocketAddr::new(host, dns_port),
            advertised_dns_port: dns_port,
            advertised_dns_targets: Vec::new(),
            database_url: "sqlite://data/cogwheel.db".to_owned(),
            upstream_servers: vec!["1.1.1.1:53".to_owned(), "1.0.0.1:53".to_owned()],
            block_mode: BlockMode::NullIp,
            // A development instance re-fetches hourly so a list edit can be watched; the
            // appliance is daily, which is how often these lists actually change.
            refresh_interval_secs: match profile {
                Profile::Dev => 3_600,
                Profile::Home => 86_400,
            },
            history_days: 7,
            max_rows: 250_000,
            prune_interval_secs: 3_600,
            ai_available: true,
            ai_api_key: None,
            ai_base_url: Url::parse(DEFAULT_AI_BASE_URL)
                .unwrap_or_else(|error| unreachable!("the default OpenRouter URL parses: {error}")),
            ai_zero_retention: true,
            allowed_hosts: Vec::new(),
        }
    }

    /// The database file, with the `sqlite://` prefix the config uses stripped.
    pub fn database_path(&self) -> PathBuf {
        PathBuf::from(
            self.database_url
                .strip_prefix("sqlite://")
                .unwrap_or(&self.database_url),
        )
    }

    /// `<dir of the database>/lists`, the on-disk body cache of §2.6.
    ///
    /// A database with no directory part — a bare filename, or `:memory:` in tests — caches into
    /// `lists/` in the working directory rather than at the filesystem root.
    pub fn lists_dir(&self) -> PathBuf {
        let path = self.database_path();
        let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
        parent.map_or_else(|| PathBuf::from("lists"), |dir| dir.join("lists"))
    }

    /// Whether raw query rows are written, which is also `queries.logging` on the wire.
    pub const fn logging(&self) -> bool {
        self.history_days != 0
    }
}

/// Read one variable and parse it, naming it in the error if it will not parse.
fn parse<T, F>(
    get: &F,
    variable: &'static str,
    expected: &'static str,
) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = get(variable) else {
        return Ok(None);
    };
    match value.trim().parse::<T>() {
        Ok(parsed) => Ok(Some(parsed)),
        Err(_) => Err(ConfigError {
            variable,
            value,
            expected,
        }),
    }
}

/// Read a switch. Spelled forgivingly, like the block mode: `true`/`false`, `1`/`0`, `yes`/`no`
/// and `on`/`off`, in any case.
fn flag<F>(get: &F, variable: &'static str) -> Result<Option<bool>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(value) = get(variable) else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(Some(true)),
        "false" | "0" | "no" | "off" => Ok(Some(false)),
        _ => Err(ConfigError {
            variable,
            value,
            expected: "true or false",
        }),
    }
}

/// An OpenRouter base URL, or `None` if it is not one Cogwheel will send a key to.
///
/// `https://`, or `http://` only to a loopback host (the offline test stub). No path but `/`, no
/// query, fragment or credentials: the endpoints are joined onto it, and anything else would be
/// a second place for a request to be redirected.
fn ai_base_url(value: &str) -> Option<Url> {
    let url = Url::parse(value.trim()).ok()?;
    let secure = match url.scheme() {
        "https" => true,
        "http" => is_loopback(&url),
        _ => false,
    };
    let bare = url.host().is_some()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    (secure && bare).then_some(url)
}

/// Whether a URL's host is this machine: 127.0.0.0/8, `::1` or `localhost`.
pub fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// `COGWHEEL_SERVER__ALLOWED_HOSTS`: hostnames, lowercased, no ports. An IP literal never needs
/// listing (the guard accepts one already), so anything with a `:` is a mistake worth naming.
fn allowed_hosts(value: &str) -> Result<Vec<String>, ConfigError> {
    split_list(value)
        .into_iter()
        .map(|entry| {
            let host = entry.trim_end_matches('.').to_ascii_lowercase();
            let usable = !host.is_empty()
                && !host.contains([':', '/', '@'])
                && !host.contains(char::is_whitespace);
            if usable {
                Ok(host)
            } else {
                Err(ConfigError {
                    variable: "COGWHEEL_SERVER__ALLOWED_HOSTS",
                    value: entry,
                    expected: "a comma-separated list of hostnames, without ports",
                })
            }
        })
        .collect()
}

/// Split a comma-separated variable, dropping empty entries and surrounding space.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, ConfigError, Profile};
    use cogwheel_policy::BlockMode;
    use std::collections::HashMap;

    fn config_from(pairs: &[(&str, &str)]) -> Result<AppConfig, ConfigError> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        AppConfig::from_source(move |key| env.get(key).cloned())
    }

    #[test]
    fn the_home_profile_is_the_default() {
        let config = config_from(&[]).expect("defaults load");
        assert_eq!(config.profile, Profile::Home);
        assert_eq!(config.http_bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(config.dns_udp_bind_addr.to_string(), "0.0.0.0:5353");
        assert_eq!(config.advertised_dns_port, 5353);
        assert_eq!(config.refresh_interval_secs, 86_400);
        assert_eq!(config.history_days, 7);
        assert_eq!(config.max_rows, 250_000);
        assert_eq!(config.prune_interval_secs, 3_600);
        assert_eq!(config.block_mode, BlockMode::NullIp);
    }

    #[test]
    fn the_dev_profile_binds_loopback_ports() {
        let config = config_from(&[("COGWHEEL_PROFILE", "dev")]).expect("dev loads");
        assert_eq!(config.http_bind_addr.to_string(), "127.0.0.1:30080");
        assert_eq!(config.dns_udp_bind_addr.to_string(), "127.0.0.1:30053");
        assert_eq!(config.refresh_interval_secs, 3_600);
    }

    #[test]
    fn smb_is_an_alias_for_home() {
        let config = config_from(&[("COGWHEEL_PROFILE", "smb")]).expect("smb loads");
        assert_eq!(config.profile, Profile::Home);
        assert_eq!(config.dns_udp_bind_addr.to_string(), "0.0.0.0:5353");
    }

    #[test]
    fn an_unknown_profile_fails_startup() {
        let error = config_from(&[("COGWHEEL_PROFILE", "office")]).expect_err("unknown profile");
        assert_eq!(
            error.to_string(),
            "COGWHEEL_PROFILE is \"office\", which is not one of dev, home, smb"
        );
    }

    #[test]
    fn an_unparseable_bind_address_fails_startup() {
        let error = config_from(&[("COGWHEEL_SERVER__HTTP_BIND_ADDR", "8080")])
            .expect_err("a bare port is not an address");
        assert!(
            error
                .to_string()
                .starts_with("COGWHEEL_SERVER__HTTP_BIND_ADDR")
        );
    }

    #[test]
    fn an_unparseable_upstream_fails_startup() {
        let error = config_from(&[("COGWHEEL_UPSTREAM__SERVERS", "1.1.1.1:53,nonsense://x")])
            .expect_err("a bad upstream spec");
        assert!(error.to_string().contains("nonsense://x"));
    }

    #[test]
    fn the_refresh_interval_and_prune_interval_have_floors() {
        let config = config_from(&[
            ("COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS", "5"),
            ("COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS", "1"),
        ])
        .expect("floors apply");
        assert_eq!(config.refresh_interval_secs, 300);
        assert_eq!(config.prune_interval_secs, 60);
    }

    #[test]
    fn history_days_zero_switches_the_log_off_without_failing() {
        let config =
            config_from(&[("COGWHEEL_RETENTION__HISTORY_DAYS", "0")]).expect("zero is legal");
        assert_eq!(config.history_days, 0);
        assert!(!config.logging());
    }

    #[test]
    fn advertised_targets_are_split_and_trimmed() {
        let config = config_from(&[(
            "COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS",
            " 192.168.1.2 , , cogwheel.local ",
        )])
        .expect("targets load");
        assert_eq!(
            config.advertised_dns_targets,
            vec!["192.168.1.2".to_owned(), "cogwheel.local".to_owned()]
        );
    }

    #[test]
    fn the_list_cache_lives_beside_the_database() {
        let config = config_from(&[(
            "COGWHEEL_STORAGE__DATABASE_URL",
            "sqlite:///var/lib/cw/x.db",
        )])
        .expect("path loads");
        assert_eq!(config.database_path().to_str(), Some("/var/lib/cw/x.db"));
        assert_eq!(config.lists_dir().to_str(), Some("/var/lib/cw/lists"));
    }

    #[test]
    fn a_database_with_no_directory_caches_into_the_working_directory() {
        let config =
            config_from(&[("COGWHEEL_STORAGE__DATABASE_URL", ":memory:")]).expect("memory loads");
        assert_eq!(config.lists_dir().to_str(), Some("lists"));
    }

    /// A recognisable fake, so a leak of any part shows. Deliberately not OpenRouter's real shape
    /// (`sk-or-v1-` and 64 hex digits): a test key in that shape trips secret scanning on push.
    const KEY: &str = "sk-or-v1-fake-test-key-qwzx-mnbv-plok-ijuh-ygtf-rdes";

    #[test]
    fn an_unusable_ai_key_stops_startup_without_echoing_it() {
        for value in [
            "sk-or-v1-0123456789 abcdef0123456789",
            "sk-or-v1-0123456789\tabcdef",
            "sk-or-v1-ключ0123456789abcdef",
            &"k".repeat(513),
        ] {
            let error = config_from(&[("COGWHEEL_AI__OPENROUTER_API_KEY", value)])
                .expect_err("a value that cannot be a header stops startup");
            let printed = format!("{error} {error:?}");
            assert!(printed.contains("COGWHEEL_AI__OPENROUTER_API_KEY"));
            assert!(printed.contains("(hidden)"), "{printed}");
            assert!(!printed.contains("0123456789"), "the key leaked: {printed}");
        }

        // No `sk-or-` check: a future key format must not stop boot. Empty counts as unset.
        let config = config_from(&[(
            "COGWHEEL_AI__OPENROUTER_API_KEY",
            "  rk-future-format-key  ",
        )])
        .expect("any header-safe key loads");
        assert_eq!(
            config.ai_api_key.as_ref().map(|key| key.expose()),
            Some("rk-future-format-key")
        );
        let config =
            config_from(&[("COGWHEEL_AI__OPENROUTER_API_KEY", "  ")]).expect("empty is unset");
        assert!(config.ai_api_key.is_none());
    }

    #[test]
    fn the_ai_base_url_must_be_https_or_loopback() {
        let base = |value: &str| {
            config_from(&[("COGWHEEL_AI__BASE_URL", value)]).map(|config| config.ai_base_url)
        };
        assert_eq!(
            config_from(&[])
                .expect("defaults load")
                .ai_base_url
                .as_str(),
            "https://openrouter.ai/"
        );
        for accepted in [
            "https://openrouter.ai",
            "https://openrouter.ai/",
            "https://proxy.example.net:8443",
            "http://127.0.0.1:18080",
            "http://[::1]:18080",
            "http://localhost:18080/",
        ] {
            assert!(base(accepted).is_ok(), "{accepted} should be accepted");
        }
        for refused in [
            "http://openrouter.ai",
            "http://192.168.1.10:8080",
            "ftp://openrouter.ai",
            "https://openrouter.ai/api/v1",
            "https://openrouter.ai/?x=1",
            "https://openrouter.ai/#here",
            "openrouter.ai",
        ] {
            let error = base(refused).expect_err("refused");
            assert!(error.to_string().starts_with("COGWHEEL_AI__BASE_URL"));
        }

        // Credentials are refused, and not repeated in the error that is printed.
        let error = base("https://user:secret-password@openrouter.ai").expect_err("userinfo");
        assert!(!error.to_string().contains("secret-password"), "{error}");
        assert!(error.to_string().contains("(hidden)"));
    }

    #[test]
    fn debug_output_never_contains_the_key() {
        let config =
            config_from(&[("COGWHEEL_AI__OPENROUTER_API_KEY", KEY)]).expect("the key loads");
        let printed = format!("{config:?} {config:#?}");
        assert!(printed.contains("SecretKey(..)"), "{printed}");
        for window in KEY.as_bytes().windows(8) {
            let window = std::str::from_utf8(window).expect("ascii");
            assert!(!printed.contains(window), "{window:?} of the key leaked");
        }
    }

    #[test]
    fn allowed_hosts_are_parsed_lowercase() {
        let config = config_from(&[(
            "COGWHEEL_SERVER__ALLOWED_HOSTS",
            " Cogwheel.Example.COM , , proxy.lan. ",
        )])
        .expect("hosts load");
        assert_eq!(
            config.allowed_hosts,
            vec!["cogwheel.example.com".to_owned(), "proxy.lan".to_owned()]
        );
        assert!(
            config_from(&[])
                .expect("defaults load")
                .allowed_hosts
                .is_empty()
        );
        for refused in ["proxy.lan:8443", "https://proxy.lan", "user@proxy.lan"] {
            let error = config_from(&[("COGWHEEL_SERVER__ALLOWED_HOSTS", refused)])
                .expect_err("not a bare hostname");
            assert!(
                error
                    .to_string()
                    .starts_with("COGWHEEL_SERVER__ALLOWED_HOSTS")
            );
        }
    }

    #[test]
    fn ai_review_is_available_by_default_and_can_be_switched_off() {
        let config = config_from(&[]).expect("defaults load");
        assert!(config.ai_available);
        assert!(
            config.ai_zero_retention,
            "zero retention is asked for by default"
        );
        assert!(config.ai_api_key.is_none());

        for (spelling, expected) in [
            ("false", false),
            ("OFF", false),
            (" 0 ", false),
            ("yes", true),
        ] {
            let config =
                config_from(&[("COGWHEEL_AI__AVAILABLE", spelling)]).expect("a switch loads");
            assert_eq!(config.ai_available, expected, "{spelling:?}");
        }
        let config = config_from(&[("COGWHEEL_AI__ZERO_RETENTION", "false")])
            .expect("zero retention can be turned off");
        assert!(!config.ai_zero_retention);

        let error = config_from(&[("COGWHEEL_AI__AVAILABLE", "maybe")]).expect_err("not a switch");
        assert_eq!(
            error.to_string(),
            "COGWHEEL_AI__AVAILABLE is \"maybe\", which is not true or false"
        );
    }
}
