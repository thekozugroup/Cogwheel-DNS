//! Compiling the database into the `Policy` the hot path evaluates against (§6).
//!
//! Three kinds of change reach here and they are not equivalent. A list change alters what every
//! scope decides, so the DNS cache is dropped and scope ids start afresh. A household-rule change
//! does the same to verdicts without touching the index, so the index `Arc` is reused but the
//! cache still goes. A device change only re-maps clients onto scopes, so the cache survives and
//! the edited device simply lands on a new id whose entries have to be fetched once.

use crate::http::ApiError;
use crate::state::{DeviceNames, ServerState, lock, read, write};
use cogwheel_lists::{ParsedList, SourceKind, build_index, parse_list, protected_hits};
use cogwheel_policy::{Action, ListIndex, Policy, RuleSet, Scope, normalize_rule_domain};
use cogwheel_storage::{Device, DeviceList, Rule, Source};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// Enabled lists that fit in one policy: one bit of the scope mask each (§6).
pub const MAX_LIST_SLOTS: usize = 64;

/// Which parts of the policy a change invalidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rebuild {
    /// Lists were fetched, toggled, added or removed: the index is rebuilt from the cached
    /// bodies and every cached answer is dropped.
    Lists,
    /// A rule that applies to everyone changed: the index is reused, the cache is dropped.
    Household,
    /// Only devices (or their own rules) changed: the index and the cache are both kept.
    Devices,
}

impl Rebuild {
    /// Whether verdicts may now differ for names already answered.
    const fn invalidates_cache(self) -> bool {
        matches!(self, Self::Lists | Self::Household)
    }
}

/// What a build installed, for the caller to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyStats {
    /// Distinct names in the index — the Overview's `rules_loaded`.
    pub rules_loaded: usize,
    /// Enabled lists that took a slot.
    pub slots: usize,
}

/// Read the database, compile a policy and install it in the runtime.
///
/// # Errors
///
/// A storage failure, or a panic on the blocking pool (which is reported as a 500).
pub async fn rebuild(state: &ServerState, kind: Rebuild) -> Result<PolicyStats, ApiError> {
    // Held across the whole build so two concurrent edits cannot interleave "read the rows" and
    // "install the policy" and leave the older read winning.
    let _serialised = state.rebuild_lock.lock().await;

    let sources = state.storage.list_sources().await?;
    let devices = state.storage.list_devices().await?;
    let device_lists = state.storage.list_device_lists(None).await?;
    let rules = state.storage.list_rules(None).await?;

    // `enabled_slots` takes only the first 64. The API refuses a 65th under the refresh gate, so
    // reaching this means the database was edited behind the server's back — and a list with no
    // slot still shows a rule count and a green "Last updated" while contributing no bits to any
    // mask. Name it, rather than let filtering go missing quietly.
    for dropped in sources
        .iter()
        .filter(|source| source.enabled)
        .skip(MAX_LIST_SLOTS)
    {
        tracing::error!(
            list = %dropped.name,
            "more than {MAX_LIST_SLOTS} lists are enabled; this one has no slot and filters nothing"
        );
    }

    // Slots are assigned from this list, so an index built from a different one cannot be
    // reused: the masks it produced would name lists by the wrong bit.
    let enabled: Vec<String> = enabled_slots(&sources)
        .map(|source| source.id.clone())
        .collect();
    let kind = if kind == Rebuild::Lists || *read(&state.indexed_lists) == enabled {
        kind
    } else {
        tracing::debug!("the enabled lists moved since the index was built; recompiling them");
        Rebuild::Lists
    };

    // A device or household rebuild reuses the compiled index: the lists did not change, and
    // re-reading 50,000 lines off an SD card to rename a phone would be absurd.
    let reuse = (kind != Rebuild::Lists).then(|| state.runtime.current_policy());
    let index = reuse.as_ref().map(|policy| Arc::clone(&policy.index));

    let lists_dir = PathBuf::from(state.lists_dir.as_path());
    // Taken before `sources` is moved onto the blocking pool; the sweep below needs every id,
    // disabled ones included, since a disabled list keeps its cached body.
    let known: Vec<String> = sources.iter().map(|source| source.id.clone()).collect();
    let block_mode = state.runtime.block_mode();
    let scopes = Arc::clone(&state.scopes);
    let built = tokio::task::spawn_blocking(move || {
        let index = index.unwrap_or_else(|| Arc::new(compile_index(&sources, &lists_dir)));
        let mut scopes = lock(&scopes);
        if kind.invalidates_cache() {
            scopes.reset();
        }
        compile_policy(
            &sources,
            &devices,
            &device_lists,
            &rules,
            index,
            block_mode,
            &mut scopes,
        )
    })
    .await
    .map_err(|error| {
        tracing::error!(%error, "policy build task failed");
        ApiError::internal("The policy could not be compiled.")
    })?;

    if kind == Rebuild::Lists {
        sweep_orphan_bodies(&state.lists_dir, &known).await;
    }
    state.set_device_names(built.device_names);
    *write(&state.indexed_lists) = enabled;
    let policy = Arc::new(built.policy);
    if kind.invalidates_cache() {
        state.runtime.swap_policy(policy);
    } else {
        state.runtime.swap_policy_keep_cache(policy);
    }
    tracing::info!(
        ?kind,
        rules_loaded = built.stats.rules_loaded,
        slots = built.stats.slots,
        "policy installed"
    );
    Ok(built.stats)
}

/// A compiled policy and the two things the server keeps alongside it.
struct Built {
    policy: Policy,
    device_names: DeviceNames,
    stats: PolicyStats,
}

/// Build the list index from the cached bodies on disk (§2.6, §6 step 1).
///
/// Every enabled source takes a slot whether or not its body has been fetched, so a list that is
/// still downloading does not shift the slots of the lists around it. A body that cannot be read
/// or parsed contributes nothing and is logged: the alternative — refusing to compile — would
/// mean one damaged cache file leaves the household with no filtering at all.
///
/// Every enabled body is re-read and re-parsed on every list change, and the parsed form is not
/// kept between builds. Measured: the whole rebuild for two lists of ~56,000 entries is 40 ms,
/// which is under a frame of the switch animation, while holding the parsed entries resident
/// costs ~3 MB of a 45 MB budget and saved nothing.
fn compile_index(sources: &[Source], lists_dir: &Path) -> ListIndex {
    let mut parsed = Vec::new();
    for source in enabled_slots(sources) {
        let kind = SourceKind::from_str(&source.kind).unwrap_or(SourceKind::Domains);
        let body =
            std::fs::read_to_string(body_path(lists_dir, &source.id)).unwrap_or_else(|error| {
                tracing::debug!(list = %source.name, %error, "no cached body for this list yet");
                String::new()
            });
        parsed.push((source.name.clone(), parse_list(kind, &body)));
    }
    let index = build_index(
        parsed
            .iter()
            .map(|(name, list)| (name.as_str(), list as &ParsedList)),
    );
    // Never a rejection: protection is enforced at evaluation, so these names stay reachable
    // whatever the lists say. The per-list `note` column carries the same fact to the UI.
    let protected = protected_hits(&index);
    if !protected.is_empty() {
        tracing::info!(
            names = protected.join(", "),
            "these protected names are on a subscribed list and stay reachable anyway"
        );
    }
    index
}

/// Where a source's cached body lives (§2.6).
pub fn body_path(lists_dir: &Path, source_id: &str) -> PathBuf {
    lists_dir.join(format!("{source_id}.txt"))
}

/// Delete cached bodies that belong to no list any more.
///
/// The delete handler removes the file itself, so this is the backstop for the paths it cannot
/// cover: a crash between the row delete and the file delete, a restored database that is older
/// than the cache directory, or a `.tmp` left by a fetch that was killed mid-write. Nothing reads
/// these — `compile_index` only opens bodies for rows still in `sources` — so they are pure
/// growth on the appliance's SD card, several megabytes apiece.
async fn sweep_orphan_bodies(lists_dir: &Path, known: &[String]) {
    let Ok(mut entries) = tokio::fs::read_dir(lists_dir).await else {
        return; // No cache directory yet: nothing has ever been fetched.
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        // Matched on the stem alone, extension ignored: a device or rule edit can promote itself
        // to a list rebuild (see above) without holding the refresh gate, so a fetch may be
        // part-way through writing `<id>.tmp` right now. Deleting that would fail its rename and
        // fail a fetch that was about to succeed. Anything whose stem is not a list at all is
        // safe to take, `.tmp` included.
        let live = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| known.iter().any(|id| id == stem));
        if live {
            continue;
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => tracing::info!(path = %path.display(), "removed an orphaned list body"),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "could not remove an orphaned list body");
            }
        }
    }
}

/// The enabled sources that get a slot, in `id` order — the slot order of §6.
pub fn enabled_slots(sources: &[Source]) -> impl Iterator<Item = &Source> {
    // `list_sources` is already `ORDER BY id`, which is the slot order; re-sorting here would
    // only introduce a way for the two to disagree.
    sources
        .iter()
        .filter(|source| source.enabled)
        .take(MAX_LIST_SLOTS)
}

/// Compile the scopes (§6 steps 2–5). Pure: everything it needs is an argument.
fn compile_policy(
    sources: &[Source],
    devices: &[Device],
    device_lists: &[DeviceList],
    rules: &[Rule],
    index: Arc<ListIndex>,
    block_mode: cogwheel_policy::BlockMode,
    scopes: &mut crate::state::ScopeAllocator,
) -> Built {
    let slot_of: HashMap<&str, u8> = enabled_slots(sources)
        .enumerate()
        .filter_map(|(slot, source)| {
            u8::try_from(slot)
                .ok()
                .map(|slot| (source.id.as_str(), slot))
        })
        .collect();
    let all_mask = slot_of.values().fold(0u64, |mask, slot| mask | bit(*slot));

    let household = Arc::new(rule_set(
        rules.iter().filter(|rule| rule.device_id.is_none()),
    ));

    let mut by_ip = HashMap::with_capacity(devices.len());
    let mut device_names = DeviceNames::with_capacity(devices.len());
    for device in devices {
        let Ok(ip) = device.ip_address.parse::<IpAddr>() else {
            // Only reachable on a database edited by hand: the API rejects a non-address.
            tracing::warn!(
                device = %device.name,
                address = %device.ip_address,
                "this device's address is not an IP; it resolves as the household"
            );
            continue;
        };
        let mask = if device.all_lists {
            all_mask
        } else {
            device_lists
                .iter()
                .filter(|link| link.device_id == device.id)
                .filter_map(|link| slot_of.get(link.source_id.as_str()))
                .fold(0u64, |mask, slot| mask | bit(*slot))
        };
        let rules = rule_set(
            rules
                .iter()
                .filter(|rule| rule.device_id.as_deref() == Some(device.id.as_str())),
        );
        let id = scopes.scope_id(all_mask, device.filtering, mask, &rules);
        by_ip.insert(
            ip,
            Scope {
                id,
                filtering: device.filtering,
                mask,
                rules: (!rules.is_empty()).then(|| Arc::new(rules)),
            },
        );
        device_names.insert(ip, Arc::from(device.name.as_str()));
    }

    let stats = PolicyStats {
        rules_loaded: index.len(),
        slots: slot_of.len(),
    };
    Built {
        policy: Policy::new(index, household, by_ip, all_mask, block_mode),
        device_names,
        stats,
    }
}

/// The mask bit for a slot.
const fn bit(slot: u8) -> u64 {
    match 1u64.checked_shl(slot as u32) {
        Some(bit) => bit,
        None => 0,
    }
}

/// Turn stored rows into a [`RuleSet`], skipping anything the schema should have refused.
fn rule_set<'a>(rules: impl Iterator<Item = &'a Rule>) -> RuleSet {
    let mut set = RuleSet::new();
    for rule in rules {
        let Ok(action) = Action::from_str(&rule.action) else {
            tracing::warn!(rule = rule.id, action = %rule.action, "unknown rule action; ignored");
            continue;
        };
        // Normalised again on the way out because the column predates the normaliser: a row
        // written by an older build, or by hand, must not become a rule that never matches.
        let domain = normalize_rule_domain(&rule.domain);
        if !domain.is_empty() {
            set.insert(&domain, action);
        }
    }
    set
}
