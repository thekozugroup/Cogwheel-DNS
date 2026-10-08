//! The AI list: `ai_verdicts` (ADR 0002).
//!
//! Its own file for the reason `query_log.rs` has one: the table has a background write path (the
//! reviewer's settlements, a handful of rows at a time) and a retention policy, which the small
//! tables in `repo.rs` do not.
//!
//! `verdict`, `why`, `choice`, `effect` and `lists` are stored as the text the `CHECK` constraints
//! in `schema_v2.sql` allow; the server maps them to its own types, and SQLite, not code here,
//! refuses anything else. The one distinction this crate makes is the one retention needs:
//!
//! - A *decision* is policy: a block, an allow, or an ignore with `why = 'contested'` (two websites
//!   disagreed, so the lists decide on purpose). It lives up to 90 days, its websites scrubbed at
//!   `HISTORY_DAYS`.
//! - An *ordinary ignore* is every other ignore (the model agreed, was unsure, or hit a cap): a
//!   negative cache, so the name is not paid for again. It is also a record of a third-party name
//!   a household website loaded, which is browsing history, so it lives no longer than the query
//!   log and Clear log deletes it (§12).

use crate::repo::{collect, write_setting};
use crate::{Storage, StorageError};
use rusqlite::{Connection, params, params_from_iter};
use serde::Serialize;

/// Seconds per day, for the retention arithmetic.
const DAY: i64 = 86_400;

/// How long any row may live, decision or not (§6.11).
const MAX_AGE_DAYS: i64 = 90;

/// The most rows one page holds, whatever the caller asks for.
const PAGE_CAP: u32 = 500;

/// The `settings` key of the reviewer's daily spend, written only with the verdicts it paid for.
const AI_SPEND: &str = "ai_spend";

/// An ordinary ignore: the negative cache, and nothing else. `IS NOT` rather than `<>` so a row
/// with no `why` at all is ordinary too, and not silently kept as if it were a decision.
const ORDINARY_IGNORE: &str = "verdict = 'ignore' AND why IS NOT 'contested'";

/// The page filter, shared by the page and its total so the two cannot count different things.
const PAGE_FILTER: &str = "WHERE (?1 = 0 OR verdict IN ('block','allow'))
                             AND (?2 IS NULL OR verdict = ?2)
                             AND (?3 IS NULL OR instr(domain, ?3) > 0)";

/// One upsert per row. A fresh judgement replaces every column, `rechecks` included, so nothing
/// from the previous verdict survives into the new one. Columns in `AiVerdict` order, which is the
/// order `record_ai_verdicts` binds them in.
const UPSERT: &str = "INSERT INTO ai_verdicts (domain, verdict, why, choice, confidence, effect,
         effect_confidence, lists, site, conflict_site, rechecks, model, judged_at, review_after)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
     ON CONFLICT(domain) DO UPDATE SET verdict = excluded.verdict, why = excluded.why,
         choice = excluded.choice, confidence = excluded.confidence, effect = excluded.effect,
         effect_confidence = excluded.effect_confidence, lists = excluded.lists,
         site = excluded.site, conflict_site = excluded.conflict_site,
         rechecks = excluded.rechecks, model = excluded.model, judged_at = excluded.judged_at,
         review_after = excluded.review_after";

/// A cross-site re-check: only the columns it changes, and only while the row is still a block or
/// an allow. A row Forget or Clear deleted after the re-check read it stays deleted, and a website
/// Clear log scrubbed meanwhile stays scrubbed.
const RECHECK: &str = "UPDATE ai_verdicts SET verdict = ?2, why = ?3, conflict_site = ?4,
         rechecks = ?5, review_after = ?6
     WHERE domain = ?1 AND verdict IN ('block','allow')";

record! {
    /// One AI review verdict (ADR 0002). Strings, not policy types: storage is a leaf crate.
    #[derive(PartialEq)]
    AiVerdict from "ai_verdicts" {
        /// The exact name judged, in `normalize_domain` form. Never a suffix.
        domain: String,
        /// `block`, `allow` or `ignore`: what the AI list holds for the name.
        verdict: String,
        /// Why an `ignore` is one: `agrees`, `unsure`, `limit` or `contested`.
        why: Option<String>,
        /// The model's answer to the role question, before any bar or cap was applied.
        choice: String,
        confidence: Option<f64>,
        /// The answer to "if it stays blocked, does the site break?", when it was asked.
        effect: Option<String>,
        effect_confidence: Option<f64>,
        /// What the household's lists did with the name when it was judged.
        lists: String,
        /// The website the name was loaded with; `None` once scrubbed.
        site: Option<String>,
        /// The other website, for a contested row; scrubbed with `site`.
        conflict_site: Option<String>,
        /// How many times another website's load asked again; 0 on every fresh judgement.
        rechecks: i64,
        /// The dated model snapshot the response named.
        model: String,
        judged_at: i64,
        /// When the name is due to be judged again, or, for an ordinary ignore, pruned.
        review_after: i64,
    }
}

record! {
    /// What a policy compile reads of a block or an allow: the columns its bars judge, and none of
    /// the text a page or the reviewer needs. Every build reads all of them, so it reads no more.
    #[derive(PartialEq)]
    AiDecision from "ai_verdicts" {
        domain: String,
        /// `block` or `allow`.
        verdict: String,
        confidence: Option<f64>,
        effect: Option<String>,
        effect_confidence: Option<f64>,
    }
}

impl From<&AiVerdict> for AiDecision {
    fn from(row: &AiVerdict) -> Self {
        Self {
            domain: row.domain.clone(),
            verdict: row.verdict.clone(),
            confidence: row.confidence,
            effect: row.effect.clone(),
            effect_confidence: row.effect_confidence,
        }
    }
}

/// What `GET /api/v1/ai/verdicts` asks for. Every field but `limit` narrows.
#[derive(Debug, Clone, Default)]
pub struct AiVerdictFilter {
    /// Only the rows that change something: blocks and allows.
    pub changes_only: bool,
    /// Only rows with this verdict.
    pub verdict: Option<String>,
    /// Only domains containing this substring; matched case-insensitively.
    pub q: Option<String>,
    /// Page size, capped at 500. Zero returns no rows, though the counts are still filled in.
    pub limit: u32,
}

/// How many rows hold each verdict, applied or not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AiCounts {
    pub block: i64,
    pub allow: i64,
    pub ignore: i64,
}

/// One page of the AI list, most recently judged first.
#[derive(Debug, Clone, Serialize)]
pub struct AiVerdictPage {
    pub rows: Vec<AiVerdict>,
    /// Every row the filter matches, not only the ones on this page.
    pub total: i64,
    /// The whole table's counts, whatever the filter.
    pub counts: AiCounts,
}

/// What a prune deleted: every domain, so the reviewer's `known` map shrinks with the table, and how
/// many of them were decisions (block, allow, contested), so the installer runs only when one was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AiPruned {
    pub domains: Vec<String>,
    pub decisions: usize,
}

impl Storage {
    /// Every row, in domain order. The table is capped at 10,000 rows, which is what makes reading
    /// all of it for the reviewer's `known` map affordable.
    ///
    /// # Errors
    ///
    /// Every method here propagates SQLite failures as [`StorageError::Sqlite`].
    pub async fn list_ai_verdicts(&self) -> Result<Vec<AiVerdict>, StorageError> {
        self.with_connection(|connection| AiVerdict::all(connection, "ORDER BY domain", []))
            .await
    }

    /// The blocks and allows, in domain order, as a policy compile reads them. Every build reads
    /// this, so it leaves the ignores, most of a full table and never compiled, in the database:
    /// reading all 10,000 full rows per build is what grew RSS past ADR 0002's budget.
    pub async fn list_ai_decisions(&self) -> Result<Vec<AiDecision>, StorageError> {
        self.with_connection(|connection| {
            AiDecision::all(
                connection,
                "WHERE verdict IN ('block','allow') ORDER BY domain",
                [],
            )
        })
        .await
    }

    /// The row for one exact name, or `None` when it has never been judged (or was forgotten).
    pub async fn ai_verdict(&self, domain: String) -> Result<Option<AiVerdict>, StorageError> {
        self.with_connection(move |connection| {
            AiVerdict::one(connection, "WHERE domain = ?1", [domain])
        })
        .await
    }

    /// One page of the AI list, most recently judged first, with the filter's total and the whole
    /// table's counts.
    ///
    /// The three reads share the connection's lock, so the counts and the page describe the same
    /// table even while the reviewer is writing.
    pub async fn page_ai_verdicts(
        &self,
        filter: AiVerdictFilter,
    ) -> Result<AiVerdictPage, StorageError> {
        self.with_connection(move |connection| {
            // Domains are stored lower-cased, so lowering the needle is the whole of
            // case-insensitive matching, as in `query_page`.
            let needle = filter
                .q
                .as_deref()
                .map(str::to_lowercase)
                .filter(|needle| !needle.is_empty());
            let rows = AiVerdict::all(
                connection,
                &format!("{PAGE_FILTER} ORDER BY judged_at DESC, domain ASC LIMIT ?4"),
                params![
                    filter.changes_only,
                    filter.verdict,
                    needle,
                    filter.limit.min(PAGE_CAP)
                ],
            )?;
            let total = connection.query_row(
                &format!("SELECT COUNT(*) FROM ai_verdicts {PAGE_FILTER}"),
                params![filter.changes_only, filter.verdict, needle],
                |row| row.get(0),
            )?;
            Ok(AiVerdictPage {
                rows,
                total,
                counts: counts(connection)?,
            })
        })
        .await
    }

    /// How many rows hold each verdict, over the whole table, for the status route that has no page
    /// to read counts from.
    pub async fn ai_counts(&self) -> Result<AiCounts, StorageError> {
        self.with_connection(|connection| counts(connection)).await
    }

    /// Store a settlement: upsert each row by domain, then write `ai_spend`, in one transaction.
    ///
    /// One transaction because the spend is what stops the reviewer at the daily limit: a crash
    /// between the verdicts and the spend that paid for them would hand a crash-looping process a
    /// fresh budget on every boot. `rows` may be empty, and that is how a billed answer with
    /// nothing to store, an aborted request and a Test record what they cost.
    pub async fn record_ai_verdicts(
        &self,
        rows: Vec<AiVerdict>,
        ai_spend: String,
    ) -> Result<(), StorageError> {
        self.record_ai_settlement(rows, None, ai_spend)
            .await
            .map(|_| ())
    }

    /// [`Self::record_ai_verdicts`], and a cross-site re-check of a stored block or allow in the
    /// same transaction: `recheck` is the row as the re-check left it, of which only `verdict`,
    /// `why`, `conflict_site`, `rechecks` and `review_after` are written, and only if the stored
    /// row is still a block or an allow. Returns whether any row was written.
    pub async fn record_ai_settlement(
        &self,
        rows: Vec<AiVerdict>,
        recheck: Option<AiVerdict>,
        ai_spend: String,
    ) -> Result<bool, StorageError> {
        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;
            let mut changed = !rows.is_empty();
            {
                let mut upsert = transaction.prepare_cached(UPSERT)?;
                for row in &rows {
                    upsert.execute(params![
                        row.domain,
                        row.verdict,
                        row.why,
                        row.choice,
                        row.confidence,
                        row.effect,
                        row.effect_confidence,
                        row.lists,
                        row.site,
                        row.conflict_site,
                        row.rechecks,
                        row.model,
                        row.judged_at,
                        row.review_after
                    ])?;
                }
            }
            if let Some(row) = &recheck {
                changed |= transaction.execute(
                    RECHECK,
                    params![
                        row.domain,
                        row.verdict,
                        row.why,
                        row.conflict_site,
                        row.rechecks,
                        row.review_after
                    ],
                )? > 0;
            }
            write_setting(&transaction, AI_SPEND, Some(&ai_spend))?;
            transaction.commit()?;
            Ok(changed)
        })
        .await
    }

    /// Forget one name, returning the row that was removed, or `None` if there was none.
    ///
    /// One `DELETE … RETURNING` rather than a read and a delete, so the row that comes back is
    /// exactly the row that went.
    pub async fn delete_ai_verdict(
        &self,
        domain: String,
    ) -> Result<Option<AiVerdict>, StorageError> {
        self.with_connection(move |connection| {
            let gone = collect(
                connection,
                &format!(
                    "DELETE FROM ai_verdicts WHERE domain = ?1 RETURNING {}",
                    AiVerdict::COLUMNS
                ),
                [domain],
                AiVerdict::from_row,
            )?;
            Ok(gone.into_iter().next())
        })
        .await
    }

    /// Empty the AI list. Returns how many rows went.
    pub async fn clear_ai_verdicts(&self) -> Result<usize, StorageError> {
        self.with_connection(|connection| Ok(connection.execute("DELETE FROM ai_verdicts", [])?))
            .await
    }

    /// Forget which websites verdicts were judged for: those judged before `judged_before`, or
    /// every one on `None` (Clear log). Returns how many rows changed.
    ///
    /// The rows themselves stay; only the browsing history in them goes. Rows with nothing left to
    /// scrub are not rewritten, so the count is what actually changed.
    pub async fn scrub_ai_sites(&self, judged_before: Option<i64>) -> Result<usize, StorageError> {
        self.with_connection(move |connection| {
            Ok(connection.execute(
                "UPDATE ai_verdicts SET site = NULL, conflict_site = NULL
                 WHERE (?1 IS NULL OR judged_at < ?1)
                   AND (site IS NOT NULL OR conflict_site IS NOT NULL)",
                [judged_before],
            )?)
        })
        .await
    }

    /// Clear log's half of the AI list (§12): delete every ordinary ignore and return their names,
    /// so the reviewer forgets them too. Decisions stay.
    pub async fn forget_ai_negatives(&self) -> Result<Vec<String>, StorageError> {
        self.with_connection(|connection| {
            collect(
                connection,
                &format!("DELETE FROM ai_verdicts WHERE {ORDINARY_IGNORE} RETURNING domain"),
                [],
                |row| row.get(0),
            )
        })
        .await
    }

    /// Enforce the AI list's retention (§6.11, §12), in one transaction, returning every name it
    /// deleted.
    ///
    /// 1. Ordinary ignores past `review_after`, or judged `history_days` or more ago. The second
    ///    clause catches rows written before `HISTORY_DAYS` was lowered. `history_days == 0` takes
    ///    every ordinary ignore, which is what a zero means here; the server does not prune at all
    ///    then, because it clears the whole list at startup instead.
    /// 2. Contested rows past `review_after`.
    /// 3. Any row judged 90 days or more ago.
    /// 4. The oldest `judged_at` beyond `max_rows`, newest kept.
    ///
    /// Each step deletes rows the steps before it left, so no name is reported twice.
    pub async fn prune_ai_verdicts(
        &self,
        now: i64,
        history_days: u32,
        max_rows: u32,
    ) -> Result<AiPruned, StorageError> {
        self.with_connection(move |connection| {
            let history_cutoff = now.saturating_sub(i64::from(history_days).saturating_mul(DAY));
            let age_cutoff = now.saturating_sub(MAX_AGE_DAYS * DAY);
            // The four steps above, in order. In the last, `LIMIT -1 OFFSET n` is "everything after
            // the newest n" and selects nothing below the cap; the domain breaks ties so which of
            // two same-second rows goes is the same on every run.
            let steps = [
                (
                    format!("{ORDINARY_IGNORE} AND (review_after <= ?1 OR judged_at <= ?2)"),
                    vec![now, history_cutoff],
                ),
                (
                    "verdict = 'ignore' AND why = 'contested' AND review_after <= ?1".to_owned(),
                    vec![now],
                ),
                ("judged_at <= ?1".to_owned(), vec![age_cutoff]),
                (
                    "domain IN (SELECT domain FROM ai_verdicts
                                ORDER BY judged_at DESC, domain ASC LIMIT -1 OFFSET ?1)"
                        .to_owned(),
                    vec![i64::from(max_rows)],
                ),
            ];
            let transaction = connection.transaction()?;
            let mut pruned = AiPruned::default();
            for (condition, values) in steps {
                let gone = collect(
                    &transaction,
                    &format!(
                        "DELETE FROM ai_verdicts WHERE {condition} RETURNING domain, verdict, why"
                    ),
                    params_from_iter(values),
                    |row| Ok((row.get(0)?, row.get::<_, String>(1)?, row.get(2)?)),
                )?;
                for (domain, verdict, why) in gone {
                    pruned.decisions += usize::from(is_decision(&verdict, why));
                    pruned.domains.push(domain);
                }
            }
            transaction.commit()?;
            Ok(pruned)
        })
        .await
    }
}

/// The whole table's counts per verdict.
fn counts(connection: &Connection) -> Result<AiCounts, StorageError> {
    let grouped = collect(
        connection,
        "SELECT verdict, COUNT(*) FROM ai_verdicts GROUP BY verdict",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut counts = AiCounts::default();
    for (verdict, count) in grouped {
        // The column's CHECK admits these three and nothing else.
        match verdict.as_str() {
            "block" => counts.block = count,
            "allow" => counts.allow = count,
            "ignore" => counts.ignore = count,
            _ => {}
        }
    }
    Ok(counts)
}

/// A row that is policy rather than a negative cache: a block, an allow, or a contested ignore.
fn is_decision(verdict: &str, why: Option<String>) -> bool {
    verdict != "ignore" || why.as_deref() == Some("contested")
}
