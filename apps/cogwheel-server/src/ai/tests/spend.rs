//! `spend.rs` and `settings.rs`: pricing, settling, the stored spend, and the settings' shapes.

use super::{config, load, storage, verdict};
use crate::ai::prompt::Usage;
use crate::ai::settings::{AiPatch, AiTestInput, Settings, cents, model_shaped, spell_cents};
use crate::ai::spend::{Cost, Spend, charge_micro, reserve_micro, utc_day};
use crate::state::now_secs;
use std::sync::Arc;

#[test]
fn spend_round_trips_and_rolls_over_at_utc_midnight() {
    let spend = Spend {
        day: 20_736,
        micro_usd: 31_200,
        requests: 412,
        overrides: 2,
    };
    assert_eq!(spend.encode(), "20736 31200 412 2");
    assert_eq!(Spend::decode(Some(&spend.encode())), spend);
    for garbage in [
        None,
        Some(""),
        Some("1 2 3"),
        Some("a b c d"),
        Some("-1 2 3 4"),
    ] {
        assert_eq!(Spend::decode(garbage), Spend::default(), "{garbage:?}");
    }

    let mut rolled = spend;
    rolled.roll_over(20_736);
    assert_eq!(rolled, spend, "same day, same counts");
    rolled.roll_over(20_737);
    assert_eq!(
        rolled,
        Spend {
            day: 20_737,
            ..Spend::default()
        }
    );
    rolled.add(Cost {
        micro_usd: u64::MAX,
        requests: 1,
        overrides: 1,
    });
    rolled.add(Cost::request(5));
    assert_eq!(rolled.micro_usd, u64::MAX, "saturates rather than wraps");
    assert_eq!((rolled.requests, rolled.overrides), (2, 1));

    // 00:00 UTC is the boundary, whatever the local zone.
    assert_eq!(utc_day(86_399), 0);
    assert_eq!(utc_day(86_400), 1);
    assert_eq!(utc_day(-1), 0, "a clock before 1970 is day 0, not a panic");
}

#[test]
fn spend_is_reserved_then_settled_and_never_free() {
    // (3,000 / 3 + 64) tokens at Jev's $0.042/M × 1.25.
    assert_eq!(reserve_micro(3_000, Some(0.042)), 56);
    // An unknown price is budgeted at $1 per million tokens.
    assert_eq!(reserve_micro(3_000, None), 1_064);
    // A free model still reserves something while the request is in flight.
    assert_eq!(reserve_micro(0, Some(0.0)), 1);

    let reserve = 56;
    let priced = Usage {
        input_tokens: Some(476),
        cost: Some(0.000_019_992),
    };
    assert_eq!(
        charge_micro(Some(&priced), reserve, Some(0.042)),
        (20, false)
    );
    // No cost: the input tokens at the ceiling, flagged as an estimate.
    let unpriced = Usage {
        input_tokens: Some(1_000),
        cost: None,
    };
    assert_eq!(
        charge_micro(Some(&unpriced), reserve, Some(0.042)),
        (53, true)
    );
    assert_eq!(charge_micro(Some(&unpriced), reserve, None), (1_000, true));
    // Nothing readable at all: twice the reservation.
    let blank = Usage::default();
    assert_eq!(
        charge_micro(Some(&blank), reserve, Some(0.042)),
        (112, true)
    );
    assert_eq!(charge_micro(None, reserve, Some(0.042)), (112, true));
    // OpenRouter saying it cost nothing is a cost of nothing, and not an estimate.
    let free = Usage {
        input_tokens: Some(500),
        cost: Some(0.0),
    };
    assert_eq!(charge_micro(Some(&free), reserve, None), (0, false));
}

#[tokio::test]
async fn settling_writes_the_spend_with_the_rows_and_survives_a_restart() {
    let storage = storage().await;
    let (ai, _rx) = load(&config(), &storage).await;
    let now = now_secs();
    let today = utc_day(now);

    ai.settle(
        &storage,
        now,
        Cost::request(56),
        vec![verdict("ads.example.net", "block", now)],
    )
    .await
    .expect("settled with a row");
    // A billed response with nothing to store, and an aborted request: spend, no rows.
    ai.settle(&storage, now, Cost::request(112), Vec::new())
        .await
        .expect("settled without rows");
    ai.settle(
        &storage,
        now,
        Cost {
            micro_usd: 0,
            requests: 0,
            overrides: 1,
        },
        Vec::new(),
    )
    .await
    .expect("an override counted");

    let expected = Cost {
        micro_usd: 168,
        requests: 2,
        overrides: 1,
    };
    assert_eq!(ai.today(now), expected);
    assert_eq!(
        ai.today(now + 86_400),
        Cost::default(),
        "tomorrow starts at zero"
    );
    assert_eq!(
        storage.setting("ai_spend").await.expect("read").as_deref(),
        Some(format!("{today} 168 2 1").as_str())
    );
    assert_eq!(storage.list_ai_verdicts().await.expect("read").len(), 1);

    // A restart reads the same day back: the budget does not reset by crashing.
    let (restarted, _rx) = load(&config(), &storage).await;
    assert_eq!(restarted.today(now), expected);
}

#[tokio::test]
async fn concurrent_settlements_never_store_an_older_total() {
    let storage = storage().await;
    let (ai, _rx) = load(&config(), &storage).await;
    let mut settling = tokio::task::JoinSet::new();
    for micro in 1..=40u64 {
        let ai = Arc::clone(&ai);
        let storage = storage.clone();
        settling.spawn(async move {
            ai.settle(&storage, now_secs(), Cost::request(micro), Vec::new())
                .await
        });
    }
    while let Some(done) = settling.join_next().await {
        done.expect("joined").expect("settled");
    }
    let total = ai.today(now_secs());
    assert_eq!(total.micro_usd, (1..=40).sum::<u64>());
    assert_eq!(total.requests, 40);
    assert_eq!(
        storage.setting("ai_spend").await.expect("read"),
        Some(format!("{} {} 40 0", utc_day(now_secs()), total.micro_usd)),
        "the stored figure is the last one made, never an older snapshot"
    );
}

#[test]
fn model_ids_and_daily_limits_are_checked() {
    for good in [
        "typesafe/jev-1.13",
        "~typesafe/jev-latest",
        "inception/mercury-decide:free",
        "togethercomputer/tev1-4b-experimental",
        "liquid/d1",
    ] {
        assert!(model_shaped(good), "{good}");
    }
    for bad in [
        "",
        "jev",
        "TypeSafe/jev",
        "typesafe/",
        "/jev",
        "-typesafe/jev",
        "typesafe/jev/1",
        "typesafe/jev 1",
        "type:safe/jev",
        "~~typesafe/jev",
        &format!("typesafe/{}", "j".repeat(120)),
    ] {
        assert!(!model_shaped(bad), "{bad}");
    }

    assert_eq!(cents(0.05), Some(5));
    assert_eq!(cents(0.1), Some(10));
    assert_eq!(cents(0.10), Some(10));
    assert_eq!(cents(0.25), Some(25));
    assert_eq!(cents(1.0), Some(100));
    for refused in [0.0, 0.07, 0.5, 2.0, -0.05, 0.051, f64::NAN, f64::INFINITY] {
        assert_eq!(cents(refused), None, "{refused}");
    }
    assert_eq!(
        [5, 10, 25, 100].map(spell_cents),
        ["0.05", "0.10", "0.25", "1.00"]
    );
}

#[tokio::test]
async fn the_settings_read_back_what_was_stored_and_ignore_the_rest() {
    let storage = storage().await;
    let defaults = Settings::load(&storage).await.expect("read");
    assert_eq!(
        defaults,
        Settings {
            enabled: false,
            model: None,
            model_price: None,
            daily_limit_cents: 10,
        }
    );
    for (key, value) in [
        ("ai_enabled", "1"),
        ("ai_model", "typesafe/jev-1.13"),
        ("ai_model_price", "0.042"),
        ("ai_daily_limit", "0.25"),
    ] {
        storage
            .set_setting(key, Some(value.to_owned()))
            .await
            .expect("store");
    }
    assert_eq!(
        Settings::load(&storage).await.expect("read"),
        Settings {
            enabled: true,
            model: Some("typesafe/jev-1.13".to_owned()),
            model_price: Some(0.042),
            daily_limit_cents: 25,
        }
    );
    for (key, value) in [
        ("ai_enabled", "yes"),
        ("ai_model", "not a model"),
        ("ai_model_price", "-1"),
        ("ai_daily_limit", "0.07"),
    ] {
        storage
            .set_setting(key, Some(value.to_owned()))
            .await
            .expect("store");
    }
    assert_eq!(Settings::load(&storage).await.expect("read"), defaults);
}

#[test]
fn the_patch_tells_absent_null_and_a_key_apart_and_never_prints_one() {
    let read = |body: &str| serde_json::from_str::<AiPatch>(body).expect("a patch");
    assert_eq!(read("{}").key, None, "absent keeps the key");
    assert_eq!(read(r#"{"key":null}"#).key, Some(None), "null removes it");
    assert_eq!(
        read(r#"{"key":"sk-or-v1-secret-value-0123"}"#).key,
        Some(Some("sk-or-v1-secret-value-0123".to_owned()))
    );
    let patch = read(
        r#"{"enabled":true,"model":"typesafe/jev-1.13","key":"sk-or-v1-secret-value-0123","daily_limit_usd":0.25}"#,
    );
    assert_eq!(patch.enabled, Some(true));
    assert_eq!(patch.daily_limit_usd, Some(0.25));
    let printed = format!("{patch:?}");
    assert!(!printed.contains("secret"), "{printed}");
    assert!(printed.contains("typesafe/jev-1.13"));
    assert!(serde_json::from_str::<AiPatch>(r#"{"key":7}"#).is_err());
    assert!(serde_json::from_str::<AiPatch>(r#"{"enabled":"yes"}"#).is_err());

    let staged: AiTestInput =
        serde_json::from_str(r#"{"key":"sk-or-v1-secret-value-0123"}"#).expect("an input");
    assert!(!format!("{staged:?}").contains("secret"));
    let empty: AiTestInput = serde_json::from_str("{}").expect("an input");
    assert!(empty.key.is_none() && empty.model.is_none());
}
