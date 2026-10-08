//! `test_run.rs`: route 26's table, the charge for every billed answer, and the rate limit.

use super::stub::{Reply, Stub};
use super::{MODEL, env_key, fixture};
use crate::ai::{AiTestInput, State, apply_patch, run_test};
use crate::http::ApiError;
use crate::state::now_secs;
use axum::http::StatusCode;

fn patch(body: &str) -> crate::ai::AiPatch {
    serde_json::from_str(body).expect("a patch body")
}

fn refused(error: &ApiError, status: StatusCode, sentence: &str) {
    assert_eq!(
        (error.status(), error.to_string().as_str()),
        (status, sentence)
    );
}

const ANSWER: &str = r#"{"id":"gen-dec-1","model":"typesafe/jev-1.13-20260917","provider":"TypeSafe",
  "answers":{"role":{"type":"choice","choice":"block","confidence":0.91},
             "effect":{"type":"choice","choice":"works","confidence":0.94}},
  "usage":{"input_tokens":510,"output_tokens":70,"cost":0.0000213}}"#;

#[tokio::test]
async fn a_test_failure_passes_through_unchanged() {
    let cases = [
        (401, StatusCode::BAD_REQUEST, "OpenRouter refused the key."),
        (
            429,
            StatusCode::TOO_MANY_REQUESTS,
            "OpenRouter is rate-limiting this key; try again in a minute.",
        ),
        (
            503,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter did not answer; try again in a minute.",
        ),
        (
            402,
            StatusCode::CONFLICT,
            "The OpenRouter account or this key is out of credit.",
        ),
        (
            404,
            StatusCode::CONFLICT,
            "OpenRouter would not run this model: no provider meets the privacy and price limits, \
             or the model is gone. Pick another, or set COGWHEEL_AI__ZERO_RETENTION=false.",
        ),
        (
            400,
            StatusCode::CONFLICT,
            "That model cannot answer Cogwheel's questions; pick another.",
        ),
        (
            307,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter redirected the request; Cogwheel never follows a redirect with your key.",
        ),
    ];
    for (status, expected, sentence) in cases {
        for through_the_put in [false, true] {
            let stub = Stub::serve(vec![Reply::json(status, "{}")]);
            let base = stub.base.clone();
            let fixture = fixture(
                move |config| {
                    env_key(config);
                    config.ai_base_url = base;
                },
                &[MODEL],
            )
            .await;
            let error = if through_the_put {
                apply_patch(&fixture.state, patch(r#"{"enabled":true}"#))
                    .await
                    .expect_err("the Test failed")
            } else {
                run_test(&fixture.state, AiTestInput::default())
                    .await
                    .expect_err("the Test failed")
            };
            refused(&error, expected, sentence);
            assert_eq!(fixture.state.ai.state(), State::Off, "status {status}");
            assert_eq!(
                fixture
                    .state
                    .storage
                    .setting("ai_enabled")
                    .await
                    .expect("read"),
                None,
                "a failed Test turns nothing on"
            );
            assert_eq!(
                fixture.state.ai.today(now_secs()).requests,
                0,
                "an error is not billed"
            );
        }
    }
}

#[tokio::test]
async fn a_model_that_does_not_say_how_sure_it_is_fails_the_test() {
    let unrated = r#"{"answers":{"role":{"type":"choice","choice":"block"}},
                      "usage":{"input_tokens":500,"cost":0.00002}}"#;
    for (body, sentence, micro) in [
        (
            unrated,
            "That model does not say how sure it is; pick another.",
            20,
        ),
        // Unreadable: charged twice its reservation, since OpenRouter billed it.
        (
            "not json",
            "That model cannot answer Cogwheel's questions; pick another.",
            0,
        ),
    ] {
        let stub = Stub::serve(vec![Reply::json(200, body)]);
        let base = stub.base.clone();
        let fixture = fixture(
            move |config| {
                env_key(config);
                config.ai_base_url = base;
            },
            &[MODEL],
        )
        .await;
        let ai = &fixture.state.ai;
        let error = run_test(&fixture.state, AiTestInput::default())
            .await
            .expect_err("fails the Test");
        refused(&error, StatusCode::CONFLICT, sentence);
        assert_eq!(ai.tested("typesafe/jev-1.13"), Some(false));
        let today = ai.today(now_secs());
        assert_eq!(
            today.requests, 1,
            "a billed answer is charged however it reads"
        );
        if micro > 0 {
            assert_eq!(today.micro_usd, micro);
        } else {
            assert!(today.micro_usd > 0, "never free");
        }
        assert!(
            fixture
                .state
                .storage
                .setting("ai_spend")
                .await
                .expect("read")
                .is_some(),
            "and the charge is stored"
        );
    }
}

#[tokio::test]
async fn a_passing_test_ends_a_terminal_state_and_tests_are_rate_limited() {
    let stub = Stub::serve(vec![Reply::json(200, ANSWER)]);
    let base = stub.base.clone();
    let fixture = fixture(
        move |config| {
            env_key(config);
            config.ai_base_url = base;
        },
        &[("ai_enabled", "1"), MODEL],
    )
    .await;
    let ai = &fixture.state.ai;
    ai.halt(crate::ai::Halt::KeyRefused);
    assert_eq!(ai.state(), State::KeyRefused);

    let result = run_test(&fixture.state, AiTestInput::default())
        .await
        .expect("the Test passes");
    assert!(result.ok);
    assert_eq!(result.model, "typesafe/jev-1.13-20260917");
    assert_eq!(result.answer.choice, "block");
    assert_eq!(result.cost_usd, 0.0000213);
    assert!(
        result.sentence.contains(
            "through TypeSafe: www.googletagmanager.com is not needed by www.wikipedia.org \
             (the model was 91% sure). The test cost $0.00002."
        ),
        "{}",
        result.sentence
    );
    assert_eq!(ai.state(), State::Reviewing, "the pass ended key_refused");

    let error = run_test(&fixture.state, AiTestInput::default())
        .await
        .expect_err("a second Test inside ten seconds");
    assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        error
            .to_string()
            .starts_with("Tested a moment ago; try again in ")
    );
    assert_eq!(stub.requests().len(), 1);
}
