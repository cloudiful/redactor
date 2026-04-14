use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde::Deserialize;
use tower::ServiceExt;

use crate::{ProxyConfig, app};

#[derive(Debug, Deserialize)]
struct TestRedactResponse {
    redacted_text: String,
    encrypted_session: String,
}

#[derive(Debug, Deserialize)]
struct TestRestoreResponse {
    restored_text: String,
}

#[tokio::test]
async fn text_routes_round_trip() {
    let app = app(ProxyConfig::new(
        "127.0.0.1:0".to_string(),
        "https://openrouter.ai/api/v1".to_string(),
        None,
        None,
        "IGNORED".to_string(),
    )
    .with_session_passphrase("test-passphrase"))
    .expect("app");

    let redact = app
        .clone()
        .oneshot(
            Request::post("/redact/text")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"text":"host=service.example.com secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("redact response");
    assert_eq!(redact.status(), StatusCode::OK);

    let redact_body = to_bytes(redact.into_body(), usize::MAX)
        .await
        .expect("redact body");
    let redact_json: TestRedactResponse =
        serde_json::from_slice(&redact_body).expect("redact json");
    assert!(redact_json.redacted_text.contains("__R_DOMAIN_001__"));
    assert!(redact_json.redacted_text.contains("__R_SECRET_001__"));

    let restore = app
        .clone()
        .oneshot(
            Request::post("/restore/text")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"text":"{}","encrypted_session":{}}}"#,
                    redact_json.redacted_text,
                    serde_json::to_string(&redact_json.encrypted_session).expect("session string")
                )))
                .expect("request"),
        )
        .await
        .expect("restore response");
    assert_eq!(restore.status(), StatusCode::OK);

    let restore_body = to_bytes(restore.into_body(), usize::MAX)
        .await
        .expect("restore body");
    let restore_json: TestRestoreResponse =
        serde_json::from_slice(&restore_body).expect("restore json");
    assert!(restore_json.restored_text.contains("service.example.com"));

    let inspect = app
        .oneshot(
            Request::post("/inspect/session")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"encrypted_session":{}}}"#,
                    serde_json::to_string(&redact_json.encrypted_session).expect("session string")
                )))
                .expect("request"),
        )
        .await
        .expect("inspect response");
    assert_eq!(inspect.status(), StatusCode::OK);
}

#[tokio::test]
async fn redact_text_accepts_git_diff_mode() {
    let app = app(ProxyConfig::new(
        "127.0.0.1:0".to_string(),
        "https://openrouter.ai/api/v1".to_string(),
        None,
        None,
        "IGNORED".to_string(),
    )
    .with_session_passphrase("test-passphrase"))
    .expect("app");
    let diff = concat!(
        "diff --git a/.env b/.env\n",
        "index 1111111..2222222 100644\n",
        "--- a/.env\n",
        "+++ b/.env\n",
        "@@ -1,1 +1,1 @@\n",
        "+API_TOKEN=sk_live_1234567890ABCDEFghij\n",
    );

    let redact = app
        .oneshot(
            Request::post("/redact/text")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"text":{},"input_kind":"git_diff"}}"#,
                    serde_json::to_string(diff).expect("diff json")
                )))
                .expect("request"),
        )
        .await
        .expect("redact response");
    assert_eq!(redact.status(), StatusCode::OK);

    let redact_body = to_bytes(redact.into_body(), usize::MAX)
        .await
        .expect("redact body");
    let redact_json: TestRedactResponse =
        serde_json::from_slice(&redact_body).expect("redact json");
    assert!(
        redact_json
            .redacted_text
            .contains("diff --git a/.env b/.env")
    );
    assert!(
        redact_json
            .redacted_text
            .contains("+API_TOKEN=__R_SECRET_001__")
    );
}
