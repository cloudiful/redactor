use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use redactor::{RedactionSession, SessionStore, StoredSession};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
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

#[derive(Debug, Default, Clone)]
struct MemorySessionStore {
    sessions: Arc<Mutex<BTreeMap<String, StoredSession>>>,
}

impl SessionStore for MemorySessionStore {
    fn load_latest(&self, external_id: &str) -> anyhow::Result<Option<StoredSession>> {
        Ok(self
            .sessions
            .lock()
            .expect("lock")
            .get(external_id)
            .cloned())
    }

    fn save_latest(
        &self,
        external_id: &str,
        session: &RedactionSession,
        expected_version: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        let mut sessions = self.sessions.lock().expect("lock");
        let current = sessions.get(external_id).cloned();
        match (current.as_ref(), expected_version) {
            (None, None) => {}
            (Some(stored), Some(expected)) if stored.version.as_deref() == Some(expected) => {}
            _ => anyhow::bail!("version_conflict"),
        }
        let next_version = current
            .and_then(|stored| stored.version)
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value + 1)
            .unwrap_or(1)
            .to_string();
        sessions.insert(
            external_id.to_string(),
            StoredSession {
                session: session.clone(),
                version: Some(next_version.clone()),
            },
        );
        Ok(Some(next_version))
    }
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
                    r#"{"text":"host=service.example.com secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC","redaction":{"domain":true,"secret":true}}"#,
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
    assert!(redact_json.redacted_text.contains("[[RDX:v2:"));
    assert!(redact_json.redacted_text.contains(":DOMAIN:001:"));
    assert!(redact_json.redacted_text.contains(":SECRET:001:"));

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
async fn redact_text_leaves_domains_by_default() {
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
        .oneshot(
            Request::post("/redact/text")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"text":"host=service.example.com"}"#))
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
    assert!(redact_json.redacted_text.contains("service.example.com"));
    assert!(!redact_json.redacted_text.contains("[[RDX:v2:"));
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
                    r#"{{"text":{},"input_kind":"git_diff","redaction":{{"secret":true}}}}"#,
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
            .contains("+API_TOKEN=[[RDX:v2:")
    );
}

#[tokio::test]
async fn text_routes_support_external_id_with_store_provider() {
    let store = Arc::new(MemorySessionStore::default());
    let app = app(
        ProxyConfig::new(
            "127.0.0.1:0".to_string(),
            "https://openrouter.ai/api/v1".to_string(),
            None,
            None,
            "IGNORED".to_string(),
        )
        .with_session_passphrase("test-passphrase")
        .with_session_store(store),
    )
    .expect("app");

    let redact = app
        .clone()
        .oneshot(
            Request::post("/redact/text")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"text":"host=service.example.com","external_id":"conv-1","redaction":{"domain":true}}"#,
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

    let restore = app
        .oneshot(
            Request::post("/restore/text")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"text":{},"external_id":"conv-1"}}"#,
                    serde_json::to_string(&redact_json.redacted_text).expect("text json")
                )))
                .expect("request"),
        )
        .await
        .expect("restore response");
    assert_eq!(restore.status(), StatusCode::OK);
}

#[tokio::test]
async fn text_routes_reject_external_id_without_store_provider() {
    let app = app(
        ProxyConfig::new(
            "127.0.0.1:0".to_string(),
            "https://openrouter.ai/api/v1".to_string(),
            None,
            None,
            "IGNORED".to_string(),
        )
        .with_session_passphrase("test-passphrase"),
    )
    .expect("app");

    let restore = app
        .oneshot(
            Request::post("/restore/text")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"text":"foo","external_id":"conv-1"}"#))
                .expect("request"),
        )
        .await
        .expect("restore response");
    assert_eq!(restore.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
