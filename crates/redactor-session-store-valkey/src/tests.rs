use std::time::{SystemTime, UNIX_EPOCH};

use redactor::{FindingKind, RedactionPolicy, RedactorBuilder, SessionStore, SessionStoreError};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

use crate::ValkeySessionStore;

const TEST_URL: &str = "redis://127.0.0.1:6379/0";
const PASSPHRASE: &str = "test-passphrase-with-at-least-32-bytes";

fn unique_namespace(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    format!("redactor:test:{name}:{nanos}:")
}

fn session(external_id: &str) -> redactor::RedactionSession {
    RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
        .build()
        .redact_artifact_with_prior_session(
            "host=private.example.com",
            redactor::InputKind::Text,
            None,
            Some(external_id),
        )
        .expect("session")
        .session
}

async fn store(namespace: &str) -> ValkeySessionStore {
    ValkeySessionStore::builder(TEST_URL, PASSPHRASE)
        .with_key_namespace(namespace)
        .build()
        .await
        .expect("store")
}

#[tokio::test]
async fn encrypted_round_trip_hides_plaintext_and_external_id() {
    let namespace = unique_namespace("encrypted");
    let store = store(&namespace).await;
    let external_id = "conversation-secret-id";
    let session = session(external_id);
    let version = store
        .save_latest(external_id, &session, None)
        .await
        .expect("save");
    let loaded = store
        .load_latest(external_id)
        .await
        .expect("load")
        .expect("stored");
    assert_eq!(loaded.session, session);
    assert_eq!(loaded.version, version);

    let digest = hex::encode(Sha256::digest(external_id.as_bytes()));
    let mut connection = redis::Client::open(TEST_URL)
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let value: String = connection
        .get(format!("{namespace}{digest}"))
        .await
        .expect("raw value");
    assert!(!value.contains("private.example.com"));
    assert!(!value.contains(external_id));
}

#[tokio::test]
async fn version_conflict_is_typed() {
    let namespace = unique_namespace("conflict");
    let store = store(&namespace).await;
    let session = session("conv-conflict");
    store
        .save_latest("conv-conflict", &session, None)
        .await
        .expect("first save");
    let error = store
        .save_latest("conv-conflict", &session, Some("0"))
        .await
        .expect_err("conflict");
    assert!(matches!(error, SessionStoreError::Conflict));
}

#[tokio::test]
async fn ttl_is_applied() {
    let namespace = unique_namespace("ttl");
    let store = ValkeySessionStore::builder(TEST_URL, PASSPHRASE)
        .with_key_namespace(&namespace)
        .with_ttl_seconds(120)
        .build()
        .await
        .expect("store");
    let external_id = "conv-ttl";
    store
        .save_latest(external_id, &session(external_id), None)
        .await
        .expect("save");
    let key = format!(
        "{namespace}{}",
        hex::encode(Sha256::digest(external_id.as_bytes()))
    );
    let mut connection = redis::Client::open(TEST_URL)
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let ttl: i64 = connection.ttl(key).await.expect("ttl");
    assert!(ttl > 0 && ttl <= 120);
}

#[tokio::test]
async fn legacy_plaintext_key_is_not_read() {
    let namespace = unique_namespace("legacy");
    let external_id = "conv-legacy";
    let mut connection = redis::Client::open(TEST_URL)
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let _: () = connection
        .set(
            format!("redactor:session:latest:{external_id}"),
            "plaintext",
        )
        .await
        .expect("legacy write");
    assert!(
        store(&namespace)
            .await
            .load_latest(external_id)
            .await
            .expect("load")
            .is_none()
    );
}
