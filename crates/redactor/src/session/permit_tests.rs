use crate::{
    FindingKind, RedactionPolicy, RedactorBuilder, RestoreContext, create_restore_permit,
    decrypt_restore_permit, encrypt_restore_permit,
};

fn artifact(external_id: Option<&str>) -> crate::RedactionArtifact {
    RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
        .build()
        .redact_artifact_with_input_kind_source_and_prior_session(
            "host=private.example.com",
            crate::InputKind::Text,
            None,
            None,
            external_id,
        )
        .expect("artifact")
}

#[test]
fn encrypted_permit_round_trips_and_rejects_tampering() {
    let permit = create_restore_permit(&artifact(None).session);
    let encrypted = encrypt_restore_permit(&permit, "permit-passphrase").expect("encrypt");
    assert_eq!(
        decrypt_restore_permit(&encrypted, "permit-passphrase").expect("decrypt"),
        permit
    );
    let mut value: serde_json::Value = serde_json::from_str(&encrypted).expect("json");
    value["ciphertext_b64"] = serde_json::Value::String("AAAA".to_string());
    assert!(decrypt_restore_permit(&value.to_string(), "permit-passphrase").is_err());
}

#[test]
fn copied_token_is_skipped_without_its_operation_permit() {
    let owned = artifact(Some("thread-a"));
    let copied = owned.session.entries[0].token.clone();
    let empty = crate::RestorePermit {
        version: 1,
        permit_id: "empty".to_string(),
        scope_id: owned.session.scope_id.clone(),
        external_id: owned.session.external_id.clone(),
        issued_tokens: Vec::new(),
    };
    let result = RestoreContext::with_permits(&owned.session, &[empty])
        .expect("context")
        .restore_text(&format!("log={copied}"));
    assert!(result.is_valid());
    assert_eq!(result.restored_count, 0);
    assert_eq!(result.skipped_tokens, vec![copied]);
}

#[test]
fn multiple_permits_union_authorized_tokens() {
    let first = artifact(Some("thread-a"));
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
        .build();
    let second = redactor
        .redact_artifact_with_prior_session(
            "backup=second.example.com",
            crate::InputKind::Text,
            Some(&first.session),
            Some("thread-a"),
        )
        .expect("second");
    let permits = [
        create_restore_permit(&first.session),
        create_restore_permit(&second.session),
    ];
    let text = format!(
        "{} {}",
        first.session.issued_tokens[0], second.session.issued_tokens[0]
    );
    let result = RestoreContext::with_permits(&second.session, &permits)
        .expect("context")
        .restore_text(&text);
    assert!(result.is_valid());
    assert_eq!(result.restored_count, 2);
}

#[test]
fn permit_from_other_external_id_is_rejected() {
    let session = artifact(Some("thread-a"));
    let permit = create_restore_permit(&artifact(Some("thread-b")).session);
    assert!(RestoreContext::with_permits(&session.session, &[permit]).is_err());
}
