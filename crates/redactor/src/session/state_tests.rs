use crate::{
    FindingKind, InputKind, RedactionArtifact, RedactionPolicy, RedactionSession, Redactor,
    RedactorBuilder, RestorePermit, RestoreState,
};

fn redactor() -> Redactor {
    RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
        .build()
}

fn first(external_id: Option<&str>) -> RedactionArtifact {
    redactor()
        .redact_artifact_with_input_kind_source_and_prior_session(
            "host=first.example.com",
            InputKind::Text,
            None,
            None,
            external_id,
        )
        .expect("first artifact")
}

fn next(prior: &RedactionSession, text: &str, external_id: Option<&str>) -> RedactionArtifact {
    redactor()
        .redact_artifact_with_input_kind_source_and_prior_session(
            text,
            InputKind::Text,
            None,
            Some(prior),
            external_id,
        )
        .expect("next artifact")
}

#[test]
fn single_round_authorizes_only_issued_tokens() {
    let old = first(Some("thread-a"));
    let latest = next(&old.session, "host=second.example.com", Some("thread-a"));
    let state = RestoreState::new(latest.session.clone()).expect("state");
    let text = format!(
        "{} {}",
        old.session.issued_tokens[0], latest.session.issued_tokens[0]
    );
    let result = state.restore_text(&text).expect("restore");

    assert!(state.has_authorized_tokens());
    assert_eq!(result.restored_count, 1);
    assert_eq!(result.skipped_tokens, old.session.issued_tokens);
}

#[test]
fn serde_round_trip_runs_normalization() {
    let artifact = first(Some("thread-a"));
    let state = RestoreState::new(artifact.session).expect("state");
    let json = serde_json::to_string(&state).expect("serialize");
    let decoded: RestoreState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, state);
}

#[test]
fn two_rounds_restore_old_and_new_tokens() {
    let old = first(Some("thread-a"));
    let state = RestoreState::new(old.session.clone()).expect("state");
    let latest = next(&old.session, "host=second.example.com", Some("thread-a"));
    let state = state.advance(latest.session.clone()).expect("advance");
    let text = format!(
        "{} {}",
        old.session.issued_tokens[0], latest.session.issued_tokens[0]
    );
    let result = state.restore_text(&text).expect("restore");

    assert_eq!(result.restored_text, "first.example.com second.example.com");
    assert_eq!(result.restored_count, 2);
    assert_eq!(permit_token_count(&state), 2);
}

#[test]
fn no_new_or_only_repeated_tokens_do_not_grow_permits() {
    let old = first(Some("thread-a"));
    let initial = RestoreState::new(old.session.clone()).expect("state");
    let no_tokens = next(&old.session, "plain text", Some("thread-a"));
    let no_tokens = initial.advance(no_tokens.session).expect("empty advance");
    assert_eq!(no_tokens.permits().len(), 1);

    let repeated = next(
        no_tokens.session(),
        "host=first.example.com",
        Some("thread-a"),
    );
    let repeated = no_tokens.advance(repeated.session).expect("repeat advance");
    assert_eq!(repeated.permits().len(), 1);
    assert_eq!(permit_token_count(&repeated), 1);
}

#[test]
fn repeated_rounds_keep_token_references_bounded() {
    let artifact = first(Some("thread-a"));
    let mut state = RestoreState::new(artifact.session).expect("state");
    for _ in 0..50 {
        let artifact = next(state.session(), "host=first.example.com", Some("thread-a"));
        state = state.advance(artifact.session).expect("advance");
    }
    assert_eq!(permit_token_count(&state), 1);
}

#[test]
fn advance_rejects_scope_external_id_and_mapping_changes() {
    let artifact = first(Some("thread-a"));
    let state = RestoreState::new(artifact.session.clone()).expect("state");

    let mut wrong_scope = artifact.session.clone();
    wrong_scope.scope_id = "other".to_string();
    assert!(state.advance(wrong_scope).is_err());

    let mut wrong_external = artifact.session.clone();
    wrong_external.external_id = Some("thread-b".to_string());
    assert!(state.advance(wrong_external).is_err());

    let mut changed = artifact.session;
    changed.entries[0].original = "changed.example.com".to_string();
    assert!(state.advance(changed).is_err());
}

#[test]
fn rejects_unknown_tokens_bad_permits_and_duplicate_permit_ids() {
    let artifact = first(Some("thread-a"));
    let session = artifact.session;
    let mut unknown_entry = session.clone();
    unknown_entry
        .issued_tokens
        .push("[[RDX:v2:unknown]]".to_string());
    assert!(RestoreState::new(unknown_entry).is_err());

    let valid_permit = permit(&session, "permit-a", vec![session.entries[0].token.clone()]);
    let mut bad_version = valid_permit.clone();
    bad_version.version = 99;
    assert!(RestoreState::from_parts(session.clone(), vec![bad_version]).is_err());
    assert!(
        RestoreState::from_parts(
            session.clone(),
            vec![valid_permit.clone(), valid_permit.clone()]
        )
        .is_err()
    );

    let unknown = permit(&session, "permit-b", vec!["unknown".to_string()]);
    assert!(RestoreState::from_parts(session, vec![unknown]).is_err());
}

#[test]
fn normalization_keeps_first_authorization_and_drops_empty_permits() {
    let artifact = first(Some("thread-a"));
    let session = artifact.session;
    let token = session.issued_tokens[0].clone();
    let permits = vec![
        permit(&session, "first", vec![token.clone(), token.clone()]),
        permit(&session, "empty", Vec::new()),
        permit(&session, "later", vec![token]),
    ];
    let state = RestoreState::from_parts(session, permits).expect("normalized state");
    assert_eq!(state.permits().len(), 1);
    assert_eq!(state.permits()[0].permit_id, "first");
    assert_eq!(state.permits()[0].issued_tokens.len(), 1);
}

#[test]
fn custom_deserialize_rejects_invalid_state() {
    let artifact = first(Some("thread-a"));
    let state = RestoreState::new(artifact.session).expect("state");
    let mut json = serde_json::to_value(state).expect("serialize");
    json["session"]["version"] = serde_json::json!(999);
    assert!(serde_json::from_value::<RestoreState>(json).is_err());
}

fn permit(session: &RedactionSession, id: &str, tokens: Vec<String>) -> RestorePermit {
    RestorePermit {
        version: 1,
        permit_id: id.to_string(),
        scope_id: session.scope_id.clone(),
        external_id: session.external_id.clone(),
        issued_tokens: tokens,
    }
}

fn permit_token_count(state: &RestoreState) -> usize {
    state
        .permits()
        .iter()
        .map(|permit| permit.issued_tokens.len())
        .sum()
}
