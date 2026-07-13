use crate::{
    FindingKind, InputKind, RedactionArtifact, RedactionPolicy, RedactionSession, Redactor,
    RedactorBuilder, RestoreState, StreamingRestoreContext,
};

fn redactor() -> Redactor {
    RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Domain, true))
        .build()
}

fn artifact(text: &str, prior: Option<&RedactionSession>) -> RedactionArtifact {
    redactor()
        .redact_artifact_with_input_kind_source_and_prior_session(
            text,
            InputKind::Text,
            None,
            prior,
            Some("thread-a"),
        )
        .expect("artifact")
}

#[test]
fn valid_token_restores_at_every_ascii_split_boundary() {
    let artifact = artifact("host=first.example.com", None);
    let token = artifact.session.issued_tokens[0].clone();
    for split in 0..=token.len() {
        let mut stream = StreamingRestoreContext::new(&artifact.session);
        let left = stream.push_str(&token[..split]);
        let right = stream.push_str(&token[split..]);
        let end = stream.finish();
        assert_eq!(
            format!(
                "{}{}{}",
                left.restored_text, right.restored_text, end.restored_text
            ),
            "first.example.com",
            "split {split}"
        );
        assert_eq!(left.restored_count + right.restored_count, 1);
        assert!(end.is_valid());
    }
}

#[test]
fn handles_many_fragments_split_marker_suffix_adjacent_and_repeated_tokens() {
    let artifact = artifact("host=first.example.com", None);
    let token = artifact.session.issued_tokens[0].clone();
    let input = format!("a{token}{token}z");
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    let mut output = String::new();
    let mut restored = 0;
    for fragment in input.as_bytes().chunks(1) {
        let part = stream.push_str(std::str::from_utf8(fragment).expect("ASCII"));
        output.push_str(&part.restored_text);
        restored += part.restored_count;
    }
    output.push_str(&stream.finish().restored_text);
    assert_eq!(output, "afirst.example.comfirst.example.comz");
    assert_eq!(restored, 2);
}

#[test]
fn preserves_unicode_around_token() {
    let artifact = artifact("host=first.example.com", None);
    let token = &artifact.session.issued_tokens[0];
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    let result = stream.push_str(&format!("前{token}后"));
    assert_eq!(result.restored_text, "前first.example.com后");
    assert!(stream.finish().restored_text.is_empty());
}

#[test]
fn valid_unauthorized_token_is_skipped() {
    let old = artifact("host=first.example.com", None);
    let latest = artifact("host=second.example.com", Some(&old.session));
    let state = RestoreState::new(latest.session).expect("state");
    let token = old.session.issued_tokens[0].clone();
    let mut stream = state.streaming_restore_context().expect("stream");
    let result = stream.push_str(&token);
    assert!(result.is_valid());
    assert_eq!(result.restored_text, token);
    assert_eq!(result.skipped_tokens, vec![token]);
}

#[test]
fn malformed_checksum_and_unknown_kind_are_reported_once() {
    let artifact = artifact("host=first.example.com", None);
    let token = &artifact.session.issued_tokens[0];
    let malformed = token.replacen(&token[token.len() - 10..token.len() - 2], "00000000", 1);
    let unknown_kind = token.replacen(":DOMAIN:", ":UNKNOWN:", 1);
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    let result = stream.push_str(&format!("{malformed}{unknown_kind}"));
    assert_eq!(result.restored_text, format!("{malformed}{unknown_kind}"));
    assert_eq!(result.unresolved_tokens.len(), 2);
    assert_eq!(result.validation_errors.len(), 2);
    assert!(stream.finish().validation_errors.is_empty());
}

#[test]
fn finish_flushes_short_prefix_and_reports_open_token() {
    let artifact = artifact("host=first.example.com", None);
    for prefix in ["[", "[[", "[[RDX", "[[RDX:v2"] {
        let mut stream = StreamingRestoreContext::new(&artifact.session);
        assert!(stream.push_str(prefix).restored_text.is_empty());
        let end = stream.finish();
        assert_eq!(end.restored_text, prefix);
        assert!(end.is_valid());
    }

    let truncated = "[[RDX:v2:open";
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    assert!(stream.push_str(truncated).restored_text.is_empty());
    let end = stream.finish();
    assert_eq!(end.restored_text, truncated);
    assert_eq!(end.unresolved_tokens, vec![truncated]);
    assert_eq!(end.validation_errors.len(), 1);
}

#[test]
fn pending_limit_flushes_candidate_then_continues_without_loss() {
    let artifact = artifact("host=first.example.com", None);
    let input = format!("[[RDX:v2:{}tail", "x".repeat(5000));
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    let pushed = stream.push_str(&input);
    let finished = stream.finish();
    assert_eq!(
        format!("{}{}", pushed.restored_text, finished.restored_text),
        input
    );
    assert_eq!(pushed.validation_errors.len(), 1);
    assert_eq!(pushed.unresolved_tokens.len(), 1);
    assert!(finished.validation_errors.is_empty());
}

#[test]
fn each_result_contains_only_new_output_and_diagnostics() {
    let artifact = artifact("host=first.example.com", None);
    let token = &artifact.session.issued_tokens[0];
    let split = token.len() - 1;
    let mut stream = StreamingRestoreContext::new(&artifact.session);
    let first = stream.push_str(&format!("prefix{}", &token[..split]));
    assert_eq!(first.restored_text, "prefix");
    assert_eq!(first.restored_count, 0);
    let second = stream.push_str(&token[split..]);
    assert_eq!(second.restored_text, "first.example.com");
    assert_eq!(second.restored_count, 1);
    let end = stream.finish();
    assert!(end.restored_text.is_empty());
    assert_eq!(end.restored_count, 0);
}
