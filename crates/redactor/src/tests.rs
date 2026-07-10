use crate::{
    CustomFileRule, CustomStringMatch, CustomStringRule, CustomStringScope, FindingKind, InputKind,
    RedactionPolicy, Redactor, RedactorBuilder, SessionStore, StoredSession,
    decrypt_session_from_str, encrypt_session_to_string, redact_text_artifact_with_stateful_session,
    restore_text_from_store,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn domain_redactor() -> Redactor {
    RedactorBuilder::new()
        .with_redaction_policy(
            RedactionPolicy::default()
                .with_kind(FindingKind::Domain, true)
                .with_kind(FindingKind::Secret, true)
                .with_kind(FindingKind::Url, true)
                .with_kind(FindingKind::Cidr, true),
        )
        .build()
}

const SAMPLE: &str = r#"  nctalk:
    image: registry.example.com/ghcr/example-releases/aio-talk
    container_name: nctalk
    networks:
      - internal
    ports:
      - 3478:3478/tcp
      - 3478:3478/udp
    environment:
      - NC_DOMAIN=chat.example.com
      - TALK_HOST=turn.example.net
      - TURN_SECRET=EJ2QEVC6AKELW0k2kkVY4NgGKONC
      - SIGNALING_SECRET=W1DDPgM3ymrHuGMDev6N4pW9Re96
      - TZ=UTC
      - TALK_PORT=3478
      - INTERNAL_SECRET=ulDo3hHfxb6tS1z02RdZmf6bAD2w
      - IPv4_ADDRESS_TALK=192.0.2.0/24
    restart: unless-stopped
    depends_on:
      - nextcloud
"#;

#[test]
fn redacts_sample_with_structured_tokens() {
    let result = domain_redactor().redact(SAMPLE).expect("redact sample");

    assert!(result.redacted_text.contains("[[RDX:v2:"));
    assert!(result.redacted_text.contains(":DOMAIN:001:"));
    assert!(result.redacted_text.contains(":DOMAIN:002:"));
    assert!(result.redacted_text.contains(":SECRET:001:"));
    assert!(result.redacted_text.contains(":SECRET:002:"));
    assert!(result.redacted_text.contains(":SECRET:003:"));
    assert!(result.redacted_text.contains(":CIDR:001:"));
    assert!(!result.redacted_text.contains("chat.example.com"));
    assert_eq!(SAMPLE.lines().count(), result.redacted_text.lines().count());
}

#[test]
fn session_round_trip_restores_original_text() {
    let redactor = domain_redactor();
    let session = redactor.redact_with_session(SAMPLE).expect("session");
    let restored = redactor.restore_text(&session.redacted_text, &session);

    assert!(restored.is_valid());
    assert_eq!(restored.restored_text, SAMPLE);
    assert!(restored.restored_count >= 6);
}

#[test]
fn restore_patch_keeps_copied_tokens_restorable() {
    let redactor = domain_redactor();
    let session = redactor.redact_with_session(SAMPLE).expect("session");
    let domain_token = session
        .entries
        .iter()
        .find(|entry| matches!(entry.kind, crate::FindingKind::Domain))
        .map(|entry| entry.token.clone())
        .expect("domain token");
    let patch = format!(
        "--- a/demo.txt\n+++ b/demo.txt\n@@ -1,1 +1,2 @@\n-const host = \"{}\";\n+const host = \"{}\";\n+const backup = \"{}\";\n",
        domain_token, domain_token, domain_token
    );

    let restored = redactor.restore_patch(&patch, &session);

    assert!(restored.is_valid());
    assert!(restored.restored_text.contains("chat.example.com"));
}

#[test]
fn altered_token_fails_strict_restore() {
    let redactor = domain_redactor();
    let session = redactor.redact_with_session(SAMPLE).expect("session");
    let edited = session.redacted_text.replacen("]]", "_X]]", 1);

    let restored = redactor.restore_text(&edited, &session);

    assert!(!restored.is_valid());
    assert!(!restored.validation_errors.is_empty());
}

#[test]
fn encrypted_session_round_trip_restores_session() {
    let redactor = domain_redactor();
    let session = redactor.redact_with_session(SAMPLE).expect("session");
    let encrypted = encrypt_session_to_string(&session, "passphrase").expect("encrypt");
    let decrypted = decrypt_session_from_str(&encrypted, "passphrase").expect("decrypt");

    assert_eq!(decrypted.session_id, session.session_id);
    assert_eq!(decrypted.scope_id, session.scope_id);
    assert_eq!(decrypted.redacted_text, session.redacted_text);
    assert_eq!(decrypted.entries.len(), session.entries.len());
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
        session: &crate::RedactionSession,
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

#[test]
fn stateful_sessions_reuse_tokens_for_same_external_id() {
    let redactor = domain_redactor();
    let store = MemorySessionStore::default();
    let first = redact_text_artifact_with_stateful_session(
        &redactor,
        "host=service.example.com",
        InputKind::Text,
        "conv-1",
        &store,
    )
    .expect("first artifact");
    let second = redact_text_artifact_with_stateful_session(
        &redactor,
        "backup=service.example.com",
        InputKind::Text,
        "conv-1",
        &store,
    )
    .expect("second artifact");

    assert_eq!(first.session.external_id.as_deref(), Some("conv-1"));
    assert_eq!(first.session.scope_id, second.session.scope_id);
    assert_eq!(
        first.session.entries[0].token,
        second.session.entries[0].token
    );
}

#[test]
fn session_redactor_accumulates_fragments_and_finishes_once() {
    let policy = RedactionPolicy::default().with_kind(FindingKind::Domain, true);
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(policy.clone())
        .build();
    let mut processor = crate::SessionRedactor::new();

    let first = processor
        .redact_fragment(&redactor, "first.example.com")
        .expect("first");
    let repeated = processor
        .redact_fragment_with_input_kind(
            &redactor,
            "first.example.com second.example.com",
            InputKind::Text,
        )
        .expect("second");
    let session = processor.finish_session(
        "first.example.com\nfirst.example.com second.example.com",
        &format!("{first}\n{repeated}"),
        &policy,
    );

    assert!(processor.has_applied_replacements());
    assert_eq!(session.entries.len(), 2);
    assert!(repeated.contains(&session.entries[0].token));
}

#[test]
fn session_redactor_imports_prior_session_once() {
    let policy = RedactionPolicy::default().with_kind(FindingKind::Domain, true);
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(policy.clone())
        .build();
    let prior = redactor
        .redact_with_session("first.example.com")
        .expect("prior");
    let mut processor =
        crate::SessionRedactor::with_prior_session(Some(&prior), None).expect("session processor");

    let redacted = processor
        .redact_fragment(&redactor, "first.example.com second.example.com")
        .expect("redact");
    let session =
        processor.finish_session("first.example.com second.example.com", &redacted, &policy);

    assert_eq!(session.scope_id, prior.scope_id);
    assert_eq!(session.entries.len(), 2);
    assert!(redacted.contains(&prior.entries[0].token));
}

#[test]
fn stateful_sessions_do_not_share_scope_between_external_ids() {
    let redactor = domain_redactor();
    let store = MemorySessionStore::default();
    let left = redact_text_artifact_with_stateful_session(
        &redactor,
        "host=service.example.com",
        InputKind::Text,
        "conv-left",
        &store,
    )
    .expect("left artifact");
    let right = redact_text_artifact_with_stateful_session(
        &redactor,
        "host=service.example.com",
        InputKind::Text,
        "conv-right",
        &store,
    )
    .expect("right artifact");

    assert_ne!(left.session.scope_id, right.session.scope_id);
    assert_ne!(left.session.entries[0].token, right.session.entries[0].token);
}

#[test]
fn stateful_restore_uses_latest_snapshot() {
    let redactor = domain_redactor();
    let store = MemorySessionStore::default();
    let artifact = redact_text_artifact_with_stateful_session(
        &redactor,
        "host=service.example.com secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC",
        InputKind::Text,
        "conv-restore",
        &store,
    )
    .expect("artifact");

    let restored = restore_text_from_store(&redactor, &artifact.result.redacted_text, "conv-restore", &store)
        .expect("restore");
    assert!(restored.is_valid());
    assert_eq!(
        restored.restored_text,
        "host=service.example.com secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC"
    );
}

#[test]
fn person_detection_is_disabled_by_default() {
    let text = "name: Build crate matrix\n";
    let findings = RedactorBuilder::new().build().detect(text).expect("detect");

    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != crate::FindingKind::Person)
    );
}

#[test]
fn person_detection_can_be_enabled_explicitly() {
    let text = "name: Jane Doe\n";
    let findings = RedactorBuilder::new()
        .with_redaction_policy(RedactionPolicy::default().with_kind(FindingKind::Person, true))
        .build()
        .detect(text)
        .expect("detect");

    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == crate::FindingKind::Person)
    );
}

#[test]
fn domain_detection_is_disabled_by_default() {
    let findings = RedactorBuilder::new()
        .build()
        .detect("host=service.example.com")
        .expect("detect");

    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != FindingKind::Domain)
    );
}

#[test]
fn domain_detection_can_be_enabled_explicitly() {
    let findings = domain_redactor()
        .detect("host=service.example.com")
        .expect("detect");

    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Domain)
    );
}

#[test]
fn default_policy_only_enables_email_ip_cidr() {
    let text = "secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC host=service.example.com admin@example.com 10.0.0.1 192.168.0.0/16 +1-555-123-4567";
    let findings = RedactorBuilder::new().build().detect(text).expect("detect");

    let kinds = findings.iter().map(|f| f.kind).collect::<Vec<_>>();
    assert!(
        kinds.contains(&FindingKind::Email),
        "email should be detected by default"
    );
    assert!(
        kinds.contains(&FindingKind::Ip),
        "ip should be detected by default"
    );
    assert!(
        kinds.contains(&FindingKind::Cidr),
        "cidr should be detected by default"
    );
    assert!(
        !kinds.contains(&FindingKind::Domain),
        "domain should NOT be detected by default"
    );
    assert!(
        !kinds.contains(&FindingKind::Secret),
        "secret should NOT be detected by default"
    );
    assert!(
        !kinds.contains(&FindingKind::Url),
        "url should NOT be detected by default"
    );
}

#[test]
fn git_diff_mode_redacts_hunk_lines_without_touching_headers() {
    let diff = concat!(
        "diff --git a/config.yml b/config.yml\n",
        "index 1111111..2222222 100644\n",
        "--- a/config.yml\n",
        "+++ b/config.yml\n",
        "@@ -1,2 +1,3 @@\n",
        "-API_URL=https://api.example.com\n",
        "+API_URL=https://api.example.com/v2\n",
        "+API_TOKEN=sk_live_1234567890ABCDEFghij\n",
    );
    let result = domain_redactor()
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(
        result
            .redacted_text
            .contains("diff --git a/config.yml b/config.yml")
    );
    assert!(result.redacted_text.contains("--- a/config.yml"));
    assert!(result.redacted_text.contains("+++ b/config.yml"));
    assert!(result.redacted_text.contains("-API_URL=[[RDX:v2:"));
    assert!(result.redacted_text.contains(":URL:001:"));
    assert!(result.redacted_text.contains(":URL:002:"));
    assert!(result.redacted_text.contains(":SECRET:001:"));
    assert!(
        !result
            .redacted_text
            .contains("sk_live_1234567890ABCDEFghij")
    );
}

#[test]
fn git_diff_mode_skips_file_name_false_positives() {
    let diff = concat!(
        "diff --git a/config.yml b/config.yml\n",
        "--- a/config.yml\n",
        "+++ b/config.yml\n",
        "@@ -1,1 +1,1 @@\n",
        "-host=internal.example.com\n",
        "+host=prod.internal.example.com\n",
    );
    let findings = domain_redactor()
        .detect_with_input_kind(diff, InputKind::GitDiff)
        .expect("detect diff");

    assert!(
        findings
            .iter()
            .all(|finding| finding.match_text != "config.yml")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.match_text == "internal.example.com")
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.match_text == "prod.internal.example.com")
    );
}

#[test]
fn git_diff_mode_skips_code_like_secret_assignments() {
    let diff = concat!(
        "diff --git a/crates/redactor/src/demo.rs b/crates/redactor/src/demo.rs\n",
        "--- a/crates/redactor/src/demo.rs\n",
        "+++ b/crates/redactor/src/demo.rs\n",
        "@@ -1,3 +1,5 @@\n",
        "+    diff_budget_is_token_mode: budget.is_token_mode(),\n",
        "+    secret_redaction_preview: format_redaction_preview(&redacted_diff.entries),\n",
        "+    secret_redactions: redacted_diff.replacement_occurrences,\n",
    );
    let result = domain_redactor()
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(
        result
            .redacted_text
            .contains("diff_budget_is_token_mode: budget.is_token_mode(),")
    );
    assert!(
        result.redacted_text.contains(
            "secret_redaction_preview: format_redaction_preview(&redacted_diff.entries),"
        )
    );
    assert!(
        result
            .redacted_text
            .contains("secret_redactions: redacted_diff.replacement_occurrences,")
    );
    assert!(!result.redacted_text.contains("[[RDX:v2:"));
}

#[test]
fn git_diff_mode_skips_code_like_domains() {
    let diff = concat!(
        "diff --git a/crates/redactor/src/demo.rs b/crates/redactor/src/demo.rs\n",
        "--- a/crates/redactor/src/demo.rs\n",
        "+++ b/crates/redactor/src/demo.rs\n",
        "@@ -1,2 +1,3 @@\n",
        "+    let x = artifact.result.stats;\n",
        "+    for entry in entries.iter() {\n",
    );
    let result = domain_redactor()
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(
        result
            .redacted_text
            .contains("let x = artifact.result.stats;")
    );
    assert!(
        result
            .redacted_text
            .contains("for entry in entries.iter() {")
    );
    assert!(!result.redacted_text.contains("[[RDX:v2:"));
}

#[test]
fn git_diff_mode_keeps_redacting_real_config_values() {
    let diff = concat!(
        "diff --git a/.env b/.env\n",
        "--- a/.env\n",
        "+++ b/.env\n",
        "@@ -1,2 +1,3 @@\n",
        "+API_TOKEN=sk_live_1234567890ABCDEFghij\n",
        "+API_URL=https://api.example.com/v2\n",
        "+host=prod.internal.example.com\n",
    );
    let result = domain_redactor()
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(result.redacted_text.contains("+API_TOKEN=[[RDX:v2:"));
    assert!(result.redacted_text.contains(":SECRET:001:"));
    assert!(result.redacted_text.contains(":URL:001:"));
    assert!(result.redacted_text.contains(":DOMAIN:001:"));
}

#[test]
fn git_diff_mode_redacts_domains_with_psl_suffixes_outside_old_allowlist() {
    let diff = concat!(
        "diff --git a/.env b/.env\n",
        "--- a/.env\n",
        "+++ b/.env\n",
        "@@ -1,1 +1,2 @@\n",
        "+public_host=demo.example.tech\n",
        "+edge_host=service.example.co.uk\n",
    );
    let result = domain_redactor()
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(
        result
            .redacted_text
            .contains("+public_host=[[RDX:v2:")
    );
    assert!(result.redacted_text.contains(":DOMAIN:002:"));
}

#[test]
fn url_keeps_precedence_over_embedded_secret_like_segment() {
    let text = r#"slack_webhook = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX""#;
    let findings = RedactorBuilder::new()
        .with_redaction_policy(
            RedactionPolicy::default()
                .with_kind(FindingKind::Url, true)
                .with_kind(FindingKind::Secret, true),
        )
        .build()
        .detect(text)
        .expect("detect");

    assert!(findings.iter().any(|finding| {
        finding.kind == crate::FindingKind::Url
            && finding.match_text == "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX"
    }));
    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != crate::FindingKind::Secret)
    );
}

#[test]
fn code_scope_separators_are_not_detected_as_ips() {
    let findings = RedactorBuilder::new()
        .build()
        .detect("crate::types\nstd::ops::Range\nuse std::collections::HashMap;\n")
        .expect("detect");

    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != crate::FindingKind::Ip)
    );
}

#[test]
fn short_ipv6_fragments_are_not_detected_as_ips() {
    let findings = RedactorBuilder::new()
        .build()
        .detect("f32::\n2001:db8::1\nfe80::1\n")
        .expect("detect");

    assert!(
        findings
            .iter()
            .all(|finding| finding.kind != crate::FindingKind::Ip)
    );
}

#[test]
fn substantial_ipv6_and_ipv4_still_detect_as_ips() {
    let findings = RedactorBuilder::new()
        .build()
        .detect("2001:db8:1:2::1\n10.20.30.40\n")
        .expect("detect");

    assert!(findings.iter().any(|finding| {
        finding.kind == FindingKind::Ip && finding.match_text == "2001:db8:1:2::1"
    }));
    assert!(
        findings.iter().any(|finding| {
            finding.kind == FindingKind::Ip && finding.match_text == "10.20.30.40"
        })
    );
}

#[test]
fn custom_string_exact_match_redacts_pattern() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "my-secret-key".to_string(),
        match_type: CustomStringMatch::Exact,
        scope: CustomStringScope::Text,
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let result = redactor
        .redact("password=my-secret-key other=my-secret-key")
        .expect("redact");

    assert!(result.redacted_text.contains(":CSTR:001:"));
    assert!(!result.redacted_text.contains("my-secret-key"));
    assert!(result.redacted_text.contains("password="));
    assert!(result.redacted_text.contains("other="));
}

#[test]
fn custom_string_exact_match_finds_substring_occurrences() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "secret".to_string(),
        match_type: CustomStringMatch::Exact,
        scope: CustomStringScope::Text,
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let result = redactor
        .redact("prefix_secret_suffix another-secret")
        .expect("redact");

    assert!(result.redacted_text.contains(":CSTR:"));
}

#[test]
fn custom_string_contains_match_is_case_insensitive() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "SECRET".to_string(),
        match_type: CustomStringMatch::Contains,
        scope: CustomStringScope::Text,
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let result = redactor.redact("password=my-secret-KEY").expect("redact");

    assert!(result.redacted_text.contains(":CSTR:001:"));
}

#[test]
fn custom_string_regex_match_works() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: r"project-\d{4}".to_string(),
        match_type: CustomStringMatch::Regex,
        scope: CustomStringScope::Text,
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let result = redactor.redact("deploy project-1234 now").expect("redact");

    assert!(result.redacted_text.contains(":CSTR:001:"));
    assert!(!result.redacted_text.contains("project-1234"));
}

#[test]
fn custom_string_line_scope_redacts_entire_line() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "secret".to_string(),
        match_type: CustomStringMatch::Exact,
        scope: CustomStringScope::Line,
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let text = "safe line\npassword=secret\nanother safe line\n";
    let session = redactor.redact_with_session(text).expect("session");

    assert!(session.redacted_text.contains("safe line\n"));
    assert!(session.redacted_text.contains("another safe line\n"));
    let restored = redactor.restore_text(&session.redacted_text, &session);
    assert!(restored.is_valid());
    assert_eq!(restored.restored_text, text);
}

#[test]
fn custom_string_line_scope_merges_multiple_matches_on_same_line() {
    let policy = RedactionPolicy::default()
        .with_custom_string(CustomStringRule {
            pattern: "alpha".to_string(),
            match_type: CustomStringMatch::Exact,
            scope: CustomStringScope::Line,
        })
        .with_custom_string(CustomStringRule {
            pattern: "beta".to_string(),
            match_type: CustomStringMatch::Exact,
            scope: CustomStringScope::Line,
        });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let text = "safe\ncontains alpha and beta here\nsafe2\n";
    let result = redactor.redact(text).expect("redact");

    assert_eq!(result.findings.len(), 1);
    assert!(result.redacted_text.contains(":CSTR:001:"));
}

#[test]
fn custom_file_rule_redacts_entire_content_for_matching_source_path() {
    let policy = RedactionPolicy::default().with_custom_file(CustomFileRule {
        path: "secrets/production.env".to_string(),
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let text = "DB_HOST=localhost\nDB_USER=admin\nDB_PASS=s3cret\n";
    let artifact = redactor
        .redact_artifact_with_input_kind_and_source(
            text,
            InputKind::Text,
            Some("secrets/production.env"),
        )
        .expect("redact");

    assert!(artifact.result.redacted_text.contains(":FILE:001:"));
    assert!(!artifact.result.redacted_text.contains("localhost"));
    assert!(!artifact.result.redacted_text.contains("admin"));

    let restored = redactor.restore_text(&artifact.result.redacted_text, &artifact.session);
    assert!(restored.is_valid());
    assert_eq!(restored.restored_text, text);
}

#[test]
fn custom_file_rule_does_not_match_different_path() {
    let policy = RedactionPolicy::default().with_custom_file(CustomFileRule {
        path: "secrets/production.env".to_string(),
    });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let text = "DB_HOST=localhost\nDB_PASS=s3cret\n";
    let result = redactor
        .redact_with_source_path(text, "config/app.yml")
        .expect("redact");

    assert!(!result.redacted_text.contains(":FILE:"));
}

#[test]
fn custom_file_rule_in_git_diff_matches_file_paths() {
    let policy = RedactionPolicy::default()
        .with_kind(FindingKind::Secret, true)
        .with_custom_file(CustomFileRule {
            path: "deploy/.env".to_string(),
        });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let diff = concat!(
        "diff --git a/deploy/.env b/deploy/.env\n",
        "--- a/deploy/.env\n",
        "+++ b/deploy/.env\n",
        "@@ -1,1 +1,2 @@\n",
        "+DATABASE_URL=postgres://host:5432/mydb\n",
    );
    let result = redactor
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(result.redacted_text.contains(":FILE:001:"));
    assert!(!result.redacted_text.contains("postgres://host:5432/mydb"));
}

#[test]
fn custom_file_rule_in_git_diff_does_not_match_other_files() {
    let policy = RedactionPolicy::default()
        .with_kind(FindingKind::Secret, true)
        .with_custom_file(CustomFileRule {
            path: "deploy/.env".to_string(),
        });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let diff = concat!(
        "diff --git a/app/config.yml b/app/config.yml\n",
        "--- a/app/config.yml\n",
        "+++ b/app/config.yml\n",
        "@@ -1,1 +1,2 @@\n",
        "+API_TOKEN=sk_live_1234567890ABCDEFghij\n",
    );
    let result = redactor
        .redact_with_input_kind(diff, InputKind::GitDiff)
        .expect("redact diff");

    assert!(!result.redacted_text.contains(":FILE:"));
    assert!(result.redacted_text.contains(":SECRET:001:"));
}

#[test]
fn redact_restore_round_trip_with_custom_string() {
    let policy = RedactionPolicy::default()
        .with_kind(FindingKind::Ip, true)
        .with_custom_string(CustomStringRule {
            pattern: "project-alpha".to_string(),
            match_type: CustomStringMatch::Exact,
            scope: CustomStringScope::Text,
        });
    let redactor = RedactorBuilder::new().with_redaction_policy(policy).build();
    let text = "server=10.0.0.1 project=project-alpha";
    let session = redactor.redact_with_session(text).expect("session");

    let restored = redactor.restore_text(&session.redacted_text, &session);
    assert!(restored.is_valid());
    assert_eq!(restored.restored_text, text);
}

#[test]
fn encrypted_session_preserves_redaction_policy() {
    let policy = RedactionPolicy::default()
        .with_kind(FindingKind::Secret, true)
        .with_custom_string(CustomStringRule {
            pattern: "project-alpha".to_string(),
            match_type: CustomStringMatch::Exact,
            scope: CustomStringScope::Text,
        })
        .with_custom_file(CustomFileRule {
            path: "secrets/production.env".to_string(),
        });
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(policy.clone())
        .build();
    let session = redactor
        .redact_with_session("project-alpha")
        .expect("session");
    let encrypted = encrypt_session_to_string(&session, "passphrase").expect("encrypt");
    let decrypted = decrypt_session_from_str(&encrypted, "passphrase").expect("decrypt");

    assert_eq!(decrypted.policy, policy);
}

#[test]
fn invalid_regex_in_custom_string_returns_validation_error() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "[invalid(regex".to_string(),
        match_type: CustomStringMatch::Regex,
        scope: CustomStringScope::Text,
    });
    assert!(policy.validate().is_err());
}

#[test]
fn empty_pattern_in_custom_string_returns_validation_error() {
    let policy = RedactionPolicy::default().with_custom_string(CustomStringRule {
        pattern: "".to_string(),
        match_type: CustomStringMatch::Exact,
        scope: CustomStringScope::Text,
    });
    assert!(policy.validate().is_err());
}

#[test]
fn empty_path_in_custom_file_returns_validation_error() {
    let policy = RedactionPolicy::default().with_custom_file(CustomFileRule {
        path: "".to_string(),
    });
    assert!(policy.validate().is_err());
}
