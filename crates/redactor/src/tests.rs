use crate::{
    FindingKind, InputKind, RedactionRules, Redactor, RedactorBuilder, decrypt_session_from_str,
    encrypt_session_to_string,
};

fn domain_redactor() -> Redactor {
    RedactorBuilder::new()
        .with_redaction_rules(RedactionRules::default().with_kind(FindingKind::Domain, true))
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

    assert!(result.redacted_text.contains("__R_DOMAIN_001__"));
    assert!(result.redacted_text.contains("__R_DOMAIN_002__"));
    assert!(result.redacted_text.contains("__R_SECRET_001__"));
    assert!(result.redacted_text.contains("__R_SECRET_002__"));
    assert!(result.redacted_text.contains("__R_SECRET_003__"));
    assert!(result.redacted_text.contains("__R_CIDR_001__"));
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
    let edited = session
        .redacted_text
        .replace("__R_SECRET_001__", "__R_SECRET_001_X__");

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
    assert_eq!(decrypted.redacted_text, session.redacted_text);
    assert_eq!(decrypted.entries.len(), session.entries.len());
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
        .with_person_detection(true)
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
    assert!(result.redacted_text.contains("-API_URL=__R_URL_001__"));
    assert!(result.redacted_text.contains("+API_URL=__R_URL_002__"));
    assert!(result.redacted_text.contains("+API_TOKEN=__R_SECRET_001__"));
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
    assert!(!result.redacted_text.contains("__R_SECRET_"));
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
    assert!(!result.redacted_text.contains("__R_DOMAIN_"));
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

    assert!(result.redacted_text.contains("+API_TOKEN=__R_SECRET_001__"));
    assert!(result.redacted_text.contains("+API_URL=__R_URL_001__"));
    assert!(result.redacted_text.contains("+host=__R_DOMAIN_001__"));
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
            .contains("+public_host=__R_DOMAIN_001__")
    );
    assert!(result.redacted_text.contains("+edge_host=__R_DOMAIN_002__"));
}

#[test]
fn url_keeps_precedence_over_embedded_secret_like_segment() {
    let text = r#"slack_webhook = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX""#;
    let findings = RedactorBuilder::new().build().detect(text).expect("detect");

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
