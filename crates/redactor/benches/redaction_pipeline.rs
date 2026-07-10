use std::hint::black_box;
use std::time::Instant;

use cloudiful_redactor::{
    CustomStringMatch, CustomStringRule, CustomStringScope, FindingKind, RedactionPolicy,
    RedactorBuilder, RestoreContext, SessionRedactor,
};

fn timed(label: &str, iterations: usize, mut run: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        run();
    }
    let elapsed = started.elapsed();
    println!(
        "{label}: {iterations} iterations in {elapsed:?} ({:.2} us/iter)",
        elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
    );
}

fn custom_rule(index: usize) -> CustomStringRule {
    CustomStringRule {
        pattern: format!("tenant-secret-{index:03}"),
        match_type: if index % 2 == 0 {
            CustomStringMatch::Exact
        } else {
            CustomStringMatch::Contains
        },
        scope: CustomStringScope::Text,
    }
}

fn main() {
    let custom_policy = RedactionPolicy::default()
        .with_custom_strings((0..100).map(custom_rule).collect::<Vec<_>>());
    let custom_redactor = RedactorBuilder::new()
        .with_redaction_policy(custom_policy)
        .build();
    let fields = (0..128)
        .map(|index| format!("payload tenant-secret-{:03}", index % 100))
        .collect::<Vec<_>>();
    timed("detect_custom_100_rules_128_fields", 100, || {
        for field in &fields {
            black_box(custom_redactor.detect(black_box(field)).unwrap());
        }
    });

    let domain_policy = RedactionPolicy::default().with_kind(FindingKind::Domain, true);
    let domain_redactor = RedactorBuilder::new()
        .with_redaction_policy(domain_policy.clone())
        .build();
    let session_fields = (0..512)
        .map(|index| format!("service-{index}.example.com"))
        .collect::<Vec<_>>();
    timed("session_512_fields", 20, || {
        let mut session_redactor = SessionRedactor::new();
        let redacted = session_fields
            .iter()
            .map(|field| {
                session_redactor
                    .redact_fragment(&domain_redactor, field)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        black_box(session_redactor.finish_session(
            &session_fields.join("\n"),
            &redacted.join("\n"),
            &domain_policy,
        ));
    });

    let mut session_redactor = SessionRedactor::new();
    let redacted_fields = session_fields
        .iter()
        .map(|field| {
            session_redactor
                .redact_fragment(&domain_redactor, field)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let session = session_redactor.finish_session(
        &session_fields.join("\n"),
        &redacted_fields.join("\n"),
        &domain_policy,
    );
    timed("restore_context_512_entries_128_fields", 100, || {
        let context = RestoreContext::new(&session);
        for field in redacted_fields.iter().take(128) {
            black_box(context.restore_text(black_box(field)));
        }
    });
}
