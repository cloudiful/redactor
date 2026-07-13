# cloudiful-redactor

`cloudiful-redactor` provides structured redaction and reversible restore APIs for text, config fragments, and git diffs.

## Install

```bash
cargo add cloudiful-redactor
```

## Example

```rust
use cloudiful_redactor::{restore_text_with_session, InputKind, RedactorBuilder};

fn main() -> anyhow::Result<()> {
    let redactor = RedactorBuilder::new().build();
    let session = redactor.redact_with_session_input_kind(
        "API_TOKEN=sk_live_1234567890ABCDEFghij",
        InputKind::Text,
    )?;

    let restored = restore_text_with_session(&session.redacted_text, &session);
    assert!(restored.is_valid());

    Ok(())
}
```

The crate keeps session-based restoration APIs available for reversible masking flows, including git diff handling through `InputKind::GitDiff`.
Each new session records only the tokens issued by that redaction operation. Restore skips valid RDX
tokens that are not authorized by that operation and reports them through `RestoreResult::skipped_tokens`.
Domain and person detection are disabled by default; configure `RedactionRules` when callers need those finding kinds.

For structured payloads with multiple text fields, reuse one `SessionRedactor` and finish the
session after all fields are processed. Reuse one `RestoreContext` when restoring those fields;
this avoids rebuilding session state and token indexes for every field.

```rust
use cloudiful_redactor::{
    RedactionPolicy, RedactorBuilder, RestoreContext, SessionRedactor,
};

let policy = RedactionPolicy::default();
let redactor = RedactorBuilder::new()
    .with_redaction_policy(policy.clone())
    .build();
let mut processor = SessionRedactor::new();
let redacted = processor.redact_fragment(&redactor, "alice@example.com")?;
let session = processor.finish_session("alice@example.com", &redacted, &policy);
let restored = RestoreContext::new(&session).restore_text(&redacted);
# Ok::<(), cloudiful_redactor::RedactorError>(())
```
