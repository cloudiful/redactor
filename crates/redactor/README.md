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
Domain and person detection are disabled by default; configure `RedactionRules` when callers need those finding kinds.
