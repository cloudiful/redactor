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

Use `RestoreState` to retain authorization across redaction rounds without retaining duplicate token
references:

```rust
use cloudiful_redactor::{RedactorBuilder, RestoreState};

let redactor = RedactorBuilder::new().build();
let session = redactor.redact_with_session("mail=alice@example.com")?;
let state = RestoreState::new(session)?;
let restored = state.restore_text(&state.session().redacted_text)?;
assert_eq!(restored.restored_text, "mail=alice@example.com");
# Ok::<(), anyhow::Error>(())
```

For decoded response fragments, create one `StreamingRestoreContext` per logical text stream. It
buffers only an incomplete marker or token, up to 4096 bytes:

```rust
# use cloudiful_redactor::{RedactorBuilder, RestoreState};
# let session = RedactorBuilder::new().build()
#     .redact_with_session("mail=alice@example.com")?;
let state = RestoreState::new(session)?;
let token = state.session().redacted_text.clone();
let split = token.len() / 2;
let mut stream = state.streaming_restore_context()?;
let first = stream.push_str(&token[..split]);
let second = stream.push_str(&token[split..]);
let end = stream.finish();
let restored = first.restored_text + &second.restored_text + &end.restored_text;
assert_eq!(restored, "mail=alice@example.com");
# Ok::<(), anyhow::Error>(())
```

Fragments must already be UTF-8 decoded. Decode JSON escapes before restoration, then serialize the
restored value again. The streaming API does not parse bytes, JSON, SSE, HTTP, or other framing.

`RestoreState` contains a full plaintext `RedactionSession`, including original sensitive values.
Never place it in a model prompt. Encrypt it at rest and restrict access to the restoring caller.
Legacy `RedactionSession` values are not automatically converted or migrated into state. Callers
must not seed state from an old envelope. When upgrading prompt-ferry, discard old envelopes and
establish new `RestoreState` values from new redaction rounds.

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
