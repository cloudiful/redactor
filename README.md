# Redactor

`redactor` is a Rust workspace for structured redaction and reversible restore flows.

The publishable library crate is [`cloudiful-redactor`](https://crates.io/crates/cloudiful-redactor). The workspace also contains:

- `redactor-app`: CLI and local tooling
- `redactor-http`: HTTP service host for text redaction endpoints and optional proxy routes
- `redactor-chat-responses-proxy`: internal chat/responses proxy crate behind an opt-in Cargo feature

## Public crate

Install the library from crates.io:

```bash
cargo add cloudiful-redactor
```

Minimal usage:

```rust
use cloudiful_redactor::{FindingKind, RedactionRules, RedactorBuilder};

fn main() -> anyhow::Result<()> {
    let redactor = RedactorBuilder::new()
        .with_redaction_rules(RedactionRules::default().with_kind(FindingKind::Domain, true))
        .build();
    let result = redactor.redact("host=service.example.com secret=sk_live_1234567890ABCDEFghij")?;

    println!("{}", result.redacted_text);
    Ok(())
}
```

Domain and person detection are disabled by default. Use `RedactionRules` or config keys under
`[redaction]` to enable only the finding kinds the caller needs.

For reversible redaction, use the session-based APIs:

- `Redactor::redact_with_session`
- `restore_text_with_session`
- `restore_patch_with_session`

## Proxy feature matrix

`redactor-app` keeps proxy support split into two Cargo features:

- `proxy`: starts HTTP service, enables `/redact/text`, `/restore/text`, and `/inspect/session`
- `chat-responses-proxy`: re-enables `/v1/chat/completions` and `/v1/responses` redaction proxying when combined with `proxy`

Build commands:

```bash
cargo run -p redactor-app --no-default-features --features proxy -- proxy
cargo run -p redactor-app --no-default-features --features "proxy chat-responses-proxy" -- proxy
```

When built with only `proxy`, the chat/responses routes stay registered but return `501 Not Implemented` with a feature-disabled error payload.

## Release flows

- GitHub Actions runs public crate CI and publishes `cloudiful-redactor` to crates.io on `v*` tags.
- Gitea Actions validates the public crate and publishes `cloudiful-redactor` to Kellnr on `v*` tags.

## License

Apache-2.0. See [LICENSE](LICENSE).
