# Redactor

`redactor` is a Rust workspace for structured redaction and reversible restore flows.

The publishable library crate is [`cloudiful-redactor`](https://crates.io/crates/cloudiful-redactor). The workspace also contains:

- `redactor-app`: CLI and local tooling
- `redactor-http`: HTTP service host for text redaction endpoints
- `redactor-session-store-valkey`: optional Valkey-backed `SessionStore` provider

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

## HTTP feature matrix

`redactor-app` keeps HTTP support split into Cargo features:

- `proxy`: starts HTTP service, enables `/redact/text`, `/restore/text`, and `/inspect/session`
- `valkey-session-store`: enables built-in Valkey-backed stateful session persistence for `external_id`

Build commands:

```bash
cargo run -p redactor-app --no-default-features --features proxy -- proxy
cargo run -p redactor-app --no-default-features --features "proxy valkey-session-store" -- proxy --valkey-url redis://127.0.0.1:6379/0
```

`external_id` stateful requests only work when a `SessionStore` provider is configured. Without a provider:

- `/redact/text` and `/restore/text` requests using `external_id` return a clear configuration error

When using the built-in Valkey provider:

- `external_id` maps to the latest stored `RedactionSession`
- sessions are stored under a configurable key prefix
- TTL is optional and disabled by default
- concurrent writes use version checks and fail on conflict instead of silently overwriting

## Release flows

- GitHub Actions runs public crate CI and publishes `cloudiful-redactor` to crates.io on `v*` tags.
- Gitea Actions validates the public crate and publishes `cloudiful-redactor` to Kellnr on `v*` tags.

## License

Apache-2.0. See [LICENSE](LICENSE).
