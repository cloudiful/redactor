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

## HTTP service

`redactor-app` keeps HTTP support split into Cargo features:

- `http`: starts HTTP service, enables `/redact/text`, `/restore/text`, and `/inspect/session`
- `valkey-session-store`: enables built-in Valkey-backed stateful session persistence for `external_id`

Build commands:

```bash
cargo run -p redactor-app --no-default-features --features http -- serve
cargo run -p redactor-app --no-default-features --features "http valkey-session-store" -- serve --valkey-url redis://127.0.0.1:6379/0
```

`external_id` stateful requests only work when a `SessionStore` provider is configured. Without a provider:

- `/redact/text` and `/restore/text` requests using `external_id` return a clear configuration error

When using the built-in Valkey provider:

- `external_id` maps to the latest stored `RedactionSession`
- keys contain a SHA-256 digest of `external_id`, not the identifier itself
- session values are encrypted with `REDACTOR_SESSION_PASSPHRASE`
- TTL is optional and disabled by default
- concurrent writes use version checks and fail on conflict instead of silently overwriting

`REDACTOR_SESSION_PASSPHRASE` must contain at least 32 UTF-8 bytes. The service validates it at
startup. Treat it as a service secret and never log it.

Every redaction response includes a `restore_permit`. Restore accepts a `restore_permits` array and
only restores tokens authorized by those permits. Valid RDX tokens that were merely copied into the
input remain unchanged and are returned in `skipped_tokens`.

The OpenAPI document is generated from the Rust routes and DTOs:

```bash
cargo run -p redactor-http --bin export-openapi -- openapi/redactor-http.yaml
```

## Upgrade to 0.4

Version 0.4 changes the `SessionStore` trait to async and requires restore permits. Complete any
pending restores created by 0.3 before upgrading. Old Valkey plaintext records are deliberately not
read or migrated.

After all 0.3 instances are stopped, remove legacy records in bounded batches. Inspect each batch
before unlinking it:

```text
SCAN 0 MATCH redactor:session:latest:* COUNT 100
UNLINK <key> [<key> ...]
```

Repeat `SCAN` with the returned cursor until it returns `0`. The service never deletes legacy keys
automatically.

## Release flows

- GitHub Actions validates and publishes `cloudiful-redactor` to crates.io on `v*` tags.

## License

Apache-2.0. See [LICENSE](LICENSE).
