# Redactor

`redactor` is a Rust workspace for structured redaction and reversible restore flows.

The publishable library crate is [`cloudiful-redactor`](https://crates.io/crates/cloudiful-redactor). The workspace also contains:

- `redactor-app`: CLI and local tooling
- `redactor-http`: HTTP proxy and text redaction endpoints

## Public crate

Install the library from crates.io:

```bash
cargo add cloudiful-redactor
```

Minimal usage:

```rust
use cloudiful_redactor::RedactorBuilder;

fn main() -> anyhow::Result<()> {
    let redactor = RedactorBuilder::new().build();
    let result = redactor.redact("host=service.example.com secret=sk_live_1234567890ABCDEFghij")?;

    println!("{}", result.redacted_text);
    Ok(())
}
```

For reversible redaction, use the session-based APIs:

- `Redactor::redact_with_session`
- `restore_text_with_session`
- `restore_patch_with_session`

## Release flows

- GitHub Actions runs public crate CI and publishes `cloudiful-redactor` to crates.io on `v*` tags.
- Gitea Actions validates the public crate and publishes `cloudiful-redactor` to Kellnr on `v*` tags.

## License

Apache-2.0. See [LICENSE](LICENSE).
