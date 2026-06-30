use anyhow::{Context, Result, anyhow};
use redis::{Commands, Script};
use redactor::{RedactionSession, SessionStore, StoredSession};
use serde::{Deserialize, Serialize};

const DEFAULT_PREFIX: &str = "redactor:session:latest:";

#[derive(Debug, Clone)]
pub struct ValkeySessionStore {
    client: redis::Client,
    key_prefix: String,
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEnvelope {
    version: u64,
    session: RedactionSession,
}

impl ValkeySessionStore {
    pub fn from_url(url: &str) -> Result<Self> {
        Self::builder(url).build()
    }

    pub fn builder(url: &str) -> ValkeySessionStoreBuilder {
        ValkeySessionStoreBuilder {
            url: url.to_string(),
            key_prefix: DEFAULT_PREFIX.to_string(),
            ttl_seconds: None,
        }
    }

    fn key_for(&self, external_id: &str) -> String {
        format!("{}{}", self.key_prefix, external_id)
    }
}

#[derive(Debug, Clone)]
pub struct ValkeySessionStoreBuilder {
    url: String,
    key_prefix: String,
    ttl_seconds: Option<u64>,
}

impl ValkeySessionStoreBuilder {
    pub fn with_key_prefix(mut self, key_prefix: impl Into<String>) -> Self {
        self.key_prefix = key_prefix.into();
        self
    }

    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = Some(ttl_seconds);
        self
    }

    pub fn build(self) -> Result<ValkeySessionStore> {
        let client = redis::Client::open(self.url.as_str())
            .with_context(|| format!("failed to create Valkey client for `{}`", self.url))?;
        Ok(ValkeySessionStore {
            client,
            key_prefix: self.key_prefix,
            ttl_seconds: self.ttl_seconds,
        })
    }
}

impl SessionStore for ValkeySessionStore {
    fn load_latest(&self, external_id: &str) -> Result<Option<StoredSession>> {
        let mut conn = self
            .client
            .get_connection()
            .context("failed to connect to Valkey")?;
        let key = self.key_for(external_id);
        let value: Option<String> = conn
            .get(&key)
            .with_context(|| format!("failed to load Valkey session for `{external_id}`"))?;
        let Some(value) = value else {
            return Ok(None);
        };
        let envelope: SessionEnvelope = serde_json::from_str(&value)
            .with_context(|| format!("failed to parse Valkey session for `{external_id}`"))?;
        Ok(Some(StoredSession {
            session: envelope.session,
            version: Some(envelope.version.to_string()),
        }))
    }

    fn save_latest(
        &self,
        external_id: &str,
        session: &RedactionSession,
        expected_version: Option<&str>,
    ) -> Result<Option<String>> {
        let mut conn = self
            .client
            .get_connection()
            .context("failed to connect to Valkey")?;
        let key = self.key_for(external_id);
        let next_version = expected_version
            .map(|value| {
                value
                    .parse::<u64>()
                    .with_context(|| format!("invalid stored version `{value}`"))
                    .map(|version| version + 1)
            })
            .transpose()?
            .unwrap_or(1);
        let payload = serde_json::to_string(&SessionEnvelope {
            version: next_version,
            session: session.clone(),
        })
        .context("failed to serialize session for Valkey")?;

        let script = if self.ttl_seconds.is_some() {
            Script::new(
                r#"
local current = redis.call("GET", KEYS[1])
if current == false then
  if ARGV[2] ~= "" then
    return {err = "version_conflict"}
  end
  redis.call("SET", KEYS[1], ARGV[1], "EX", tonumber(ARGV[3]))
  return ARGV[4]
end
local decoded = cjson.decode(current)
if tostring(decoded.version) ~= ARGV[2] then
  return {err = "version_conflict"}
end
redis.call("SET", KEYS[1], ARGV[1], "EX", tonumber(ARGV[3]))
return ARGV[4]
"#,
            )
        } else {
            Script::new(
                r#"
local current = redis.call("GET", KEYS[1])
if current == false then
  if ARGV[2] ~= "" then
    return {err = "version_conflict"}
  end
  redis.call("SET", KEYS[1], ARGV[1])
  return ARGV[3]
end
local decoded = cjson.decode(current)
if tostring(decoded.version) ~= ARGV[2] then
  return {err = "version_conflict"}
end
redis.call("SET", KEYS[1], ARGV[1])
return ARGV[3]
"#,
            )
        };

        let expected = expected_version.unwrap_or("");
        let result = match self.ttl_seconds {
            Some(ttl_seconds) => script
                .key(&key)
                .arg(&payload)
                .arg(expected)
                .arg(ttl_seconds)
                .arg(next_version.to_string())
                .invoke::<String>(&mut conn),
            None => script
                .key(&key)
                .arg(&payload)
                .arg(expected)
                .arg(next_version.to_string())
                .invoke::<String>(&mut conn),
        };

        result
            .map(Some)
            .map_err(|error| anyhow!("failed to save Valkey session for `{external_id}`: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::ValkeySessionStore;
    use redactor::{
        FindingKind, RedactionPolicy, RedactorBuilder, SessionStore,
        redact_text_artifact_with_stateful_session,
    };
    use redis::Commands;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_URL: &str = "redis://127.0.0.1:6379/0";

    fn unique_prefix(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("redactor:test:{name}:{nanos}:")
    }

    fn build_redactor() -> redactor::Redactor {
        RedactorBuilder::new()
            .with_redaction_policy(
                RedactionPolicy::default()
                    .with_kind(FindingKind::Domain, true)
                    .with_kind(FindingKind::Secret, true),
            )
            .build()
    }

    #[test]
    fn save_and_load_round_trip() {
        let prefix = unique_prefix("roundtrip");
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(prefix.clone())
            .build()
            .expect("store");
        let artifact = build_redactor()
            .redact_artifact_with_prior_session(
                "host=service.example.com",
                redactor::InputKind::Text,
                None,
                Some("conv-1"),
            )
            .expect("artifact");

        let version = store
            .save_latest("conv-1", &artifact.session, None)
            .expect("save")
            .expect("version");
        let loaded = store
            .load_latest("conv-1")
            .expect("load")
            .expect("stored");

        assert_eq!(loaded.session, artifact.session);
        assert_eq!(loaded.version.as_deref(), Some(version.as_str()));
    }

    #[test]
    fn missing_key_returns_none() {
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(unique_prefix("missing"))
            .build()
            .expect("store");

        assert!(store.load_latest("missing").expect("load").is_none());
    }

    #[test]
    fn ttl_is_applied() {
        let prefix = unique_prefix("ttl");
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(prefix.clone())
            .with_ttl_seconds(120)
            .build()
            .expect("store");
        let artifact = build_redactor()
            .redact_artifact_with_prior_session(
                "host=service.example.com",
                redactor::InputKind::Text,
                None,
                Some("conv-ttl"),
            )
            .expect("artifact");
        store
            .save_latest("conv-ttl", &artifact.session, None)
            .expect("save");

        let client = redis::Client::open(TEST_URL).expect("client");
        let mut conn = client.get_connection().expect("conn");
        let ttl: i64 = conn.ttl(format!("{prefix}conv-ttl")).expect("ttl");

        assert!(ttl > 0);
        assert!(ttl <= 120);
    }

    #[test]
    fn key_prefix_is_used() {
        let prefix = unique_prefix("prefix");
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(prefix.clone())
            .build()
            .expect("store");
        let artifact = build_redactor()
            .redact_artifact_with_prior_session(
                "host=service.example.com",
                redactor::InputKind::Text,
                None,
                Some("conv-prefix"),
            )
            .expect("artifact");
        store
            .save_latest("conv-prefix", &artifact.session, None)
            .expect("save");

        let client = redis::Client::open(TEST_URL).expect("client");
        let mut conn = client.get_connection().expect("conn");
        let exists: bool = conn.exists(format!("{prefix}conv-prefix")).expect("exists");

        assert!(exists);
    }

    #[test]
    fn version_conflict_returns_error() {
        let prefix = unique_prefix("conflict");
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(prefix)
            .build()
            .expect("store");
        let redactor = build_redactor();
        let first = redactor
            .redact_artifact_with_prior_session(
                "host=service.example.com",
                redactor::InputKind::Text,
                None,
                Some("conv-conflict"),
            )
            .expect("first");
        let second = redactor
            .redact_artifact_with_prior_session(
                "backup=service.example.com",
                redactor::InputKind::Text,
                None,
                Some("conv-conflict"),
            )
            .expect("second");

        let version = store
            .save_latest("conv-conflict", &first.session, None)
            .expect("save")
            .expect("version");
        let error = store
            .save_latest("conv-conflict", &second.session, Some(&(version.parse::<u64>().expect("version") - 1).to_string()))
            .expect_err("conflict");

        assert!(error.to_string().contains("version_conflict"));
    }

    #[test]
    fn stateful_redaction_reuses_tokens_serially() {
        let prefix = unique_prefix("serial");
        let store = ValkeySessionStore::builder(TEST_URL)
            .with_key_prefix(prefix)
            .build()
            .expect("store");
        let redactor = build_redactor();
        let first = redact_text_artifact_with_stateful_session(
            &redactor,
            "host=service.example.com",
            redactor::InputKind::Text,
            "conv-serial",
            &store,
        )
        .expect("first");
        let second = redact_text_artifact_with_stateful_session(
            &redactor,
            "backup=service.example.com",
            redactor::InputKind::Text,
            "conv-serial",
            &store,
        )
        .expect("second");

        assert_eq!(first.session.scope_id, second.session.scope_id);
        assert_eq!(first.session.entries[0].token, second.session.entries[0].token);
    }
}
