use anyhow::anyhow;
use async_trait::async_trait;
use redactor::{
    RedactionSession, SessionStore, SessionStoreError, StoredSession, decrypt_session_from_storage,
    encrypt_session_for_storage,
};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_NAMESPACE: &str = "redactor:session:encrypted:v1:";
const MIN_PASSPHRASE_BYTES: usize = 32;

#[derive(Clone)]
pub struct ValkeySessionStore {
    connection: ConnectionManager,
    key_namespace: String,
    ttl_seconds: Option<u64>,
    passphrase: SecretString,
}

impl std::fmt::Debug for ValkeySessionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValkeySessionStore")
            .field("key_namespace", &self.key_namespace)
            .field("ttl_seconds", &self.ttl_seconds)
            .field("passphrase", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEnvelope {
    version: u64,
    encrypted_session: String,
}

impl ValkeySessionStore {
    pub async fn from_url(url: &str, passphrase: impl Into<SecretString>) -> anyhow::Result<Self> {
        Self::builder(url, passphrase).build().await
    }

    pub fn builder(url: &str, passphrase: impl Into<SecretString>) -> ValkeySessionStoreBuilder {
        ValkeySessionStoreBuilder {
            url: url.to_string(),
            key_namespace: DEFAULT_NAMESPACE.to_string(),
            ttl_seconds: None,
            passphrase: passphrase.into(),
        }
    }

    fn key_for(&self, external_id: &str) -> String {
        let digest = Sha256::digest(external_id.as_bytes());
        format!("{}{}", self.key_namespace, hex::encode(digest))
    }
}

pub struct ValkeySessionStoreBuilder {
    url: String,
    key_namespace: String,
    ttl_seconds: Option<u64>,
    passphrase: SecretString,
}

impl std::fmt::Debug for ValkeySessionStoreBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValkeySessionStoreBuilder")
            .field("url", &self.url)
            .field("key_namespace", &self.key_namespace)
            .field("ttl_seconds", &self.ttl_seconds)
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

impl ValkeySessionStoreBuilder {
    pub fn with_key_namespace(mut self, key_namespace: impl Into<String>) -> Self {
        self.key_namespace = key_namespace.into();
        self
    }

    pub fn with_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = Some(ttl_seconds);
        self
    }

    pub async fn build(self) -> anyhow::Result<ValkeySessionStore> {
        if self.passphrase.expose_secret().len() < MIN_PASSPHRASE_BYTES {
            anyhow::bail!("session passphrase must contain at least 32 UTF-8 bytes");
        }
        let client = redis::Client::open(self.url.as_str())?;
        let connection = ConnectionManager::new(client).await?;
        Ok(ValkeySessionStore {
            connection,
            key_namespace: self.key_namespace,
            ttl_seconds: self.ttl_seconds,
            passphrase: self.passphrase,
        })
    }
}

#[async_trait]
impl SessionStore for ValkeySessionStore {
    async fn load_latest(
        &self,
        external_id: &str,
    ) -> Result<Option<StoredSession>, SessionStoreError> {
        let mut connection = self.connection.clone();
        let value: Option<String> = connection
            .get(self.key_for(external_id))
            .await
            .map_err(unavailable)?;
        let Some(value) = value else {
            return Ok(None);
        };
        let envelope: SessionEnvelope = serde_json::from_str(&value)
            .map_err(|error| SessionStoreError::CorruptData(error.into()))?;
        let encrypted = envelope.encrypted_session;
        let passphrase = self.passphrase.clone();
        let external_id = external_id.to_string();
        let session = tokio::task::spawn_blocking(move || {
            decrypt_session_from_storage(&encrypted, passphrase.expose_secret(), &external_id)
        })
        .await
        .map_err(|error| SessionStoreError::Crypto(anyhow!(error)))?
        .map_err(SessionStoreError::Crypto)?;
        Ok(Some(StoredSession {
            session,
            version: envelope.version.to_string(),
        }))
    }

    async fn save_latest(
        &self,
        external_id: &str,
        session: &RedactionSession,
        expected_version: Option<&str>,
    ) -> Result<String, SessionStoreError> {
        let next_version = expected_version
            .map(|value| value.parse::<u64>().map(|version| version + 1))
            .transpose()
            .map_err(|error| SessionStoreError::CorruptData(error.into()))?
            .unwrap_or(1);
        let session = session.clone();
        let passphrase = self.passphrase.clone();
        let external_id_owned = external_id.to_string();
        let encrypted_session = tokio::task::spawn_blocking(move || {
            encrypt_session_for_storage(&session, passphrase.expose_secret(), &external_id_owned)
        })
        .await
        .map_err(|error| SessionStoreError::Crypto(anyhow!(error)))?
        .map_err(SessionStoreError::Crypto)?;
        let payload = serde_json::to_string(&SessionEnvelope {
            version: next_version,
            encrypted_session,
        })
        .map_err(|error| SessionStoreError::CorruptData(error.into()))?;
        let mut connection = self.connection.clone();
        let script = save_script(self.ttl_seconds.is_some());
        let expected = expected_version.unwrap_or("");
        let result = match self.ttl_seconds {
            Some(ttl) => {
                script
                    .key(self.key_for(external_id))
                    .arg(payload)
                    .arg(expected)
                    .arg(ttl)
                    .arg(next_version)
                    .invoke_async::<u64>(&mut connection)
                    .await
            }
            None => {
                script
                    .key(self.key_for(external_id))
                    .arg(payload)
                    .arg(expected)
                    .arg(0)
                    .arg(next_version)
                    .invoke_async::<u64>(&mut connection)
                    .await
            }
        };
        result.map(|version| version.to_string()).map_err(|error| {
            if error.to_string().contains("version_conflict") {
                SessionStoreError::Conflict
            } else {
                unavailable(error)
            }
        })
    }
}

fn unavailable(error: redis::RedisError) -> SessionStoreError {
    SessionStoreError::Unavailable(error.into())
}

fn save_script(with_ttl: bool) -> Script {
    let set = if with_ttl {
        "redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[3]))"
    } else {
        "redis.call('SET', KEYS[1], ARGV[1])"
    };
    Script::new(&format!(
        r#"
local current = redis.call('GET', KEYS[1])
if current == false then
  if ARGV[2] ~= '' then return {{err = 'version_conflict'}} end
  {set}
  return tonumber(ARGV[4])
end
local decoded = cjson.decode(current)
if tostring(decoded.version) ~= ARGV[2] then
  return {{err = 'version_conflict'}}
end
{set}
return tonumber(ARGV[4])
"#
    ))
}
