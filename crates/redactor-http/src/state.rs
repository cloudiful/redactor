use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use redactor::{RedactionPolicy, SessionStore};
#[cfg(feature = "valkey-session-store")]
use redactor_session_store_valkey::ValkeySessionStore;
use secrecy::{ExposeSecret, SecretString};
use server::{CorsConfig, ServerConfig, TlsConfig, ValidatedServerConfig};

use crate::blocking::BlockingExecutor;

const MIN_PASSPHRASE_BYTES: usize = 32;

#[derive(Clone)]
pub struct HttpServerConfig {
    pub listen: String,
    pub audit_dir: Option<PathBuf>,
    pub session_passphrase_env: String,
    pub cors_allowed_origins: Vec<String>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub redaction_policy: RedactionPolicy,
    session_passphrase_override: Option<SecretString>,
    session_store: Option<Arc<dyn SessionStore>>,
}

impl HttpServerConfig {
    pub fn new(listen: String, audit_dir: Option<PathBuf>, session_passphrase_env: String) -> Self {
        Self {
            listen,
            audit_dir,
            session_passphrase_env,
            cors_allowed_origins: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            redaction_policy: RedactionPolicy::default(),
            session_passphrase_override: None,
            session_store: None,
        }
    }

    pub fn with_cors_allowed_origins<I, S>(mut self, allowed_origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.cors_allowed_origins = allowed_origins.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_tls(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(key_path.into());
        self
    }

    pub fn with_session_passphrase(mut self, passphrase: impl Into<SecretString>) -> Self {
        self.session_passphrase_override = Some(passphrase.into());
        self
    }

    pub fn with_redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }

    pub fn with_session_store(mut self, session_store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(session_store);
        self
    }

    #[cfg(feature = "valkey-session-store")]
    pub async fn with_valkey_session_store(
        mut self,
        url: &str,
        key_namespace: Option<&str>,
        ttl_seconds: Option<u64>,
    ) -> Result<Self> {
        let passphrase = self.resolve_passphrase()?;
        let mut builder = ValkeySessionStore::builder(url, passphrase);
        if let Some(namespace) = key_namespace {
            builder = builder.with_key_namespace(namespace);
        }
        if let Some(ttl_seconds) = ttl_seconds {
            builder = builder.with_ttl_seconds(ttl_seconds);
        }
        self.session_store = Some(Arc::new(builder.build().await?));
        Ok(self)
    }

    pub(crate) fn server_config(&self) -> Result<ValidatedServerConfig<Arc<HttpState>>> {
        let cors = if self.cors_allowed_origins.is_empty() {
            CorsConfig::permissive()
        } else {
            CorsConfig::restricted(self.cors_allowed_origins.clone())
                .with_allowed_methods(["GET", "POST", "OPTIONS"])
        };
        let mut config = ServerConfig::new()
            .with_listen_addr(self.listen.clone())
            .with_app_data(HttpState::from_config(self)?)
            .with_cors(cors);
        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(cert), Some(key)) => {
                config = config.with_tls(
                    TlsConfig::new()
                        .with_cert_path(cert.clone())
                        .with_cert_key_path(key.clone()),
                );
            }
            (None, None) => {}
            _ => anyhow::bail!("HTTP TLS configuration requires both certificate and key paths"),
        }
        config
            .build()
            .context("failed to validate HTTP server configuration")
    }

    fn resolve_passphrase(&self) -> Result<SecretString> {
        let passphrase = self
            .session_passphrase_override
            .clone()
            .or_else(|| env::var(&self.session_passphrase_env).ok().map(Into::into))
            .with_context(|| {
                format!(
                    "missing session passphrase in {}",
                    self.session_passphrase_env
                )
            })?;
        if passphrase.expose_secret().len() < MIN_PASSPHRASE_BYTES {
            anyhow::bail!("session passphrase must contain at least 32 UTF-8 bytes");
        }
        Ok(passphrase)
    }
}

#[derive(Clone)]
pub(crate) struct HttpState {
    pub(crate) audit_dir: Option<PathBuf>,
    pub(crate) session_passphrase: SecretString,
    pub(crate) redaction_policy: RedactionPolicy,
    pub(crate) session_store: Option<Arc<dyn SessionStore>>,
    pub(crate) blocking: BlockingExecutor,
}

impl HttpState {
    pub(crate) fn from_config(config: &HttpServerConfig) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            audit_dir: config.audit_dir.clone(),
            session_passphrase: config.resolve_passphrase()?,
            redaction_policy: config.redaction_policy.clone(),
            session_store: config.session_store.clone(),
            blocking: BlockingExecutor::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpServerConfig, HttpState};

    #[test]
    fn rejects_short_session_passphrase_at_startup() {
        let config = HttpServerConfig::new("127.0.0.1:0".to_string(), None, "IGNORED".to_string())
            .with_session_passphrase("too-short");
        assert!(HttpState::from_config(&config).is_err());
    }
}
