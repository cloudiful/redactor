use anyhow::{Context, Result};
use redactor::RedactionRules;
use reqwest::Client;
use server::{CorsConfig, ServerConfig, TlsConfig, ValidatedServerConfig};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: String,
    pub upstream: String,
    pub api_key_env: Option<String>,
    pub audit_dir: Option<PathBuf>,
    pub session_passphrase_env: String,
    pub cors_allowed_origins: Vec<String>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub redaction_rules: RedactionRules,
    session_passphrase_override: Option<String>,
}

impl ProxyConfig {
    pub fn new(
        listen: String,
        upstream: String,
        api_key_env: Option<String>,
        audit_dir: Option<PathBuf>,
        session_passphrase_env: String,
    ) -> Self {
        Self {
            listen,
            upstream,
            api_key_env,
            audit_dir,
            session_passphrase_env,
            cors_allowed_origins: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            redaction_rules: RedactionRules::default(),
            session_passphrase_override: None,
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

    pub fn with_tls(
        mut self,
        cert_path: impl Into<PathBuf>,
        cert_key_path: impl Into<PathBuf>,
    ) -> Self {
        self.tls_cert_path = Some(cert_path.into());
        self.tls_key_path = Some(cert_key_path.into());
        self
    }

    pub fn with_session_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.session_passphrase_override = Some(passphrase.into());
        self
    }

    pub fn with_redaction_rules(mut self, rules: RedactionRules) -> Self {
        self.redaction_rules = rules;
        self
    }

    pub(crate) fn server_config(&self) -> Result<ValidatedServerConfig<Arc<ProxyState>>> {
        let cors = if self.cors_allowed_origins.is_empty() {
            CorsConfig::permissive()
        } else {
            CorsConfig::restricted(self.cors_allowed_origins.clone())
                .with_allowed_methods(["GET", "POST", "OPTIONS"])
        };

        let mut server_config = ServerConfig::new()
            .with_listen_addr(self.listen.clone())
            .with_app_data(ProxyState::from_config(self)?)
            .with_cors(cors);

        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(cert_path), Some(cert_key_path)) => {
                server_config = server_config.with_tls(
                    TlsConfig::new()
                        .with_cert_path(cert_path.clone())
                        .with_cert_key_path(cert_key_path.clone()),
                );
            }
            (None, None) => {}
            _ => anyhow::bail!(
                "proxy TLS configuration requires both tls_cert_path and tls_key_path"
            ),
        }

        server_config
            .build()
            .context("failed to validate proxy server configuration")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyState {
    pub(crate) upstream: String,
    pub(crate) api_key_env: Option<String>,
    pub(crate) audit_dir: Option<PathBuf>,
    pub(crate) session_passphrase_env: String,
    pub(crate) session_passphrase: Option<String>,
    pub(crate) redaction_rules: RedactionRules,
    pub(crate) client: Client,
}

impl ProxyState {
    pub(crate) fn from_config(config: &ProxyConfig) -> Result<Arc<Self>> {
        let session_passphrase = config
            .session_passphrase_override
            .clone()
            .or_else(|| env::var(&config.session_passphrase_env).ok());

        Ok(Arc::new(Self {
            upstream: config.upstream.trim_end_matches('/').to_string(),
            api_key_env: config.api_key_env.clone(),
            audit_dir: config.audit_dir.clone(),
            session_passphrase_env: config.session_passphrase_env.clone(),
            session_passphrase,
            redaction_rules: config.redaction_rules,
            client: Client::builder()
                .build()
                .context("failed to construct proxy HTTP client")?,
        }))
    }
}
