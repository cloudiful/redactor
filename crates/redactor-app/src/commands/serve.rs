use anyhow::Result;
use std::path::PathBuf;

use crate::app_config::AppConfig;
use crate::cli::{RedactionRuleArgs, SessionPassphraseEnvArgs};

pub(crate) struct ServeCommand {
    pub(crate) listen: Option<String>,
    pub(crate) audit_dir: Option<PathBuf>,
    pub(crate) valkey_url: Option<String>,
    pub(crate) session_ttl_seconds: Option<u64>,
    pub(crate) session_key_namespace: Option<String>,
    pub(crate) redaction: RedactionRuleArgs,
    pub(crate) session_passphrase_env: SessionPassphraseEnvArgs,
}

pub(crate) fn run(command: ServeCommand, app_config: AppConfig) -> Result<()> {
    #[cfg(feature = "http")]
    {
        use anyhow::Context;
        use redactor_http::HttpServerConfig;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to create tokio runtime")?;
        let http_config = app_config.http;
        let mut server = HttpServerConfig::new(
            command.listen.unwrap_or(http_config.listen),
            command.audit_dir.or(http_config.audit_dir),
            command
                .session_passphrase_env
                .session_passphrase_env
                .unwrap_or(http_config.session_passphrase_env),
        )
        .with_redaction_policy(crate::support::resolve_redaction_policy(
            command.redaction,
            app_config.redaction,
        ))
        .with_cors_allowed_origins(http_config.cors_allowed_origins);
        if let (Some(cert_path), Some(cert_key_path)) =
            (http_config.tls_cert_path, http_config.tls_key_path)
        {
            server = server.with_tls(cert_path, cert_key_path);
        }
        let valkey_url = command.valkey_url.or(http_config.valkey_url);
        let ttl = command
            .session_ttl_seconds
            .or(http_config.session_ttl_seconds);
        let namespace = command
            .session_key_namespace
            .or(http_config.session_key_namespace);
        if let Some(valkey_url) = valkey_url {
            #[cfg(feature = "valkey-session-store")]
            {
                server = runtime.block_on(server.with_valkey_session_store(
                    &valkey_url,
                    namespace.as_deref(),
                    ttl,
                ))?;
            }
            #[cfg(not(feature = "valkey-session-store"))]
            {
                let _ = (namespace, ttl);
                return Err(anyhow::anyhow!(
                    "Valkey configuration requires `--features valkey-session-store`"
                ));
            }
        }
        runtime.block_on(redactor_http::run_server(server))
    }
    #[cfg(not(feature = "http"))]
    {
        let _ = (command, app_config);
        Err(anyhow::anyhow!(
            "this binary was built without HTTP support; rebuild with `--features http`"
        ))
    }
}
