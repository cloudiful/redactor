#[cfg(feature = "proxy")]
use anyhow::Context;
use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use redactor::InputKind;
#[cfg(feature = "proxy")]
use redactor_http::ProxyConfig;
use std::path::PathBuf;

use crate::app_config::{DEFAULT_CONFIG_PATH, load};
use crate::commands;
use crate::settings::{DEFAULT_SESSION_PASSPHRASE_ENV, LlmMode};
use crate::support::resolve_llm_args;

#[derive(Debug, Parser)]
#[command(
    name = "redactor",
    version,
    about = "Redact sensitive values from text"
)]
struct Cli {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Args)]
struct ConfigArgs {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    Redact {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        report: ReportArgs,
        #[command(flatten)]
        input_kind: InputKindArgs,
        #[command(flatten)]
        llm: LlmArgs,
        #[arg(long)]
        session_out: Option<PathBuf>,
        #[command(flatten)]
        session_passphrase: SessionPassphraseArgs,
    },
    Detect {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        report: ReportArgs,
        #[command(flatten)]
        input_kind: InputKindArgs,
        #[command(flatten)]
        llm: LlmArgs,
    },
    Restore {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        patch: Option<PathBuf>,
        #[command(flatten)]
        report: ReportArgs,
        #[command(flatten)]
        session_passphrase: SessionPassphraseArgs,
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        skip_apply_check: bool,
    },
    InspectSession {
        #[arg(long)]
        session: PathBuf,
        #[command(flatten)]
        report: ReportArgs,
    },
    Proxy {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long)]
        api_key_env: Option<String>,
        #[arg(long)]
        audit_dir: Option<PathBuf>,
        #[command(flatten)]
        session_passphrase_env: SessionPassphraseEnvArgs,
    },
}

#[derive(Debug, Clone, Args)]
pub(crate) struct InputArgs {
    pub(crate) input: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct ReportArgs {
    #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
    pub(crate) report: ReportFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum ReportFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct LlmArgs {
    #[arg(long, value_enum)]
    pub(crate) llm: Option<LlmMode>,
    #[arg(long)]
    pub(crate) ollama_url: Option<String>,
    #[arg(long)]
    pub(crate) model: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum InputKindArg {
    Text,
    GitDiff,
}

#[derive(Debug, Clone, Copy, Args)]
pub(crate) struct InputKindArgs {
    #[arg(long, value_enum, default_value_t = InputKindArg::Text)]
    pub(crate) input_kind: InputKindArg,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct SessionPassphraseArgs {
    #[arg(long)]
    pub(crate) session_passphrase: Option<String>,
    #[arg(long, default_value = DEFAULT_SESSION_PASSPHRASE_ENV)]
    pub(crate) session_passphrase_env: String,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct SessionPassphraseEnvArgs {
    #[arg(long)]
    pub(crate) session_passphrase_env: Option<String>,
}

impl From<InputKindArg> for InputKind {
    fn from(value: InputKindArg) -> Self {
        match value {
            InputKindArg::Text => InputKind::Text,
            InputKindArg::GitDiff => InputKind::GitDiff,
        }
    }
}

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    let app_config = load(&cli.config.config)?;

    match cli.command {
        Command::Redact {
            input,
            report,
            input_kind,
            llm,
            session_out,
            session_passphrase,
        } => commands::redact::run(
            input,
            report,
            input_kind,
            resolve_llm_args(llm, &app_config.llm),
            session_out,
            session_passphrase,
        ),
        Command::Detect {
            input,
            report,
            input_kind,
            llm,
        } => commands::detect::run(
            input,
            report,
            input_kind,
            resolve_llm_args(llm, &app_config.llm),
        ),
        Command::Restore {
            input,
            session,
            patch,
            report,
            session_passphrase,
            repo,
            skip_apply_check,
        } => commands::restore::run(
            input,
            session,
            patch,
            report,
            session_passphrase,
            repo,
            skip_apply_check,
        ),
        Command::InspectSession { session, report } => {
            commands::inspect_session::run(session, report)
        }
        Command::Proxy {
            listen,
            upstream,
            api_key_env,
            audit_dir,
            session_passphrase_env,
        } => {
            #[cfg(feature = "proxy")]
            {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .context("failed to create tokio runtime")?;
                let proxy_config = app_config.proxy;
                let mut proxy = ProxyConfig::new(
                    listen.unwrap_or(proxy_config.listen),
                    upstream.unwrap_or(proxy_config.upstream),
                    Some(api_key_env.unwrap_or(proxy_config.api_key_env)),
                    audit_dir.or(proxy_config.audit_dir),
                    session_passphrase_env
                        .session_passphrase_env
                        .unwrap_or(proxy_config.session_passphrase_env),
                )
                .with_cors_allowed_origins(proxy_config.cors_allowed_origins);
                if let (Some(cert_path), Some(cert_key_path)) =
                    (proxy_config.tls_cert_path, proxy_config.tls_key_path)
                {
                    proxy = proxy.with_tls(cert_path, cert_key_path);
                }

                runtime.block_on(redactor_http::run_proxy(proxy))?;
                Ok(())
            }
            #[cfg(not(feature = "proxy"))]
            {
                let _ = (
                    listen,
                    upstream,
                    api_key_env,
                    audit_dir,
                    session_passphrase_env,
                );
                Err(anyhow::anyhow!(
                    "this binary was built without proxy support; rebuild with `--features proxy`"
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Command, DEFAULT_CONFIG_PATH, DEFAULT_SESSION_PASSPHRASE_ENV, InputKindArg,
        ReportFormat,
    };
    use clap::{CommandFactory, Parser};
    use std::path::PathBuf;

    #[test]
    fn redact_defaults_remain_unchanged() {
        let cli = Cli::parse_from(["redactor", "redact"]);
        let config_path = cli.config.config.clone();
        match cli.command {
            Command::Redact {
                report,
                input_kind,
                llm,
                session_passphrase,
                ..
            } => {
                assert_eq!(report.report, ReportFormat::Human);
                assert_eq!(input_kind.input_kind, InputKindArg::Text);
                assert_eq!(llm.llm, None);
                assert_eq!(llm.ollama_url, None);
                assert_eq!(llm.model, None);
                assert_eq!(
                    session_passphrase.session_passphrase_env,
                    DEFAULT_SESSION_PASSPHRASE_ENV
                );
            }
            _ => panic!("expected redact command"),
        }

        assert_eq!(config_path, PathBuf::from(DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn help_output_mentions_config_path_and_session_env() {
        let mut root = Cli::command();
        let mut root_help = Vec::new();
        root.write_long_help(&mut root_help)
            .expect("root help output");
        let root_help = String::from_utf8(root_help).expect("root help utf8");

        assert!(root_help.contains("--config"));
        assert!(root_help.contains(DEFAULT_CONFIG_PATH));

        let mut command = Cli::command();
        let redact = command
            .find_subcommand_mut("redact")
            .expect("redact subcommand");
        let mut help = Vec::new();
        redact.write_long_help(&mut help).expect("help output");
        let help = String::from_utf8(help).expect("utf8 help");

        assert!(help.contains(DEFAULT_SESSION_PASSPHRASE_ENV));
    }
}
