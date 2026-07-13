use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use redactor::InputKind;
use std::path::PathBuf;

use crate::app_config::{DEFAULT_CONFIG_PATH, load};
use crate::commands;
use crate::settings::{DEFAULT_SESSION_PASSPHRASE_ENV, LlmMode};
use crate::support::{resolve_llm_args, resolve_redaction_policy};

mod custom;
use custom::{CustomArgs, RedactCommandParts};

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
        #[command(flatten)]
        redaction: RedactionRuleArgs,
        #[arg(long)]
        custom_string: Vec<String>,
        #[arg(long)]
        custom_string_contains: Vec<String>,
        #[arg(long)]
        custom_string_regex: Vec<String>,
        #[arg(long)]
        custom_string_line: Vec<String>,
        #[arg(long)]
        custom_string_contains_line: Vec<String>,
        #[arg(long)]
        custom_string_regex_line: Vec<String>,
        #[arg(long)]
        custom_file: Vec<String>,
        #[arg(long)]
        source_path: Option<String>,
        #[arg(long)]
        session_out: Option<PathBuf>,
        #[arg(long)]
        permit_out: Option<PathBuf>,
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
        #[command(flatten)]
        redaction: RedactionRuleArgs,
        #[arg(long)]
        custom_string: Vec<String>,
        #[arg(long)]
        custom_string_contains: Vec<String>,
        #[arg(long)]
        custom_string_regex: Vec<String>,
        #[arg(long)]
        custom_string_line: Vec<String>,
        #[arg(long)]
        custom_string_contains_line: Vec<String>,
        #[arg(long)]
        custom_string_regex_line: Vec<String>,
        #[arg(long)]
        custom_file: Vec<String>,
        #[arg(long)]
        source_path: Option<String>,
    },
    Restore {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long)]
        session: PathBuf,
        #[arg(long = "permit", required = true)]
        permits: Vec<PathBuf>,
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
        #[command(flatten)]
        session_passphrase: SessionPassphraseArgs,
    },
    Serve {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        audit_dir: Option<PathBuf>,
        #[arg(long)]
        valkey_url: Option<String>,
        #[arg(long)]
        session_ttl_seconds: Option<u64>,
        #[arg(long)]
        session_key_namespace: Option<String>,
        #[command(flatten)]
        redaction: RedactionRuleArgs,
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

#[derive(Debug, Clone, Args)]
pub(crate) struct RedactionRuleArgs {
    #[arg(long = "redact-secret")]
    pub(crate) secret: Option<bool>,
    #[arg(long = "redact-domain")]
    pub(crate) domain: Option<bool>,
    #[arg(long = "redact-url")]
    pub(crate) url: Option<bool>,
    #[arg(long = "redact-email")]
    pub(crate) email: Option<bool>,
    #[arg(long = "redact-ip")]
    pub(crate) ip: Option<bool>,
    #[arg(long = "redact-cidr")]
    pub(crate) cidr: Option<bool>,
    #[arg(long = "redact-phone")]
    pub(crate) phone: Option<bool>,
    #[arg(long = "redact-person")]
    pub(crate) person: Option<bool>,
    #[arg(long = "redact-organization")]
    pub(crate) organization: Option<bool>,
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
            redaction,
            custom_string,
            custom_string_contains,
            custom_string_regex,
            custom_string_line,
            custom_string_contains_line,
            custom_string_regex_line,
            custom_file,
            source_path,
            session_out,
            permit_out,
            session_passphrase,
        } => {
            let parts = RedactCommandParts {
                custom_string,
                custom_string_contains,
                custom_string_regex,
                custom_string_line,
                custom_string_contains_line,
                custom_string_regex_line,
                custom_file,
                source_path,
            };
            let custom = CustomArgs::from(&parts);
            let policy = resolve_redaction_policy(redaction, app_config.redaction)
                .with_custom_strings(custom.custom_strings)
                .with_custom_files(custom.custom_files);
            policy.validate().map_err(|e| anyhow::anyhow!(e))?;
            commands::redact::run(commands::redact::RedactCommand {
                input,
                report,
                input_kind,
                llm: resolve_llm_args(llm, &app_config.llm),
                policy,
                source_path: custom.source_path,
                session_out,
                permit_out,
                session_passphrase,
            })
        }
        Command::Detect {
            input,
            report,
            input_kind,
            llm,
            redaction,
            custom_string,
            custom_string_contains,
            custom_string_regex,
            custom_string_line,
            custom_string_contains_line,
            custom_string_regex_line,
            custom_file,
            source_path,
        } => {
            let parts = RedactCommandParts {
                custom_string,
                custom_string_contains,
                custom_string_regex,
                custom_string_line,
                custom_string_contains_line,
                custom_string_regex_line,
                custom_file,
                source_path,
            };
            let custom = CustomArgs::from(&parts);
            let policy = resolve_redaction_policy(redaction, app_config.redaction)
                .with_custom_strings(custom.custom_strings)
                .with_custom_files(custom.custom_files);
            policy.validate().map_err(|e| anyhow::anyhow!(e))?;
            commands::detect::run(
                input,
                report,
                input_kind,
                resolve_llm_args(llm, &app_config.llm),
                policy,
                custom.source_path,
            )
        }
        Command::Restore {
            input,
            session,
            permits,
            patch,
            report,
            session_passphrase,
            repo,
            skip_apply_check,
        } => commands::restore::run(commands::restore::RestoreCommand {
            input,
            session,
            permits,
            patch,
            report,
            session_passphrase,
            repo,
            skip_apply_check,
        }),
        Command::InspectSession {
            session,
            report,
            session_passphrase,
        } => commands::inspect_session::run(session, report, session_passphrase),
        Command::Serve {
            listen,
            audit_dir,
            valkey_url,
            session_ttl_seconds,
            session_key_namespace,
            redaction,
            session_passphrase_env,
        } => commands::serve::run(
            commands::serve::ServeCommand {
                listen,
                audit_dir,
                valkey_url,
                session_ttl_seconds,
                session_key_namespace,
                redaction,
                session_passphrase_env,
            },
            app_config,
        ),
    }
}

#[cfg(test)]
mod tests;
