use clap::{CommandFactory, Parser};
use std::path::PathBuf;

use super::{
    Cli, Command, DEFAULT_CONFIG_PATH, DEFAULT_SESSION_PASSPHRASE_ENV, InputKindArg, ReportFormat,
};

#[test]
fn redact_defaults_remain_unchanged() {
    let cli = Cli::parse_from(["redactor", "redact"]);
    let config_path = cli.config.config.clone();
    match cli.command {
        Command::Redact {
            report,
            input_kind,
            llm,
            redaction,
            session_passphrase,
            ..
        } => {
            assert_eq!(report.report, ReportFormat::Human);
            assert_eq!(input_kind.input_kind, InputKindArg::Text);
            assert_eq!(llm.llm, None);
            assert_eq!(llm.ollama_url, None);
            assert_eq!(llm.model, None);
            assert_eq!(redaction.domain, None);
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
