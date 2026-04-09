use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use redactor::{LlmConfig, RedactorBuilder};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "redactor",
    version,
    about = "Redact sensitive values from text"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Redact {
        input: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        report: ReportFormat,
        #[arg(long, value_enum, default_value_t = LlmMode::Off)]
        llm: LlmMode,
        #[arg(long, default_value = "http://localhost:11434")]
        ollama_url: String,
        #[arg(long, default_value = "gemma4:e2b")]
        model: String,
    },
    Detect {
        input: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Human)]
        report: ReportFormat,
        #[arg(long, value_enum, default_value_t = LlmMode::Off)]
        llm: LlmMode,
        #[arg(long, default_value = "http://localhost:11434")]
        ollama_url: String,
        #[arg(long, default_value = "gemma4:e2b")]
        model: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum ReportFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum LlmMode {
    Off,
    Ollama,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Redact {
            input,
            report,
            llm,
            ollama_url,
            model,
        } => {
            let text = read_input(input)?;
            let redactor = build_redactor(llm, ollama_url, model);
            let result = redactor.redact(&text).context("failed to redact input")?;
            match report {
                ReportFormat::Human => print!("{}", result.redacted_text),
                ReportFormat::Json => print!("{}", serde_json::to_string_pretty(&result)?),
            }
        }
        Command::Detect {
            input,
            report,
            llm,
            ollama_url,
            model,
        } => {
            let text = read_input(input)?;
            let redactor = build_redactor(llm, ollama_url, model);
            let findings = redactor
                .detect(&text)
                .context("failed to detect sensitive values")?;
            match report {
                ReportFormat::Human => {
                    for finding in findings {
                        println!(
                            "{} [{}..{}] {} ({:?})",
                            finding.kind.label(),
                            finding.start,
                            finding.end,
                            finding.match_text,
                            finding.source
                        );
                    }
                }
                ReportFormat::Json => print!("{}", serde_json::to_string_pretty(&findings)?),
            }
        }
    }

    Ok(())
}

fn build_redactor(llm: LlmMode, ollama_url: String, model: String) -> redactor::Redactor {
    let builder = RedactorBuilder::new();
    match llm {
        LlmMode::Off => builder.build(),
        LlmMode::Ollama => builder
            .with_llm(LlmConfig {
                base_url: ollama_url,
                model,
            })
            .build(),
    }
}

fn read_input(input: Option<PathBuf>) -> Result<String> {
    match input {
        Some(path) if path.as_os_str() == "-" => read_stdin(),
        Some(path) => fs::read_to_string(path).context("failed to read input file"),
        None => read_stdin(),
    }
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read stdin")?;
    Ok(buffer)
}
