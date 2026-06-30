use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";
pub(crate) const DEFAULT_OLLAMA_MODEL: &str = "gemma4:e2b";
pub(crate) const DEFAULT_PROXY_LISTEN: &str = "127.0.0.1:8787";
pub(crate) const DEFAULT_SESSION_PASSPHRASE_ENV: &str = "REDACTOR_SESSION_PASSPHRASE";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LlmMode {
    Off,
    Ollama,
}
