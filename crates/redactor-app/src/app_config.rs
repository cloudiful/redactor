use anyhow::{Context, Result};
use config::{ConfigSource, ReadOptions, read};
use redactor::RedactionPolicy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::settings::{
    DEFAULT_OLLAMA_MODEL, DEFAULT_OLLAMA_URL, DEFAULT_PROXY_LISTEN, DEFAULT_PROXY_UPSTREAM,
    DEFAULT_SESSION_PASSPHRASE_ENV, DEFAULT_UPSTREAM_API_KEY_ENV, LlmMode,
};

pub(crate) const CONFIG_ENV_PREFIX: &str = "REDACTOR_";
pub(crate) const DEFAULT_CONFIG_PATH: &str = "redactor.toml";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub(crate) struct AppConfig {
    pub(crate) llm: LlmSettings,
    pub(crate) redaction: RedactionPolicy,
    pub(crate) proxy: ProxySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct LlmSettings {
    pub(crate) mode: LlmMode,
    pub(crate) ollama_url: String,
    pub(crate) model: String,
}

impl Default for LlmSettings {
    fn default() -> Self {
        Self {
            mode: LlmMode::Off,
            ollama_url: DEFAULT_OLLAMA_URL.to_string(),
            model: DEFAULT_OLLAMA_MODEL.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct ProxySettings {
    pub(crate) listen: String,
    pub(crate) upstream: String,
    pub(crate) api_key_env: String,
    pub(crate) audit_dir: Option<PathBuf>,
    pub(crate) session_passphrase_env: String,
    pub(crate) valkey_url: Option<String>,
    pub(crate) session_ttl_seconds: Option<u64>,
    pub(crate) session_key_prefix: Option<String>,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) tls_cert_path: Option<PathBuf>,
    pub(crate) tls_key_path: Option<PathBuf>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            listen: DEFAULT_PROXY_LISTEN.to_string(),
            upstream: DEFAULT_PROXY_UPSTREAM.to_string(),
            api_key_env: DEFAULT_UPSTREAM_API_KEY_ENV.to_string(),
            audit_dir: None,
            session_passphrase_env: DEFAULT_SESSION_PASSPHRASE_ENV.to_string(),
            valkey_url: None,
            session_ttl_seconds: None,
            session_key_prefix: None,
            cors_allowed_origins: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

pub(crate) fn load(path: impl AsRef<Path>) -> Result<AppConfig> {
    let path = path.as_ref();
    read(
        ConfigFileSource(path.to_path_buf()),
        Some(ReadOptions::with_env_prefix(CONFIG_ENV_PREFIX)),
    )
    .with_context(|| format!("failed to load application config from {}", path.display()))
}

struct ConfigFileSource(PathBuf);

impl ConfigSource for ConfigFileSource {
    fn source_name(&self) -> String {
        self.0.display().to_string()
    }

    fn read_value(&mut self) -> io::Result<Option<serde_json::Value>> {
        if self.0.is_file() {
            let text = fs::read_to_string(&self.0)?;
            let value = toml::from_str::<toml::Value>(&text).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse config file {}: {error}", self.0.display()),
                )
            })?;
            serde_json::to_value(value).map(Some).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to convert config file {} to json value: {error}",
                        self.0.display()
                    ),
                )
            })
        } else {
            Ok(None)
        }
    }

    fn write_config<T>(&mut self, config: &T) -> io::Result<()>
    where
        T: serde::Serialize,
    {
        if let Some(parent) = self.0.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = toml::to_string_pretty(config).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to serialize default config for {}: {error}",
                    self.0.display()
                ),
            )
        })?;
        fs::write(&self.0, encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, CONFIG_ENV_PREFIX, DEFAULT_CONFIG_PATH, load};
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "redactor-app-config-{}-{}-{DEFAULT_CONFIG_PATH}",
            std::process::id(),
            unique
        ))
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env_vars(vars: &[(String, String)], test: impl FnOnce()) {
        let _guard = env_lock().lock().expect("env lock");
        let previous: Vec<(String, Option<OsString>)> = vars
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
            .collect();

        for (key, value) in vars {
            unsafe {
                std::env::set_var(key, value);
            }
        }

        test();

        for (key, value) in previous {
            match value {
                Some(value) => unsafe {
                    std::env::set_var(&key, value);
                },
                None => unsafe {
                    std::env::remove_var(&key);
                },
            }
        }
    }

    fn without_env_vars(keys: &[String], test: impl FnOnce()) {
        let _guard = env_lock().lock().expect("env lock");
        let previous: Vec<(String, Option<OsString>)> = keys
            .iter()
            .map(|key| (key.clone(), std::env::var_os(key)))
            .collect();

        for key in keys {
            unsafe {
                std::env::remove_var(key);
            }
        }

        test();

        for (key, value) in previous {
            match value {
                Some(value) => unsafe {
                    std::env::set_var(&key, value);
                },
                None => unsafe {
                    std::env::remove_var(&key);
                },
            }
        }
    }

    #[test]
    fn load_creates_default_config_file() {
        let path = temp_path();
        let keys = vec![
            format!("{CONFIG_ENV_PREFIX}LLM__MODE"),
            format!("{CONFIG_ENV_PREFIX}LLM__MODEL"),
            format!("{CONFIG_ENV_PREFIX}PROXY__LISTEN"),
        ];

        let config = {
            let mut loaded = None;
            without_env_vars(&keys, || {
                loaded = Some(load(&path).expect("load config"));
            });
            loaded.expect("config loaded")
        };

        assert_eq!(config, AppConfig::default());
        assert!(path.exists());

        let written = fs::read_to_string(&path).expect("read config");
        assert!(written.contains("[llm]"));
        assert!(written.contains("[proxy]"));
    }

    #[test]
    fn env_overrides_nested_settings() {
        let path = temp_path();
        let vars = vec![
            (
                format!("{CONFIG_ENV_PREFIX}LLM__MODE"),
                "\"ollama\"".to_string(),
            ),
            (
                format!("{CONFIG_ENV_PREFIX}LLM__MODEL"),
                "\"qwen3:14b\"".to_string(),
            ),
            (
                format!("{CONFIG_ENV_PREFIX}PROXY__LISTEN"),
                "\"0.0.0.0:9900\"".to_string(),
            ),
            (
                format!("{CONFIG_ENV_PREFIX}PROXY__VALKEY_URL"),
                "\"redis://127.0.0.1:6379/0\"".to_string(),
            ),
        ];

        with_env_vars(&vars, || {
            let config = load(&path).expect("load config");
            assert_eq!(config.llm.mode, super::LlmMode::Ollama);
            assert_eq!(config.llm.model, "qwen3:14b");
            assert_eq!(config.proxy.listen, "0.0.0.0:9900");
            assert_eq!(
                config.proxy.valkey_url.as_deref(),
                Some("redis://127.0.0.1:6379/0")
            );
        });
    }
}
