use anyhow::{Context, Result};
use redactor::{LlmConfig, RedactionPolicy, RedactionRules, Redactor, RedactorBuilder};
use std::env;

use crate::app_config::LlmSettings;
use crate::cli::{LlmArgs, RedactionRuleArgs, SessionPassphraseArgs};
use crate::settings::LlmMode;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedLlmArgs {
    pub(crate) llm: LlmMode,
    pub(crate) ollama_url: String,
    pub(crate) model: String,
}

pub(crate) fn resolve_redaction_policy(
    overrides: RedactionRuleArgs,
    defaults: RedactionPolicy,
) -> RedactionPolicy {
    let rules = RedactionRules {
        secret: overrides.secret.unwrap_or(defaults.rules.secret),
        domain: overrides.domain.unwrap_or(defaults.rules.domain),
        url: overrides.url.unwrap_or(defaults.rules.url),
        email: overrides.email.unwrap_or(defaults.rules.email),
        ip: overrides.ip.unwrap_or(defaults.rules.ip),
        cidr: overrides.cidr.unwrap_or(defaults.rules.cidr),
        phone: overrides.phone.unwrap_or(defaults.rules.phone),
        person: overrides.person.unwrap_or(defaults.rules.person),
        organization: overrides
            .organization
            .unwrap_or(defaults.rules.organization),
    };
    RedactionPolicy {
        rules,
        custom_strings: defaults.custom_strings,
        custom_files: defaults.custom_files,
    }
}

pub(crate) fn resolve_llm_args(llm: LlmArgs, defaults: &LlmSettings) -> ResolvedLlmArgs {
    ResolvedLlmArgs {
        llm: llm.llm.unwrap_or(defaults.mode),
        ollama_url: llm
            .ollama_url
            .unwrap_or_else(|| defaults.ollama_url.clone()),
        model: llm.model.unwrap_or_else(|| defaults.model.clone()),
    }
}

pub(crate) fn build_redactor(llm: ResolvedLlmArgs, policy: RedactionPolicy) -> Result<Redactor> {
    let builder = RedactorBuilder::new().with_redaction_policy(policy);
    let redactor = match llm.llm {
        LlmMode::Off => builder.try_build(),
        LlmMode::Ollama => builder
            .with_llm(LlmConfig {
                base_url: llm.ollama_url,
                model: llm.model,
            })
            .try_build(),
    }?;
    Ok(redactor)
}

pub(crate) fn resolve_passphrase(direct: Option<String>, env_name: &str) -> Result<String> {
    if let Some(passphrase) = direct {
        return Ok(passphrase);
    }

    env::var(env_name).with_context(|| {
        format!("missing session passphrase; pass --session-passphrase or set {env_name}")
    })
}

pub(crate) fn resolve_session_passphrase(args: SessionPassphraseArgs) -> Result<String> {
    resolve_passphrase(args.session_passphrase, &args.session_passphrase_env)
}
