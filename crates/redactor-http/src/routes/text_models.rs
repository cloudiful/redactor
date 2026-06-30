use redactor::{InputKind, RedactionPolicy, SessionSummary};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub(crate) struct RedactTextRequest {
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) input_kind: InputKind,
    pub(crate) redaction: Option<RedactionPolicy>,
    pub(crate) source_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RedactTextResponse {
    pub(crate) redacted_text: String,
    pub(crate) encrypted_session: String,
    pub(crate) session_summary: SessionSummary,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RestoreTextRequest {
    pub(crate) text: String,
    pub(crate) encrypted_session: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InspectSessionRequest {
    pub(crate) encrypted_session: String,
}
