use redactor::{InputKind, RedactionPolicy, RestoreResult, SessionSummary};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedactTextRequest {
    pub(crate) text: String,
    #[serde(default)]
    pub(crate) input_kind: InputKind,
    pub(crate) redaction: Option<RedactionPolicy>,
    pub(crate) source_path: Option<String>,
    pub(crate) external_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RedactTextResponse {
    pub(crate) redacted_text: String,
    pub(crate) encrypted_session: String,
    pub(crate) restore_permit: String,
    pub(crate) session_summary: SessionSummary,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreTextRequest {
    pub(crate) text: String,
    pub(crate) encrypted_session: Option<String>,
    pub(crate) external_id: Option<String>,
    pub(crate) restore_permits: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InspectSessionRequest {
    pub(crate) encrypted_session: String,
}

pub(crate) type RestoreTextResponse = RestoreResult;
