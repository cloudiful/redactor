use std::sync::Arc;

#[cfg(not(feature = "chat-responses-proxy"))]
use crate::http_error::error_response;
use crate::state::ProxyState;
use axum::body::{Body, Bytes};
use axum::extract::State;
#[cfg(not(feature = "chat-responses-proxy"))]
use axum::http::StatusCode;
use axum::http::{HeaderMap, Response};

pub(crate) async fn proxy_chat(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    #[cfg(feature = "chat-responses-proxy")]
    {
        let ctx = state.chat_responses_proxy_context();
        redactor_chat_responses_proxy::proxy_chat(&ctx, headers, body).await
    }

    #[cfg(not(feature = "chat-responses-proxy"))]
    {
        let _ = (state, headers, body);
        feature_disabled_response()
    }
}

pub(crate) async fn proxy_responses(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    #[cfg(feature = "chat-responses-proxy")]
    {
        let ctx = state.chat_responses_proxy_context();
        redactor_chat_responses_proxy::proxy_responses(&ctx, headers, body).await
    }

    #[cfg(not(feature = "chat-responses-proxy"))]
    {
        let _ = (state, headers, body);
        feature_disabled_response()
    }
}

#[cfg(not(feature = "chat-responses-proxy"))]
fn feature_disabled_response() -> Response<Body> {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "chat/responses proxy support is disabled in this build; rebuild with `--features chat-responses-proxy`".to_string(),
        "feature_disabled",
    )
}
