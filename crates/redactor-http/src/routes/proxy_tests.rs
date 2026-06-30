#[cfg(not(feature = "chat-responses-proxy"))]
use axum::body::{Body, to_bytes};
#[cfg(not(feature = "chat-responses-proxy"))]
use axum::http::{Request, StatusCode};
#[cfg(not(feature = "chat-responses-proxy"))]
use serde::Deserialize;
#[cfg(not(feature = "chat-responses-proxy"))]
use tower::ServiceExt;

#[cfg(not(feature = "chat-responses-proxy"))]
use crate::{ProxyConfig, app};

#[cfg(not(feature = "chat-responses-proxy"))]
#[derive(Debug, Deserialize)]
struct ProxyErrorEnvelope {
    error: ProxyErrorBody,
}

#[cfg(not(feature = "chat-responses-proxy"))]
#[derive(Debug, Deserialize)]
struct ProxyErrorBody {
    message: String,
    kind: String,
}

#[cfg(not(feature = "chat-responses-proxy"))]
#[tokio::test]
async fn chat_proxy_route_returns_feature_disabled() {
    let app = app(ProxyConfig::new(
        "127.0.0.1:0".to_string(),
        "https://openrouter.ai/api/v1".to_string(),
        None,
        None,
        "IGNORED".to_string(),
    ))
    .expect("app");

    let response = app
        .oneshot(
            Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"messages":[]}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: ProxyErrorEnvelope = serde_json::from_slice(&body).expect("json");
    assert_eq!(json.error.kind, "feature_disabled");
    assert!(json.error.message.contains("chat-responses-proxy"));
}

#[cfg(not(feature = "chat-responses-proxy"))]
#[tokio::test]
async fn responses_proxy_route_returns_feature_disabled() {
    let app = app(ProxyConfig::new(
        "127.0.0.1:0".to_string(),
        "https://openrouter.ai/api/v1".to_string(),
        None,
        None,
        "IGNORED".to_string(),
    ))
    .expect("app");

    let response = app
        .oneshot(
            Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"input":[]}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: ProxyErrorEnvelope = serde_json::from_slice(&body).expect("json");
    assert_eq!(json.error.kind, "feature_disabled");
    assert!(json.error.message.contains("chat-responses-proxy"));
}
