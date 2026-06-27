use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::error;

#[derive(Serialize)]
struct ApiErrorBody {
    error: ApiErrorDetail,
}

#[derive(Serialize)]
struct ApiErrorDetail {
    code: String,
    message: String,
}

pub(crate) fn api_error(status: StatusCode, message: impl Into<String>) -> Response {
    let message = message.into();
    let code = error_code(&message);
    (
        status,
        Json(ApiErrorBody {
            error: ApiErrorDetail { code, message },
        }),
    )
        .into_response()
}

pub(crate) fn api_server_error(err: impl std::fmt::Display) -> Response {
    error!("server error: {}", err);
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "server error")
}

fn error_code(message: &str) -> String {
    let mut out = String::new();
    let mut previous_separator = false;
    for ch in message.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator && !out.is_empty() {
            out.push('_');
            previous_separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "error".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::header::CONTENT_TYPE;

    #[test]
    fn error_code_normalizes_message() {
        assert_eq!(error_code("tenant not allowed"), "tenant_not_allowed");
        assert_eq!(
            error_code("v3 request missing key_id"),
            "v3_request_missing_key_id"
        );
    }

    #[tokio::test]
    async fn api_error_returns_json_body() {
        let response = api_error(StatusCode::FORBIDDEN, "admin required");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "admin_required");
        assert_eq!(value["error"]["message"], "admin required");
    }
}
