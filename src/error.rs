use axum::{http::{header, StatusCode}, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError { BadRequest(&'static str), Unauthorized, Forbidden, Conflict, Internal }
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Invalid or missing credentials"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Insufficient permissions"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict", "Account already exists"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal error occurred"),
        };
        let mut response = (status, Json(json!({"status":"fail", "code":code, "message":message}))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
        }
        response
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if error.as_database_error().is_some_and(|error| error.is_unique_violation()) { Self::Conflict } else { Self::Internal }
    }
}
