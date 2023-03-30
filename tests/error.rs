use axum::{http::StatusCode, response::IntoResponse};
use axum_jwt_auth::error::ApiError;
#[tokio::test]
async fn errors_have_stable_status_codes_and_safe_messages() {
    for (error, status, code) in [
        (ApiError::Unauthorized, StatusCode::UNAUTHORIZED, "unauthorized"),
        (ApiError::Forbidden, StatusCode::FORBIDDEN, "forbidden"),
        (ApiError::Conflict, StatusCode::CONFLICT, "conflict"),
        (ApiError::Internal, StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    ] {
        let response = error.into_response();
        assert_eq!(response.status(), status);
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], code);
        assert_eq!(body["status"], "fail");
        assert!(!String::from_utf8(bytes.to_vec()).unwrap().contains("SELECT"));
    }
}
