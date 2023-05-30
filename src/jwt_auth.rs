use std::sync::Arc;
use axum::{body::Body, extract::State, http::{header, HeaderMap, Request}, middleware::Next, response::Response};
use crate::{error::ApiError, model::User, AppState};

pub fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(ApiError::Unauthorized)?;
    if values.next().is_some() { return Err(ApiError::Unauthorized); }
    let (scheme, token) = value.to_str().map_err(|_| ApiError::Unauthorized)?.split_once(' ').ok_or(ApiError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || token.len() > 8192 || token.chars().any(char::is_whitespace) {
        return Err(ApiError::Unauthorized);
    }
    Ok(token)
}

pub async fn auth(State(data): State<Arc<AppState>>, mut request: Request<Body>, next: Next) -> Result<Response, ApiError> {
    let claims = data.env.token_service()?.verify(bearer_token(request.headers())?)?;
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id=$1")
        .bind(claims.sub).fetch_optional(&data.db).await?.ok_or(ApiError::Unauthorized)?;
    request.extensions_mut().insert(user);
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
