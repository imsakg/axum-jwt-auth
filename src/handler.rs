use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, Response, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde_json::json;

use crate::{
    model::{LoginUserSchema, RegisterUserSchema, TokenClaims, User},
    response::FilteredUser,
    AppState,
};

pub async fn health_checker_handler() -> impl IntoResponse {
    const MESSAGE: &str = "JWT Authentication in Rust using Axum, Postgres, and SQLX";

    let json_response = serde_json::json!({
        "status": "success",
        "message": MESSAGE
    });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, crate::error::ApiError> {
    use crate::{error::ApiError, password::hash_password, validation::validate_registration};
    let (name, email) = validate_registration(&body)?;
    let password = body.password;
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await.map_err(|_| ApiError::Internal)??;
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING *",
    ).bind(name).bind(email).bind(hash).fetch_one(&data.db).await?;
    Ok((StatusCode::CREATED, Json(json!({"status":"success", "data":{"user":filter_user_record(&user)}}))))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, crate::error::ApiError> {
    use crate::{error::ApiError, password::verify_password, validation::normalize_email};
    let email = normalize_email(&body.email).map_err(|_| ApiError::Unauthorized)?;
    if body.password.is_empty() || body.password.len() > 128 { return Err(ApiError::Unauthorized); }
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email).fetch_optional(&data.db).await?.ok_or(ApiError::Unauthorized)?;
    let password = body.password;
    let hash = user.password;
    let valid = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await.map_err(|_| ApiError::Internal)?;
    if !valid { return Err(ApiError::Unauthorized); }
    Ok(Json(crate::session::issue_session(&data, user.id).await?))
}

pub async fn refresh_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<crate::model::RefreshSchema>,
) -> Result<Json<crate::session::TokenPair>, crate::error::ApiError> {
    Ok(Json(crate::session::rotate_session(&data, &body.refresh_token).await?))
}

pub async fn logout_handler() -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());
    Ok(response)
}

pub async fn get_me_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let json_response = serde_json::json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&user)
        })
    });

    Ok(Json(json_response))
}

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}
