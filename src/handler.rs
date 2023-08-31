use std::sync::Arc;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde_json::json;
use crate::{error::ApiError, model::{LoginUserSchema, RegisterUserSchema, User}, response::FilteredUser, AppState};

pub async fn health_checker_handler() -> impl IntoResponse {
    Json(json!({"status":"success", "message":"JWT Authentication in Rust using Axum, Postgres, and SQLX"}))
}

pub async fn register_user_handler(State(data): State<Arc<AppState>>, Json(body): Json<RegisterUserSchema>) -> Result<impl IntoResponse, ApiError> {
    let (name,email)=crate::validation::validate_registration(&body)?;
    let password=body.password;
    let hash=tokio::task::spawn_blocking(move || crate::password::hash_password(&password)).await.map_err(|_| ApiError::Internal)??;
    let user=sqlx::query_as::<_,User>("INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING *")
        .bind(name).bind(email).bind(hash).fetch_one(&data.db).await?;
    Ok((StatusCode::CREATED,Json(json!({"status":"success","data":{"user":filter_user_record(&user)}}))))
}

pub async fn login_user_handler(State(data): State<Arc<AppState>>, Json(body): Json<LoginUserSchema>) -> Result<impl IntoResponse,ApiError> {
    let email=crate::validation::normalize_email(&body.email).map_err(|_| ApiError::Unauthorized)?;
    if body.password.is_empty() || body.password.len()>128 { return Err(ApiError::Unauthorized); }
    let user=sqlx::query_as::<_,User>("SELECT * FROM users WHERE email=$1").bind(email).fetch_optional(&data.db).await?.ok_or(ApiError::Unauthorized)?;
    let password=body.password; let hash=user.password;
    let valid=tokio::task::spawn_blocking(move || crate::password::verify_password(&password,&hash)).await.map_err(|_| ApiError::Internal)?;
    if !valid { return Err(ApiError::Unauthorized); }
    Ok(Json(crate::session::issue_session(&data,user.id).await?))
}

pub async fn refresh_handler(State(data): State<Arc<AppState>>, Json(body): Json<crate::model::RefreshSchema>) -> Result<Json<crate::session::TokenPair>,ApiError> {
    Ok(Json(crate::session::rotate_session(&data,&body.refresh_token).await?))
}

pub async fn logout_handler(State(data): State<Arc<AppState>>, Extension(claims): Extension<crate::token::AccessClaims>) -> Result<StatusCode,ApiError> {
    sqlx::query("UPDATE session_families SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=$1 AND user_id=$2")
        .bind(claims.sid).bind(claims.sub).execute(&data.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_me_handler(Extension(user): Extension<User>) -> impl IntoResponse {
    Json(json!({"status":"success","data":{"user":filter_user_record(&user)}}))
}

pub async fn list_users_handler(State(data): State<Arc<AppState>>) -> Result<impl IntoResponse,ApiError> {
    let users=sqlx::query_as::<_,User>("SELECT * FROM users ORDER BY created_at,id LIMIT 100").fetch_all(&data.db).await?;
    let users:Vec<_>=users.iter().map(filter_user_record).collect();
    Ok(Json(json!({"status":"success","data":{"users":users}})))
}

pub(crate) fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser { id:user.id.to_string(),email:user.email.clone(),name:user.name.clone(),photo:user.photo.clone(),role:user.role.clone(),verified:user.verified,createdAt:user.created_at.unwrap(),updatedAt:user.updated_at.unwrap() }
}
