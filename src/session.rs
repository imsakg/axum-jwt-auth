use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;
use crate::{error::ApiError, refresh::generate_refresh_token, AppState};

// Credentials deliberately do not implement Debug.
#[derive(Serialize)]
pub struct TokenPair {
    pub status: &'static str,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}
fn token_pair(state: &AppState, user: Uuid, family: Uuid, refresh: String, expires: DateTime<Utc>) -> Result<TokenPair, ApiError> {
    let now=Utc::now().timestamp();
    let ttl=state.env.access_ttl_seconds.min(expires.timestamp()-now);
    if ttl<=0 { return Err(ApiError::Unauthorized); }
    let service=crate::token::TokenService::from_keys(&state.env.active_kid,state.env.jwt_keys.clone(),&state.env.issuer,&state.env.audience,ttl)?;
    Ok(TokenPair { status:"success", access_token:service.issue(user,family,now)?,refresh_token:refresh,token_type:"Bearer",expires_in:ttl })
}
pub async fn issue_session(state: &AppState, user: Uuid) -> Result<TokenPair, ApiError> {
    let family=Uuid::new_v4();
    let secret=generate_refresh_token();
    let expires=Utc::now()+Duration::seconds(state.env.refresh_ttl_seconds);
    let pair=token_pair(state,user,family,secret.secret,expires)?;
    let mut transaction=state.db.begin().await?;
    sqlx::query("INSERT INTO session_families (id,user_id,expires_at) VALUES ($1,$2,$3)")
        .bind(family).bind(user).bind(expires).execute(&mut *transaction).await?;
    sqlx::query("INSERT INTO refresh_tokens (family_id,token_hash) VALUES ($1,$2)")
        .bind(family).bind(secret.digest).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(pair)
}
