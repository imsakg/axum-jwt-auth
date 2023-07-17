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

#[derive(sqlx::FromRow)]
struct Family { user_id: Uuid, expires_at: DateTime<Utc>, revoked_at: Option<DateTime<Utc>> }

pub async fn rotate_session(state: &AppState, secret: &str) -> Result<TokenPair, ApiError> {
    let hash=crate::refresh::refresh_digest(secret)?;
    let mut transaction=state.db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED").execute(&mut *transaction).await?;
    let family:Uuid=sqlx::query_scalar("SELECT family_id FROM refresh_tokens WHERE token_hash=$1")
        .bind(&hash).fetch_optional(&mut *transaction).await?.ok_or(ApiError::Unauthorized)?;
    // Serialize all rotations and revocations for this family, then re-read use state.
    let row=sqlx::query_as::<_, Family>("SELECT user_id,expires_at,revoked_at FROM session_families WHERE id=$1 FOR UPDATE")
        .bind(family).fetch_optional(&mut *transaction).await?.ok_or(ApiError::Unauthorized)?;
    let used:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT used_at FROM refresh_tokens WHERE token_hash=$1")
        .bind(&hash).fetch_one(&mut *transaction).await?;
    if used.is_some() {
        sqlx::query("UPDATE session_families SET revoked_at=COALESCE(revoked_at,NOW()) WHERE id=$1")
            .bind(family).execute(&mut *transaction).await?;
        // Commit before returning 401: rolling back here would erase replay defense.
        transaction.commit().await?;
        return Err(ApiError::Unauthorized);
    }
    if row.revoked_at.is_some() || row.expires_at<=Utc::now() { return Err(ApiError::Unauthorized); }
    let next=generate_refresh_token();
    let pair=token_pair(state,row.user_id,family,next.secret,row.expires_at)?;
    sqlx::query("UPDATE refresh_tokens SET used_at=NOW() WHERE token_hash=$1").bind(hash).execute(&mut *transaction).await?;
    sqlx::query("INSERT INTO refresh_tokens (family_id,token_hash) VALUES ($1,$2)")
        .bind(family).bind(next.digest).execute(&mut *transaction).await?;
    transaction.commit().await?;
    Ok(pair)
}
