use crate::error::ApiError;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub jti: Uuid,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
    pub token_use: String,
}

#[derive(Clone)]
pub struct TokenService {
    secret: String,
    issuer: String,
    audience: String,
    ttl: i64,
}
impl TokenService {
    pub fn new(secret: &str, issuer: &str, audience: &str, ttl: i64) -> Result<Self, ApiError> {
        if secret.len() < 32 || ttl <= 0 || issuer.is_empty() || audience.is_empty() { return Err(ApiError::Internal); }
        Ok(Self { secret:secret.into(), issuer:issuer.into(), audience:audience.into(), ttl })
    }
    pub fn issue(&self, user: Uuid, session: Uuid, now: i64) -> Result<String, ApiError> {
        let claims = AccessClaims {
            sub:user, sid:session, jti:Uuid::new_v4(), iat:now, nbf:now,
            exp:now.checked_add(self.ttl).ok_or(ApiError::Internal)?,
            iss:self.issuer.clone(), aud:self.audience.clone(), token_use:"access".into(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(self.secret.as_bytes())).map_err(|_| ApiError::Internal)
    }
    pub fn verify(&self, token: &str) -> Result<AccessClaims, ApiError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        decode::<AccessClaims>(token, &DecodingKey::from_secret(self.secret.as_bytes()), &validation)
            .map(|data| data.claims).map_err(|_| ApiError::Unauthorized)
    }
}
