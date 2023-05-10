use crate::error::ApiError;
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    keys: BTreeMap<String, String>,
    active_kid: String,
    issuer: String,
    audience: String,
    ttl: i64,
}
impl TokenService {
    pub fn new(secret: &str, issuer: &str, audience: &str, ttl: i64) -> Result<Self, ApiError> {
        Self::from_keys("default", BTreeMap::from([("default".into(),secret.into())]), issuer,audience,ttl)
    }
    pub fn from_keys(active_kid: &str, keys: BTreeMap<String,String>, issuer: &str, audience: &str, ttl: i64) -> Result<Self, ApiError> {
        if !keys.contains_key(active_kid) || keys.iter().any(|(kid,key)| kid.is_empty() || kid.len()>64 || key.len()<32)
            || !(1..=86400).contains(&ttl) || issuer.is_empty() || audience.is_empty() { return Err(ApiError::Internal); }
        Ok(Self { keys, active_kid:active_kid.into(), issuer:issuer.into(), audience:audience.into(), ttl })
    }
    pub fn issue(&self, user: Uuid, session: Uuid, now: i64) -> Result<String, ApiError> {
        let claims = AccessClaims {
            sub:user, sid:session, jti:Uuid::new_v4(), iat:now, nbf:now,
            exp:now.checked_add(self.ttl).ok_or(ApiError::Internal)?,
            iss:self.issuer.clone(), aud:self.audience.clone(), token_use:"access".into(),
        };
        let mut header = Header::new(Algorithm::HS256); header.kid=Some(self.active_kid.clone());
        encode(&header, &claims, &EncodingKey::from_secret(self.keys[&self.active_kid].as_bytes())).map_err(|_| ApiError::Internal)
    }
    pub fn verify(&self, token: &str) -> Result<AccessClaims, ApiError> {
        let header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
        let kid = header.kid.ok_or(ApiError::Unauthorized)?;
        let key = self.keys.get(&kid).ok_or(ApiError::Unauthorized)?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        decode::<AccessClaims>(token, &DecodingKey::from_secret(key.as_bytes()), &validation)
            .map(|data| data.claims).map_err(|_| ApiError::Unauthorized)
    }
}
