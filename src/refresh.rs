use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use crate::error::ApiError;

// Deliberately no Debug/Serialize implementation: plaintext credentials are not logs.
pub struct RefreshSecret { pub secret: String, pub digest: String }
fn digest(secret: &str) -> String {
    Sha256::digest(secret.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn generate_refresh_token() -> RefreshSecret {
    let mut bytes = [0u8;32]; OsRng.fill_bytes(&mut bytes);
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    RefreshSecret { digest:digest(&secret), secret }
}
pub fn refresh_digest(secret: &str) -> Result<String, ApiError> {
    if secret.len() != 43 { return Err(ApiError::Unauthorized); }
    let bytes = URL_SAFE_NO_PAD.decode(secret).map_err(|_| ApiError::Unauthorized)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != secret { return Err(ApiError::Unauthorized); }
    Ok(digest(secret))
}
