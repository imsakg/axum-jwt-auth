use crate::{error::ApiError, model::RegisterUserSchema};

pub fn normalize_email(email: &str) -> Result<String, ApiError> {
    let email = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else { return Err(ApiError::BadRequest("Invalid email")); };
    if email.len() > 255 || !email.is_ascii() || email.chars().any(char::is_whitespace)
        || email.chars().any(char::is_control) || local.is_empty() || domain.contains('@')
        || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(ApiError::BadRequest("Invalid email"));
    }
    Ok(email)
}

pub fn validate_registration(body: &RegisterUserSchema) -> Result<(String, String), ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest("Name must contain 1 to 100 characters"));
    }
    if !(12..=128).contains(&body.password.len()) {
        return Err(ApiError::BadRequest("Password must contain 12 to 128 bytes"));
    }
    Ok((name.to_owned(), normalize_email(&body.email)?))
}
