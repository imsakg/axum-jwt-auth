pub mod config;
pub mod error;
pub mod handler;
pub mod jwt_auth;
pub mod model;
pub mod password;
pub mod response;
pub mod route;
pub mod validation;

use sqlx::PgPool;

pub struct AppState {
    pub db: PgPool,
    pub env: config::Config,
}
