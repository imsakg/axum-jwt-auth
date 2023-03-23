use std::fmt;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
    pub issuer: String,
    pub audience: String,
    pub bind_address: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"[REDACTED]")
            .field("jwt_secret", &"[REDACTED]")
            .field("bind_address", &self.bind_address)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, &'static str> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, &'static str> {
        let database_url = get("DATABASE_URL").ok_or("missing DATABASE_URL")?;
        if !database_url.starts_with("postgres://") && !database_url.starts_with("postgresql://") {
            return Err("invalid DATABASE_URL");
        }
        let jwt_secret = get("JWT_SECRET").ok_or("missing JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err("JWT_SECRET must contain at least 32 bytes");
        }
        let ttl = |key: &str, default: i64, max: i64| -> Result<i64, &'static str> {
            let message = match key {
                "ACCESS_TTL_SECONDS" => "invalid ACCESS_TTL_SECONDS",
                _ => "invalid REFRESH_TTL_SECONDS",
            };
            let n = get(key)
                .unwrap_or_else(|| default.to_string())
                .parse::<i64>()
                .map_err(|_| message)?;
            if !(1..=max).contains(&n) {
                return Err(message);
            }
            Ok(n)
        };
        let access_ttl_seconds = ttl("ACCESS_TTL_SECONDS", 900_i64, 86400)?;
        let refresh_ttl_seconds = ttl("REFRESH_TTL_SECONDS", 604800_i64, 2592000)?;
        if refresh_ttl_seconds <= access_ttl_seconds {
            return Err("refresh lifetime must exceed access lifetime");
        }
        let issuer = get("JWT_ISSUER").unwrap_or_else(|| "axum-jwt-auth".into());
        let audience = get("JWT_AUDIENCE").unwrap_or_else(|| "axum-jwt-clients".into());
        if issuer.is_empty() || audience.is_empty() {
            return Err("JWT issuer and audience must be non-empty");
        }
        let bind_address = get("BIND_ADDRESS").unwrap_or_else(|| "127.0.0.1:8000".into());
        bind_address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "invalid BIND_ADDRESS")?;
        Ok(Self {
            database_url,
            jwt_secret,
            access_ttl_seconds,
            refresh_ttl_seconds,
            issuer,
            audience,
            bind_address,
        })
    }
}
