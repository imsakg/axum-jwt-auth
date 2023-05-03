use axum_jwt_auth::token::TokenService;
use uuid::Uuid;
const KEY: &str = "a-long-test-key-with-at-least-32-bytes";
#[test]
fn access_claims_round_trip_and_tampering_is_rejected() {
    let tokens = TokenService::new(KEY, "issuer", "clients", 900).unwrap();
    let user = Uuid::new_v4(); let family = Uuid::new_v4();
    let jwt = tokens.issue(user, family, chrono::Utc::now().timestamp()).unwrap();
    let claims = tokens.verify(&jwt).unwrap();
    assert_eq!(claims.sub, user); assert_eq!(claims.sid, family);
    let mut parts: Vec<String> = jwt.split('.').map(str::to_owned).collect();
    parts[1].push('a');
    assert!(tokens.verify(&parts.join(".")).is_err());
    assert!(tokens.verify("not-a-jwt").is_err());
}
#[test]
fn rejects_weak_secrets_and_invalid_ttls() {
    assert!(TokenService::new("short", "issuer", "clients", 900).is_err());
    assert!(TokenService::new(KEY, "issuer", "clients", 0).is_err());
}
