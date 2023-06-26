use axum_jwt_auth::refresh::{generate_refresh_token,refresh_digest};
#[test]
fn generated_refresh_secrets_are_unique_canonical_and_hashed() {
    let mut seen=std::collections::HashSet::new();
    for _ in 0..100 {
        let token=generate_refresh_token();
        assert_eq!(token.secret.len(),43);
        assert_eq!(token.digest.len(),64);
        assert_eq!(refresh_digest(&token.secret).unwrap(),token.digest);
        assert_ne!(token.secret,token.digest);
        assert!(seen.insert(token.secret));
    }
    for invalid in ["", "abc", &"a".repeat(200), "!@#$"] { assert!(refresh_digest(invalid).is_err()); }
}
