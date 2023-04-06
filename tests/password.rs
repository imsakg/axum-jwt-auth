use axum_jwt_auth::password::{hash_password, verify_password};
#[test]
fn salted_argon2_hashes_verify_only_the_right_password() {
    let one = hash_password("correct horse battery staple").unwrap();
    let two = hash_password("correct horse battery staple").unwrap();
    assert_ne!(one, two);
    assert!(one.starts_with("$argon2id$"));
    assert!(verify_password("correct horse battery staple", &one));
    assert!(!verify_password("wrong", &one));
    assert!(!verify_password("anything", "broken hash"));
}
