use axum_jwt_auth::{model::RegisterUserSchema, validation::{normalize_email, validate_registration}};
#[test]
fn email_is_trimmed_and_case_normalized() {
    assert_eq!(normalize_email("  Alice@Example.COM ").unwrap(), "alice@example.com");
    for email in ["", "a", "@example.com", "a@", "a@b", "a b@example.com", "a@b@c.com"] {
        assert!(normalize_email(email).is_err(), "{email}");
    }
}
#[test]
fn registration_rejects_blank_names_and_unbounded_passwords() {
    for (name, password) in [(" ", "long-enough-password".into()), ("Alice", "short".into()), ("Alice", "a".repeat(129))] {
        let body = RegisterUserSchema { name:name.into(), email:"a@example.com".into(), password };
        assert!(validate_registration(&body).is_err());
    }
    let body = RegisterUserSchema { name:" Alice ".into(), email:"A@example.com".into(), password:"long-enough-password".into() };
    assert_eq!(validate_registration(&body).unwrap(), ("Alice".into(),"a@example.com".into()));
}
