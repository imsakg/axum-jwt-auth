use std::collections::BTreeMap;
use axum_jwt_auth::token::TokenService;
use uuid::Uuid;
const OLD: &str = "old-secret-material-at-least-thirty-two-bytes";
const NEW: &str = "new-secret-material-at-least-thirty-two-bytes";
#[test]
fn rotation_signs_new_key_and_accepts_the_old_key_during_overlap() {
    let old = TokenService::from_keys("old", BTreeMap::from([("old".into(),OLD.into())]),"issuer","clients",900).unwrap();
    let jwt = old.issue(Uuid::new_v4(),Uuid::new_v4(),chrono::Utc::now().timestamp()).unwrap();
    let overlap = TokenService::from_keys("new", BTreeMap::from([("old".into(),OLD.into()),("new".into(),NEW.into())]),"issuer","clients",900).unwrap();
    assert!(overlap.verify(&jwt).is_ok());
    let fresh = overlap.issue(Uuid::new_v4(),Uuid::new_v4(),chrono::Utc::now().timestamp()).unwrap();
    assert_eq!(jsonwebtoken::decode_header(&fresh).unwrap().kid.as_deref(),Some("new"));
    let retired = TokenService::from_keys("new",BTreeMap::from([("new".into(),NEW.into())]),"issuer","clients",900).unwrap();
    assert!(retired.verify(&jwt).is_err());
    assert!(retired.verify(&fresh).is_ok());
}
#[test]
fn active_key_must_exist_and_every_key_must_be_strong() {
    assert!(TokenService::from_keys("missing",BTreeMap::new(),"issuer","clients",900).is_err());
    assert!(TokenService::from_keys("one",BTreeMap::from([("one".into(),"weak".into())]),"issuer","clients",900).is_err());
}
