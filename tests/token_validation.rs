use axum_jwt_auth::token::TokenService;
use jsonwebtoken::{encode,Algorithm,EncodingKey,Header};
use serde_json::{json,Value};
use uuid::Uuid;
const KEY: &str = "a-long-test-key-with-at-least-32-bytes";
fn claims() -> Value {
    let now=chrono::Utc::now().timestamp();
    json!({"sub":Uuid::new_v4(),"sid":Uuid::new_v4(),"jti":Uuid::new_v4(),"iat":now,"nbf":now,"exp":now+900,"iss":"issuer","aud":"clients","token_use":"access"})
}
fn sign(claims: Value) -> String {
    let mut header=Header::new(Algorithm::HS256); header.kid=Some("default".into());
    encode(&header,&claims,&EncodingKey::from_secret(KEY.as_bytes())).unwrap()
}
#[test]
fn rejects_expired_future_and_wrong_purpose_tokens() {
    let service=TokenService::new(KEY,"issuer","clients",900).unwrap();
    let now=chrono::Utc::now().timestamp();
    for (field,value) in [("exp",json!(now-1)),("iat",json!(now+3600)),("nbf",json!(now+3600)),("token_use",json!("refresh")),("iss",json!("evil")),("aud",json!("elsewhere")),("sub",json!("not-a-uuid"))] {
        let mut c=claims(); c[field]=value;
        assert!(service.verify(&sign(c)).is_err(),"accepted invalid {field}");
    }
}
#[test]
fn requires_every_claim_and_rejects_unbounded_tokens() {
    let service=TokenService::new(KEY,"issuer","clients",900).unwrap();
    for field in ["exp","iat","nbf","iss","aud","sub","sid","jti","token_use"] {
        let mut c=claims(); c.as_object_mut().unwrap().remove(field);
        assert!(service.verify(&sign(c)).is_err(),"accepted missing {field}");
    }
    assert!(service.verify(&"x".repeat(8193)).is_err());
}
