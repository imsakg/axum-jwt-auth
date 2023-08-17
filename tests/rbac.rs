use axum_jwt_auth::rbac::{Permission,Role};
use std::str::FromStr;
#[test]
fn roles_use_an_explicit_deny_by_default_permission_matrix() {
    assert!(Role::User.allows(Permission::ReadSelf));
    assert!(!Role::User.allows(Permission::ListUsers));
    assert!(Role::Admin.allows(Permission::ReadSelf));
    assert!(Role::Admin.allows(Permission::ListUsers));
    assert_eq!(Role::from_str("user").unwrap(),Role::User);
    assert_eq!(Role::from_str("admin").unwrap(),Role::Admin);
    for role in ["", "superadmin", "ADMIN", " user"] { assert!(Role::from_str(role).is_err()); }
}
