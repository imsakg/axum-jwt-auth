use std::str::FromStr;
use axum::{body::Body,http::Request,middleware::Next,response::Response};
use crate::model::User;

pub async fn require_admin(request: Request<Body>, next: Next) -> Result<Response,ApiError> {
    let user=request.extensions().get::<User>().ok_or(ApiError::Unauthorized)?;
    let role=user.role.parse::<Role>()?;
    if !role.allows(Permission::ListUsers) { return Err(ApiError::Forbidden); }
    Ok(next.run(request).await)
}
use crate::error::ApiError;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Role { User, Admin }
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Permission { ReadSelf, ListUsers }
impl FromStr for Role {
    type Err=ApiError;
    fn from_str(role: &str) -> Result<Self,Self::Err> {
        match role { "user"=>Ok(Self::User), "admin"=>Ok(Self::Admin), _=>Err(ApiError::Forbidden) }
    }
}
impl Role {
    pub fn allows(self, permission: Permission) -> bool {
        matches!((self,permission),(Self::Admin,_) | (Self::User,Permission::ReadSelf))
    }
}
