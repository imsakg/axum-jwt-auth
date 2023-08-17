use std::str::FromStr;
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
