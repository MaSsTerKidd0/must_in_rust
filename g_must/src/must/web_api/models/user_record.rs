use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, DateTime};


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum Role {
    User,
    PermittedUser,
    Admin,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRecord {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<ObjectId>,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) role: Role,
    pub(crate) created_at: String,
}
impl Role {
    pub fn from_str(role_str: &str) -> Option<Self> {
        match role_str {
            "User" => Some(Role::User),
            "PermittedUser" => Some(Role::PermittedUser),
            "Admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn eq_str(&self, other: &str) -> bool {
        self == &Role::from_str(other).unwrap_or_else(|| Role::User) // Default to User if unmatched
    }
}
