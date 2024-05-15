use std::cmp::Ordering;
use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, DateTime};
use chrono::Utc;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, PartialOrd, Eq)]
pub enum Role {
    User,
    PermittedUser,
    Admin,
}

impl Ord for Role {
    fn cmp(&self, other: &Self) -> Ordering {
        use Role::*;
        match (self, other) {
            (User, User) => Ordering::Equal,
            (User, PermittedUser) => Ordering::Less,
            (User, Admin) => Ordering::Less,
            (PermittedUser, User) => Ordering::Greater,
            (PermittedUser, PermittedUser) => Ordering::Equal,
            (PermittedUser, Admin) => Ordering::Less,
            (Admin, User) => Ordering::Greater,
            (Admin, PermittedUser) => Ordering::Greater,
            (Admin, Admin) => Ordering::Equal,
        }
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRecord {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub password: String,
    pub role: Role,
    pub created_at: String,
}

impl From<NewUser> for UserRecord {
    fn from(new_user: NewUser) -> Self {
        UserRecord {
            id: None,
            username: new_user.username,
            password: new_user.password,
            role: new_user.role,
            created_at: Utc::now().to_rfc3339(),
        }
    }
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
