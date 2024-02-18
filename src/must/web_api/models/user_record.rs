use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, DateTime};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    id: ObjectId,
    username: String,
    password: String, // Consider hashing in a real application
    roles: Vec<String>,
    created_at: DateTime,
}