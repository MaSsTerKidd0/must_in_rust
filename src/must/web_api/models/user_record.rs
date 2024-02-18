use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, DateTime};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRecord {
    #[serde(rename = "_id")]
    id: ObjectId,
    username: String,
    password: String,
    roles: Vec<String>,
    created_at: DateTime,
}
