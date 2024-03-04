use serde::{Deserialize, Serialize};
use mongodb::bson::{oid::ObjectId, DateTime};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRecord {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<ObjectId>, // make it optional to allow MongoDB to auto-generate it
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) roles: Vec<String>,
    pub(crate) created_at: String, // Use MongoDB's DateTime
}
