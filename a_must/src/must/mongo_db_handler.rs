use mongodb::{bson, Client, Collection, Database, error::Result as MongoResult};
use serde::{Serialize, Deserialize};
use chrono::{Utc};
use futures::TryStreamExt;
use mongodb::bson::{doc, Document};
use mongodb::bson::oid::ObjectId;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use crate::must::web_api::models::user_record::UserRecord;

#[derive(Clone)]
pub struct MongoDBHandler {
    db: Database,
}

impl MongoDBHandler {
    // Initializes a new MongoDBHandler instance
    pub async fn new(uri: &str, db_name: &str) -> mongodb::error::Result<Self> {
        let client = Client::with_uri_str(uri).await?;
        let db = client.database(db_name);
        Ok(MongoDBHandler { db })
    }

    // Gets a collection
    fn collection<T>(&self, name: &str) -> Collection<T> {
        self.db.collection::<T>(name)
    }

    pub(crate) async fn insert_user(&self, user: UserRecord) -> mongodb::error::Result<()> {
        let users_collection = self.collection::<UserRecord>("Users");
        users_collection.insert_one(user, None).await?;
        Ok(())
    }

    pub(crate) async fn delete_user(&self, user_id: ObjectId) -> mongodb::error::Result<()> {
        let users_collection = self.collection::<UserRecord>("Users");
        users_collection.delete_one(doc! { "_id": user_id }, None).await?;
        Ok(())
    }

    pub async fn get_all_users(&self) -> mongodb::error::Result<Vec<UserRecord>> {
        let users_collection = self.collection::<UserRecord>("Users");
        let cursor = users_collection.find(None, None).await?;
        let users: Vec<UserRecord> = cursor.try_collect().await?;
        Ok(users)
    }
}

static MONGO_HANDLER: Lazy<Mutex<Option<MongoDBHandler>>> = Lazy::new(|| Mutex::new(None));

pub async fn get_mongo_handler() -> mongodb::error::Result<MongoDBHandler> {
    let mut handler = MONGO_HANDLER.lock().await;
    if handler.is_none() {
        *handler = Some(MongoDBHandler::new("mongodb://localhost:27017/", "MUST").await?);
    }
    Ok(handler.clone().expect("MongoDBHandler was not initialized"))
}