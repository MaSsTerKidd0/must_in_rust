use actix_web::{web, HttpResponse, post, get, delete};
use mongodb::{Collection, Client};
use mongodb::bson::oid::ObjectId;
use mongodb::bson::doc;
use crate::must::web_api::models::user_record::UserRecord;

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .service(create_user)
            .service(get_users)
            .service(get_user_by_id)
            .service(delete_user),
    );
}
#[post("/")] // Creates a new user
pub async fn create_user(client: web::Data<Client>, new_user: web::Json<UserRecord>) -> HttpResponse {
    let users_collection: Collection<UserRecord> = client.database("myapp").collection("users");

    match users_collection.insert_one(new_user.into_inner(), None).await {
        Ok(_) => HttpResponse::Created().body("User added successfully"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}


#[get("/")] // Retrieves all users
pub async fn get_users(client: web::Data<Client>) -> HttpResponse {
    // Placeholder implementation that returns an empty array
    HttpResponse::Ok().json(Vec::<UserRecord>::new()) // Sending an empty array as a placeholder
}

#[get("/{id}")] // Retrieves a user by ID
pub async fn get_user_by_id(client: web::Data<Client>, user_id: web::Path<String>) -> HttpResponse {
    // Placeholder implementation that returns null or some default value
    HttpResponse::Ok().json("User retrieval by ID not implemented yet") // Sending a placeholder string
}

#[delete("/{id}")] // Deletes a user by ID
pub async fn delete_user(client: web::Data<Client>, user_id: web::Path<String>) -> HttpResponse {
    let users_collection: Collection<UserRecord> = client.database("myapp").collection("users");

    // Parse the string to an ObjectId
    match ObjectId::parse_str(user_id.as_str()) {
        Ok(id) => {
            match users_collection.delete_one(doc! {"_id": id}, None).await {
                Ok(delete_result) if delete_result.deleted_count > 0 => HttpResponse::Ok().body("User removed successfully"),
                Ok(_) => HttpResponse::NotFound().body("User not found"),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        },
        Err(_) => HttpResponse::BadRequest().body("Invalid ObjectId format"),
    }
}