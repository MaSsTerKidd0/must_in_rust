use actix_web::{web, App, HttpResponse, HttpServer, Responder, post, get, delete};
use actix_web::web::service;
use mongodb::bson::doc;
use mongodb::bson::oid::ObjectId;
use mongodb::Collection;
use crate::must::mongo_db_handler::{get_mongo_handler};
use serde_json::json;
use crate::must::web_api::models::user_record::{NewUser, Role, UserRecord};

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/HR")
            .service(get_all_users)
            .service(insert_user)
            .service(get_all_users_except_admins)
            .service(delete_user_by_name),
    );
}

#[post("/insertUser")]
async fn insert_user(new_user: web::Json<NewUser>) -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    let user_record: UserRecord = new_user.into_inner().into();
    match mongo_handler.insert_user(user_record).await {
        Ok(_) => HttpResponse::Ok().json("User created successfully"),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to insert user: {}", e)),
    }
}

#[get("/getAllUsers")]
async fn get_all_users() -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    match mongo_handler.get_all_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to get users: {}", e)),
    }
}

#[get("/getUsers")]
async fn get_all_users_except_admins() -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    match mongo_handler
        .get_all_users_except_admins()
        .await
        .map(|mut users| {
            users.sort_by(|a, b| {
                let a_role_value = match a.role {
                    Role::User => 0,
                    Role::PermittedUser => 1,
                    Role::Admin => 2,
                };
                let b_role_value = match b.role {
                    Role::User => 0,
                    Role::PermittedUser => 1,
                    Role::Admin => 2,
                };

                a.username
                    .cmp(&b.username)
                    .then(a.created_at.cmp(&b.created_at))
                    .then(a.password.cmp(&b.password))
                    .then(a_role_value.cmp(&b_role_value))
            });
            users
        })
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to get users: {}", e)),
    }
}
#[delete("/deleteUser/{username}")]
async fn delete_user_by_name(username: web::Path<String>) -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");

    // Find the user by username
    let users_collection: Collection<UserRecord> = mongo_handler.collection("Users");
    let user_record = users_collection
        .find_one(doc! { "username": username.as_str() }, None)
        .await;

    match user_record {
        Ok(Some(user)) => {
            let user_id = user.id.unwrap();
            match mongo_handler.delete_user(user_id).await {
                Ok(_) => HttpResponse::Ok().json(format!("User with username '{}' deleted successfully", username)),
                Err(e) => HttpResponse::InternalServerError().json(format!("Failed to delete user: {}", e)),
            }
        }
        Ok(None) => HttpResponse::NotFound().json(format!("User with username '{}' not found", username)),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to find user: {}", e)),
    }
}