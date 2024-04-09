use actix_web::{web, App, HttpResponse, HttpServer, Responder, post, get, delete};
use actix_web::web::service;
use mongodb::bson::oid::ObjectId;
use crate::must::mongo_db_handler::{get_mongo_handler};
use serde_json::json;
use crate::must::web_api::models::user_record::UserRecord;

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .service(get_all_users)
            .service(insert_user),
    );
}

#[post("/insertUser")]
async fn insert_user(user: web::Json<UserRecord>) -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    match mongo_handler.insert_user(user.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json("User created successfully"),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to insert user: {}", e)),
    }
}

#[get("/getUsers")]
async fn get_all_users() -> impl Responder {
    let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    match mongo_handler.get_all_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().json(format!("Failed to get users: {}", e)),
    }
}


    // #[delete("/users/{id}")]
    // async fn delete_user(path: web::Path<String>) -> impl Responder {
    //     let mongo_handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");
    //     let id = ObjectId::with_string(&path.into_inner()).unwrap(); // Handle unwrap more gracefully in real app
    //
    //     match mongo_handler.delete_user(id).await {
    //         Ok(_) => HttpResponse::Ok().json("User deleted successfully"),
    //         Err(e) => HttpResponse::InternalServerError().json(format!("Failed to delete user: {}", e)),
    //     }
    // }
