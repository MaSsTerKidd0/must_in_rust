// use actix_web::{web, HttpResponse, post, get, delete};
// use mongodb::bson::oid::ObjectId;
// use crate::must::web_api::models::user_record::UserRecord;
// use crate::must::mongo_db_handler::MongoDBHandler; // make sure to import MongoDBHandler
//
// pub fn user_routes(cfg: &mut web::ServiceConfig) {
//     cfg.service(
//         web::scope("/user")
//             .service(create_user)
//             .service(get_users)
//             .service(get_user_by_id)
//             .service(delete_user),
//     );
// }
//
// #[post("/")]
// async fn create_user(handler: web::Data<MongoDBHandler>, new_user: web::Json<UserRecord>) -> HttpResponse {
//     match handler.create_user(new_user.into_inner()).await {
//         Ok(_) => HttpResponse::Created().body("User added successfully"),
//         Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
//     }
// }
//
// #[get("/")]
// async fn get_users(handler: web::Data<MongoDBHandler>) -> HttpResponse {
//     match handler.get_all_users().await {
//         Ok(users) => HttpResponse::Ok().json(users),
//         Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
//     }
// }
//
// #[get("/{id}")]
// async fn get_user_by_id(handler: web::Data<MongoDBHandler>, user_id: web::Path<String>) -> HttpResponse {
//     match ObjectId::parse_str(&user_id) {
//         Ok(id) => {
//             match handler.get_user_by_id(id).await {
//                 Ok(user) => HttpResponse::Ok().json(user),
//                 Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
//             }
//         },
//         Err(_) => HttpResponse::BadRequest().body("Invalid ObjectId format"),
//     }
// }
//
// #[delete("/{id}")]
// async fn delete_user(handler: web::Data<MongoDBHandler>, user_id: web::Path<String>) -> HttpResponse {
//     match ObjectId::parse_str(&user_id) {
//         Ok(id) => {
//             match handler.delete_user(id).await {
//                 Ok(_) => HttpResponse::Ok().body("User removed successfully"),
//                 Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
//             }
//         },
//         Err(_) => HttpResponse::BadRequest().body("Invalid ObjectId format"),
//     }
// }
