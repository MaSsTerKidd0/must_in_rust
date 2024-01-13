use actix_web::{web, HttpResponse, Responder};
use crate::must::web_api::models::login_request::LoginRequest;

pub async fn login(info: web::Json<LoginRequest>) -> impl Responder {
    println!("Username: {}, Password: {}", info.username, info.password);
    HttpResponse::Ok().json("Login Successful")
}
