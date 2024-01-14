use actix_web::{web, HttpResponse, Responder};
use crate::must::web_api::models::login_req::LoginReq;

pub async fn login(info: web::Json<LoginReq>) -> impl Responder {
    println!("Username: {}, Password: {}", info.username, info.password);
    HttpResponse::Ok().json("Login Successful")
}
