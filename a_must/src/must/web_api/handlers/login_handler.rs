use actix_web::{web, HttpResponse, Responder, post};
use crate::must::web_api::models::login_record::LoginReq;
#[post("/login/")]
pub async fn login(info: web::Json<LoginReq>) -> impl Responder {
    println!("Username: {}, Password: {}", info.username, info.password);
    HttpResponse::Ok().json("Login Successful")
}
