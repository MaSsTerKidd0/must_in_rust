use actix_web::{web, HttpResponse, Responder};
use crate::must::web_api::models::config_req::ConfigReq;

pub async fn config(info: web::Json<ConfigReq>) -> impl Responder {
    println!("Config Name: {}, IP Address: {}, Encryption: {}",
             info.config_name,
             info.ip_addr,
             info.encryption);
    HttpResponse::Ok().json("Configured")
}