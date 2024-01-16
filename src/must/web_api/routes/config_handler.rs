use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::must::json_handler::JsonHandler;
use crate::must::web_api::models::config_req::ConfigReq;

pub async fn config(info: web::Json<ConfigReq>) -> impl Responder {
    println!("Config Name: {}, SecureNet: {}, UnsecureNet: {}, Encryption: {}",
             info.0.config_name,
             info.0.secure_net,
             info.0.unsecure_net,
             info.0.aes_type);


    let mut configs: Vec<ConfigReq> = match JsonHandler::load("configurations.json") {
        Ok(cfg) => cfg,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to load configurations")
    };

    if !info.0.is_valid() {
        return HttpResponse::BadRequest().json("Invalid input data");
    }

    if configs.iter().any(|cfg| cfg.config_name == info.0.config_name) {
        return HttpResponse::BadRequest().json("Configuration name already exists");
    }

    configs.push(info.0);

    if let Err(_) = JsonHandler::save("configurations.json", &configs) {
        return HttpResponse::InternalServerError().json("Failed to save configuration");
    }
    return HttpResponse::Ok().json("Configuration has been saved");
}