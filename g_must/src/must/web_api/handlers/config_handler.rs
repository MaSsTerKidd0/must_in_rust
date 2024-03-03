use std::io;
use actix_web::{web, HttpResponse, Responder, post, get};
use crate::must::json_handler::JsonHandler;
use crate::must::web_api::models::config_record::ConfigRecord;


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/config")
            .service(save_config)
            .service(get_configurations)
            .service(get_configuration_by_name),
    );
}

#[post("/")]
pub async fn save_config(info: web::Json<ConfigRecord>) -> impl Responder {

    println!("Config Name: {}, SecureNet: {}, SecureNetPort: {}, SecureNetSubnetMask: {}, SecureNetBandwidth: {}, UnsecureNet: {}, UnsecureNetPort: {}, UnsecureNetSubnetMask: {}, UnsecureNetBandwidth: {}, Encryption: {}",
             info.config_name, info.secure_net, info.secure_net_port, info.secure_net_subnet_mask, info.secure_net_bandwidth, info.unsecure_net, info.unsecure_net_port, info.unsecure_net_subnet_mask, info.unsecure_net_bandwidth, info.aes_type);

    if !info.is_valid() {
        return HttpResponse::BadRequest().json("Invalid input data");
    }

    let file_path = "configurations.json";

    match find_config_by_name(file_path, &info.config_name) {
        Ok(Some(_)) => {
            return HttpResponse::BadRequest().json("Configuration name already exists");
        }
        Ok(None) => {
            let mut configs: Vec<ConfigRecord> = match JsonHandler::load(file_path) {
                Ok(cfg) => cfg,
                Err(_) => return HttpResponse::InternalServerError().json("Failed to load configurations"),
            };
            configs.push(info.into_inner());
            if let Err(_) = JsonHandler::save(file_path, &configs) {
                return HttpResponse::InternalServerError().json("Failed to save configuration");
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json("Failed to load configurations");
        }
    }

    HttpResponse::Ok().json("Configuration has been saved")
}


#[get("/")]
pub async fn get_configurations() -> impl Responder {
    let configs: Vec<ConfigRecord> = match JsonHandler::load("configurations.json") {
        Ok(cfg) => cfg,
        Err(_) => return HttpResponse::InternalServerError().json("Failed to load configurations")
    };

    let config_names: Vec<String> = configs.into_iter().map(|cfg| cfg.config_name).collect();
    HttpResponse::Ok().json(config_names)
}


#[get("/{config_name}")]
pub async fn get_configuration_by_name(path: web::Path<String>) -> impl Responder {
    let config_name = path.into_inner();
    let file_path = "configurations.json";

    match find_config_by_name(file_path, &config_name) {
        Ok(Some(config)) => HttpResponse::Ok().json(config),
        Ok(None) => HttpResponse::NotFound().json("Configuration not found"),
        Err(_) => HttpResponse::InternalServerError().json("Failed to load configurations"),
    }
}

pub fn find_config_by_name(file_path: &str, config_name: &str) -> io::Result<Option<ConfigRecord>> {
    let configurations: Vec<ConfigRecord> = JsonHandler::load(file_path)?;

    let found_config = configurations
        .into_iter()
        .find(|config| config.config_name == config_name);

    Ok(found_config)
}