use std::fs;
use actix_web::{get, HttpResponse, post, Responder, web};
use serde_json::from_str;
use crate::must::web_api::models::rsa_record::PublicKeyData;

#[get("/rsa/public")]
pub async fn get_rsa_public_key() -> impl Responder {
    let file_path = "public_key.json";

    let file_content = fs::read_to_string(file_path).unwrap_or_else(|_| "".to_string());
    let public_key_data: Result<PublicKeyData, _> = from_str(&file_content);
    match public_key_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(_) => HttpResponse::InternalServerError().body("Error reading public key data"),
    }
}

// #[post("/rsa/regenerate")]
// pub async fn regenerate_rsa_keys() -> impl Responder {
//
// }