use std::fs;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use rand::rngs::OsRng;
use rsa::pkcs1::RsaPublicKey;
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use serde_json::from_str;
use crate::must::ciphers_lib::rsa_crypto::RsaCryptoKeys;
use crate::must::web_api::models::rsa_record::PublicKeyData;

#[get("/rsa/public")]
pub async fn get_rsa_public_key() -> impl Responder {
    let public_key_pem = fs::read_to_string("public_key.pem")
        .expect("Failed to read public key PEM file");

    HttpResponse::Ok().content_type("text/plain").body(public_key_pem)
}


// #[post("/rsa/regenerate")]
// pub async fn regenerate_rsa_keys() -> impl Responder {
//
// }