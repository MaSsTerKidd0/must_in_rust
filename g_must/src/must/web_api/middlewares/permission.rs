use std::cmp::PartialEq;
use actix_web::{dev::ServiceRequest, error::ErrorUnauthorized, Error, HttpMessage, dev, middleware, error};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, errors::Result as JwtResult};
use actix_web::{web, http, HttpRequest, HttpResponse, Responder};
use crate::must::web_api::models::user_record::Role::Admin;


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    sub: String,
    pub(crate) role: String,
    exp: usize,
}

pub async fn auth_middleware(
    req: ServiceRequest,
    payload: &Claims,
) -> Result<ServiceRequest, Error> {
    let role = payload.role.as_str();
    let path = req.path();

    // Define your role-based access rules
    match (role, path) {
        ("Admin", _) => Ok(req), // Admins can access all pages
        ("User", "/dashboard") => Ok(req), // Users can access the dashboard
        ("PermittetUser", "/config") => Ok(req), // Users can access the settings page
        _ => Err(ErrorUnauthorized("Access denied")),
    }
}

pub async fn validate_token(token: &str) -> Result<Claims, actix_web::Error> {
    let decoding_key = DecodingKey::from_secret(b"your-secret-key");
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60; // 60 second leeway

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|err| ErrorUnauthorized(err.to_string()))?;
    Ok(token_data.claims)
}

fn validate_jwt(token: &str) -> JwtResult<jsonwebtoken::TokenData<Claims>> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret("your_secret_key".as_ref()),
        &Validation::new(Algorithm::HS256),
    )
}



pub async fn protected_route(req: HttpRequest) -> impl Responder {
    // Extract the Authorization header
    let auth_header = req.headers().get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .unwrap_or("");

    // Check if the token is present and starts with "Bearer "
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        match validate_jwt(token) {
            Ok(data) => {
                // Token is valid, now check if the role is allowed
                if  Admin.eq_str(&data.claims.role) {
                    // User has the 'admin' role, grant access
                    HttpResponse::Ok().body("Admin access granted")
                } else {
                    // User does not have the 'admin' role
                    HttpResponse::Unauthorized().body("Access denied: insufficient permissions")
                }
            },
            Err(_err) => {
                // Token is invalid
                HttpResponse::Unauthorized().body("Invalid token")
            },
        }
    } else {
        HttpResponse::BadRequest().body("Missing or invalid Authorization header")
    }
}

