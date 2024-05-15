use std::cmp::PartialEq;
use std::env;
    use actix_web::{dev::ServiceRequest, error::ErrorUnauthorized, Error, HttpMessage, dev, middleware, error};
    use serde::{Deserialize, Serialize};
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, errors::Result as JwtResult};
    use actix_web::{web, http, HttpRequest, HttpResponse, Responder};
    use std::string::String;
    use actix_web::dev::ServiceResponse;
    use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::must::web_api::middlewares::Route;
use crate::must::web_api::models::user_record::Role;
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
            ("PermittedUser", "/config") => Ok(req), // Users can access the settings page
            _ => Err(ErrorUnauthorized("Access denied")),
        }
    }

    fn decode_session_token(token: &str) -> JwtResult<jsonwebtoken::TokenData<Claims>> {
        let decoding_key = DecodingKey::from_secret("your-secret-key".as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        // Add additional validation rules, e.g., token expiration
        validation.validate_exp = true;

        decode::<Claims>(&token, &decoding_key, &validation)
    }




pub async fn protected_route(req: HttpRequest, route: Route) -> impl Responder {
    let auth_header = req.headers().get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .unwrap_or("");
    let token = if auth_header.starts_with("Bearer ") {
        auth_header.strip_prefix("Bearer ").unwrap_or_default().trim()
    } else {
        auth_header
    };

    match decode_session_token(token) {
        Ok(data) => {
            let response = match route {
                Route::Config => handle_config_route(&data.claims.role),
                Route::HR => handle_hr_route(&data.claims.role),
                Route::Other => handle_other_routes(&data.claims.role),
            };
            response
        }
        Err(_err) => HttpResponse::Unauthorized().body("Invalid token"),
    }
}

fn handle_config_route(role: &str) -> HttpResponse {
    if role == "Admin" || role == "PermittedUser"{
        HttpResponse::Ok().body("Access granted")
    } else {
        HttpResponse::Unauthorized().body("Access denied: Admin role required")
    }
}

fn handle_hr_route(role: &str) -> HttpResponse {
    if role == "Admin" {
        HttpResponse::Ok().body("Access granted")
    } else {
        HttpResponse::Unauthorized().body("Access denied: Admin role required")
    }
}

fn handle_other_routes(role: &str) -> HttpResponse {
    if !role.is_empty(){
        HttpResponse::Ok().body("Access granted")
    } else {
        HttpResponse::Unauthorized().body("Access denied: insufficient permissions")
    }
}