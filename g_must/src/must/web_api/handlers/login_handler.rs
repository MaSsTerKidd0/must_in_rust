use actix_web::{web, HttpResponse, Responder, post};
use serde::{Deserialize, Serialize};
use crate::must::mongo_db_handler::get_mongo_handler;
use crate::must::web_api::models::login_record::LoginReq;
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[post("/login/")]
async fn login(
    info: web::Json<LoginRequest>,
) -> impl Responder {
    let handler = get_mongo_handler().await.expect("Failed to get MongoDB handler");

    match handler.get_user(&info.username).await {
        Ok(Some(user)) => {
            if user.password == info.password {
                let token = generate_session_token(&user);
                HttpResponse::Ok().json(LoginResponse { token })
            } else {
                HttpResponse::Unauthorized().json("Invalid username or password")
            }
        },
        Ok(None) => {
            HttpResponse::Unauthorized().json("Invalid username or password")
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(format!("Database error: {:?}", e))
        },
    }
}

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::must::web_api::models::user_record::{Role, UserRecord};

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String, // Subject (user ID)
    role: Role,
    exp: usize, // Expiration time

}

fn generate_session_token(user: &UserRecord) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let expiration = now + 3600; // Token expires in 1 hour

    let claims = Claims {
        sub: user.id.expect("Id Unavailable").to_string(),
        role: user.role.clone(),
        exp: expiration,
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(b"your-secret-key");//TODO:RANDOM GENERATE SECRET KEY

    encode(&header, &claims, &encoding_key)
        .expect("Failed to encode JWT token")
}