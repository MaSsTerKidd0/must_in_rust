use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}
