use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}
