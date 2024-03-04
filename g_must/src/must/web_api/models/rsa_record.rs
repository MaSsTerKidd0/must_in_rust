use serde::{Serialize, Deserialize};
use chrono::Utc; // For handling the current date

#[derive(Serialize, Deserialize)]
pub struct PublicKeyData {
    pub(crate) exponent: String,
    pub(crate) modulus: String,
    pub(crate) date: String,
}