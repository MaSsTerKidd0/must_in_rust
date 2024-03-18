use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    #[serde(rename = "secureNetwork")]
    pub(crate) secure_network: NetworkDetails,
    #[serde(rename = "unsecureNetwork")]
    pub(crate) unsecure_network: NetworkDetails,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkDetails {
    pub(crate) ip: String,
    pub(crate) port: String,
}
