use std::{fs, io};
use serde::de::DeserializeOwned;
use serde::{Serialize};

pub struct JsonHandler;


impl JsonHandler{
    pub fn save<T: Serialize>(file_path: &str, data: &T) -> io::Result<()> {
        let pretty_json = serde_json::to_string_pretty(data)?;
        fs::write(file_path, pretty_json)?;
        Ok(())
    }

    pub fn load<T: DeserializeOwned>(file_path: &str) -> io::Result<T> {
        let contents = fs::read_to_string(file_path)?;

        if contents.trim().is_empty() {
            // Deserialize an empty Vec<T> if the file is empty
            let data: T = serde_json::from_str("[]")?;
            Ok(data)
        } else {
            let data = serde_json::from_str(&contents)?;
            Ok(data)
        }
    }
}