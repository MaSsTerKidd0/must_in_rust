use std::{fs, io};
use serde::de::DeserializeOwned;
use serde::{Serialize};

pub struct JsonHandler;


impl JsonHandler{
    pub fn save<T: Serialize>(filename: &str, data: &T) -> io::Result<()> {
        let json = serde_json::to_string(data)?;
        fs::write(filename, json)?;
        Ok(())
    }

    pub fn load<T: DeserializeOwned>(filename: &str) -> io::Result<T> {
        let contents = fs::read_to_string(filename)?;
        let data = serde_json::from_str(&contents)?;
        Ok(data)
    }
}