use chrono::{Local, DateTime};
use crate::must::log_handler::{LOG_HANDLER, LogLevel};

pub struct LogAssistant;

impl LogAssistant {
    // Helper function to get the current date and time
    fn current_timestamp() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    // Function to generate a message with a timestamp
    fn log_with_level(level: LogLevel, message: &str) {
        let timestamped_message = format!("{} {}", Self::current_timestamp(), message);
        let log_handler = LOG_HANDLER.lock().unwrap();
        log_handler.log(level, &timestamped_message);
    }

    pub fn generic_error() {
        Self::log_with_level(LogLevel::Error, "An unexpected error occurred.");
    }
    pub fn send_success() {
        Self::log_with_level(LogLevel::Info, "Successful to send data to network.");
    }
    pub fn send_error() {
        Self::log_with_level(LogLevel::Error, "Failed to send data due to network issue.");
    }

    pub fn config_load_error() {
        Self::log_with_level(LogLevel::Error, "Error loading configuration from file.");
    }

    pub fn start_info() {
        Self::log_with_level(LogLevel::Info, "Application is starting up.");
    }

    pub fn low_disk_space_warning() {
        Self::log_with_level(LogLevel::Warning, "Warning: Low disk space detected.");
    }

    pub fn serialize_failure() {
        Self::log_with_level(LogLevel::Error, "Serialization failed.");
    }

    pub fn fragment_failure() {
        Self::log_with_level(LogLevel::Error, "Fragmentation failed.");
    }
    pub(crate) fn cipher_failure() {
        Self::log_with_level(LogLevel::Error, "cipher failed.");
    }
}
