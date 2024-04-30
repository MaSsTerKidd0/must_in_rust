use chrono::{Local, DateTime};
use crate::must::log_handler::{LOG_HANDLER, LogLevel};
use crate::must::network::network_icd::NetworkICD;

pub enum OperationId {
    SendPacket,
    LoadConfig,
    Startup,
    LowDiskSpace,
    Serialization,
    Fragmentation,
    Cipher,
}

impl OperationId {
    pub fn as_str(&self) -> &'static str {
        match *self {
            OperationId::SendPacket => "send_packet",
            OperationId::LoadConfig => "load_config",
            OperationId::Startup => "startup",
            OperationId::LowDiskSpace => "low_disk_space",
            OperationId::Serialization => "serialization",
            OperationId::Fragmentation => "fragmentation",
            OperationId::Cipher => "cipher",
        }
    }
}

pub struct LogAssistant;

impl LogAssistant {

}

impl LogAssistant {
    fn current_timestamp() -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn log_with_level(level: LogLevel, operation_id: OperationId, status: &str, message: &str) {
        let timestamped_message = format!("{} [{}] [{}] {}", Self::current_timestamp(), operation_id.as_str(), status, message);
        let log_handler = LOG_HANDLER.lock().unwrap();
        log_handler.log(level, &timestamped_message);
    }

    pub fn generic_error(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "ERROR", "An unexpected error occurred.");
    }

    pub fn send_success(operation_id: OperationId, packet_counter: u32) {
        let message = format!("Successfully transmitted packets, packet_count: {}", packet_counter);
        Self::log_with_level(LogLevel::Info, operation_id, "SUCCESS", &message);
    }

    pub fn send_error(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "FAILURE", "Failed to send data due to network issue.");
    }

    pub fn config_load_error(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "ERROR", "Error loading configuration from file.");
    }

    pub fn start_info(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Info, operation_id, "INFO", "Application is starting up.");
    }

    pub fn low_disk_space_warning(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Warning, operation_id, "WARNING", "Low disk space detected.");
    }

    pub fn serialize_failure(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "ERROR", "Serialization failed.");
    }

    pub fn fragment_failure(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "ERROR", "Fragmentation failed.");
    }

    pub fn cipher_failure(operation_id: OperationId) {
        Self::log_with_level(LogLevel::Error, operation_id, "ERROR", "Cipher failed.");
    }

    pub(crate) fn network_icd_packet(pac: NetworkICD) {
        Self::log_with_level(LogLevel::Info, OperationId::Fragmentation, "INFO", &format!("Network-ICD:{:?}", pac));
    }

}

