use std::env;
use std::fs::{create_dir_all, OpenOptions, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use chrono::{Local, NaiveDateTime};
use lazy_static::lazy_static;

pub enum LogLevel {
    Info,
    Warning,
    Error,
}

pub struct LogHandler {
    log_dir_path: PathBuf,
    pub incoming_secure_log_path: PathBuf,
    pub incoming_unsecure_log_path: PathBuf,
    pub outgoing_secure_log_path: PathBuf,
    pub outgoing_unsecure_log_path: PathBuf,
}

impl LogHandler {
    pub fn new(log_base_dir: &str) -> LogHandler {
        let date_time = Local::now().format("%d%m%Y").to_string();
        let log_dir_path = Path::new(log_base_dir).join(date_time);

        let incoming_secure_log_path = log_dir_path.join("incomingSecure.log");
        let incoming_unsecure_log_path = log_dir_path.join("incomingUnsecure.log");
        let outgoing_secure_log_path = log_dir_path.join("outgoingSecure.log");
        let outgoing_unsecure_log_path = log_dir_path.join("outgoingUnsecure.log");

        create_dir_all(&log_dir_path).expect("Failed to create log directory");

        LogHandler {
            log_dir_path,
            incoming_secure_log_path,
            incoming_unsecure_log_path,
            outgoing_secure_log_path,
            outgoing_unsecure_log_path,
        }
    }

    fn write_to_log_file(&self, log_path: &Path, message: &str) {
        let mut file = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(log_path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open log file: {}", e);
                return;
            }
        };

        if let Err(e) = writeln!(file, "{}", message) {
            eprintln!("Failed to write to log file: {}", e);
        }
    }

    pub fn log(&self, log_path: &Path, level: LogLevel, message: &str) {
        let log_message = match level {
            LogLevel::Info => format!("INFO: {}", message),
            LogLevel::Warning => format!("WARNING: {}", message),
            LogLevel::Error => format!("ERROR: {}", message),
        };

        self.write_to_log_file(log_path, &log_message);
    }

    pub fn info(&self, log_path: &Path, message: &str) {
        self.log(log_path, LogLevel::Info, message);
    }

    pub fn warning(&self, log_path: &Path, message: &str) {
        self.log(log_path, LogLevel::Warning, message);
    }

    pub fn error(&self, log_path: &Path, message: &str) {
        self.log(log_path, LogLevel::Error, message);
    }
}

lazy_static! {
    pub static ref LOG_HANDLER: Mutex<LogHandler> = Mutex::new(LogHandler::new("./logs"));
}