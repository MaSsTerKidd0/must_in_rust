use std::fs::{OpenOptions, File};
use std::io::Write;
use std::path::Path;

pub struct LogHandler {
    log_file_path: String,
}

impl LogHandler {
    pub fn new(log_file_path: &str) -> LogHandler {
        LogHandler {
            log_file_path: log_file_path.to_string(),
        }
    }

    fn write_to_log_file(&self, message: &str) {
        let mut file = match OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(Path::new(&self.log_file_path)) {
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

    pub fn log(&self, level: LogLevel, message: &str) {
        let log_message = match level {
            LogLevel::Info => format!("INFO: {}", message),
            LogLevel::Warning => format!("WARNING: {}", message),
            LogLevel::Error => format!("ERROR: {}", message),
        };

        println!("{}", log_message);
        self.write_to_log_file(&log_message);
    }

    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    pub fn warning(&self, message: &str) {
        self.log(LogLevel::Warning, message);
    }

    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }
}

pub enum LogLevel {
    Info,
    Warning,
    Error,
}
