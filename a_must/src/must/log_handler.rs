use std::fs::{OpenOptions, File};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use chrono::Local;
use lazy_static::lazy_static;

pub enum LogLevel {
    Info,
    Warning,
    Error,
}

pub struct LogHandler {
    log_file_path: String,
}

impl LogHandler {
    pub fn new(log_file_base_path: &str) -> LogHandler {
        let date_time = Local::now().format("%d%m%Y").to_string();
        // Construct the log file name with the current date and time
        let log_file_path = format!("{}_{}.log", log_file_base_path, date_time);
        println!("{}", log_file_path);
        LogHandler {
            log_file_path,
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

lazy_static! {
    pub static ref LOG_HANDLER: Mutex<LogHandler> = Mutex::new(LogHandler::new("./logs/Log"));
}


