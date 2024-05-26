use std::env;
use actix_web::{get, HttpResponse, Responder, web};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::{Arc, Mutex};
use actix_web::http::header::IfRange::Date;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};
use crate::must::web_api::middlewares::Claims;

#[derive(Serialize, Deserialize)]
struct LogEntry {
    time: String,
    packet_count: u32,
}

#[derive(Serialize, Clone)]
pub struct ConnectionStatusResponse {
    pub connection_established: bool,
    pub data_transmitted: bool,
}

impl Default for ConnectionStatusResponse {
    fn default() -> Self {
        Self {
            connection_established: true,
            data_transmitted: true,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_STATUS: Arc<Mutex<ConnectionStatusResponse>> = Arc::new(Mutex::new(ConnectionStatusResponse::default()));
}

pub fn dashboard(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/dashboard")
            .service(get_connection_status)
            .service(get_incoming_unsecure_data)
            .service(get_outgoing_unsecure_data)
            .service(get_incoming_secure_data)
            .service(get_outgoing_secure_data),
    );
}


#[get("/incomingUnsecure")]
pub async fn get_incoming_unsecure_data() -> impl Responder {
    let logs_dir = env::var("LOGS_DIR").unwrap_or_else(|_| String::from("logs"));
    let date_dir = Local::now().format("%d%m%Y").to_string();
    let path = format!("{}/{}/incomingUnsecure.log",logs_dir, date_dir);
    let log_data = read_log_file(&path);

    match log_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/outgoingUnsecure")]
pub async fn get_outgoing_unsecure_data() -> impl Responder {
    let logs_dir = env::var("LOGS_DIR").unwrap_or_else(|_| String::from("logs"));
    let date_dir = Local::now().format("%d%m%Y").to_string();
    let path = format!("{}/{}/outgoingUnsecure.log",logs_dir, date_dir);
    let log_data = read_log_file(&path);

    match log_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/incomingSecure")]
pub async fn get_incoming_secure_data() -> impl Responder {
    let logs_dir = env::var("LOGS_DIR").unwrap_or_else(|_| String::from("logs"));
    let date_dir = Local::now().format("%d%m%Y").to_string();
    let path = format!("{}/{}/incomingSecure.log",logs_dir, date_dir);
    let log_data = read_log_file(&path);

    match log_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/outgoingSecure")]
pub async fn get_outgoing_secure_data() -> impl Responder {
    let logs_dir = env::var("LOGS_DIR").unwrap_or_else(|_| String::from("logs"));
    let date_dir = Local::now().format("%d%m%Y").to_string();
    let path = format!("{}/{}/outgoingSecure.log",logs_dir, date_dir);
    let log_data = read_log_file(&path);

    match log_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
fn read_log_file<P>(filename: P) -> io::Result<Vec<LogEntry>> where P: AsRef<Path> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);

    let mut log_entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.contains("[send_packet] [SUCCESS]") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let date_time_str = format!("{} {}", parts[1], parts[2]);
                if let Ok(naive_datetime) = NaiveDateTime::parse_from_str(&date_time_str, "%Y-%m-%d %H:%M:%S") {
                    let datetime: DateTime<Local> = Local.from_local_datetime(&naive_datetime).unwrap();
                    let time = datetime.format("%H:%M:%S").to_string();

                    let packet_count_str = parts[parts.len() - 1];
                    if let Ok(packet_count) = packet_count_str.parse::<u32>() {
                        log_entries.push(LogEntry { time, packet_count });
                    }
                }
            }
        }
    }

    Ok(log_entries)
}


#[get("/connectionStatus")]
async fn get_connection_status() -> impl Responder {
    let status = GLOBAL_STATUS.lock().unwrap().clone();
    HttpResponse::Ok().json(status)
}