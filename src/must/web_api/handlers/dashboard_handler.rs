use std::env;
use actix_web::{get, HttpResponse, Responder, web};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use actix_web::http::header::IfRange::Date;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct LogEntry {
    time: String,
    packet_count: u32,
}


pub fn dashboard(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/dashboard")
            .service(update_live_chart)
    );
}

#[get("/log")]
pub async fn update_live_chart() -> impl Responder {
    let date_time = Local::now().format("%d%m%Y").to_string();
    // Get the logs directory from an environment variable
    let logs_dir = env::var("LOGS_DIR").unwrap_or_else(|_| String::from("logs"));
    let path = format!("{}/Log_{}.log", logs_dir, date_time);
    println!("{}", path);
    let log_data = read_log_file(&path);

    match log_data {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

fn read_log_file<P>(filename: P) -> io::Result<Vec<LogEntry>>
    where P: AsRef<Path> {
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