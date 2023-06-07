extern crate diesel;
extern crate log;
extern crate simplelog;

use ini::Ini;

use std::env;
use std::fs::File;

use log::*;
use simplelog::*;

mod db;
mod defaults;
mod net;

fn main() {
    let args: Vec<String> = env::args().collect();

    match CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create("rusty_maple.log").unwrap(),
        ),
    ]) {
        Ok(_) => {}
        Err(error) => panic!("{}", error),
    };

    let general_settings = match Ini::load_from_file("settings\\global.ini") {
        Ok(ini) => ini,
        Err(error) => panic!("{}", error),
    };

    let general_infrastructure_section = match general_settings.section(Some("Infrastructure")) {
        Some(section) => section,
        None => panic!("Infrastructure section did not found in general settings"),
    };

    let clients_threads: usize = match general_infrastructure_section.get("clients_threads") {
        Some(value) => match value.parse::<usize>() {
            Ok(usize_value) => usize_value,
            Err(error) => {
                warn!(
                    "could not use the given value for the key `clients_threads` [{}]",
                    error
                );
                info!(
                    "using the default value for `clients_threads` ({})",
                    defaults::DEFAULT_CLIENTS_THREADS
                );
                defaults::DEFAULT_CLIENTS_THREADS
            }
        },
        None => {
            warn!("Unable to determine 'clients_thread' from general settings");
            info!(
                "using default value for `clients_threads` ({})",
                defaults::DEFAULT_CLIENTS_THREADS
            );
            defaults::DEFAULT_CLIENTS_THREADS
        }
    };

    let client_workers: usize = match general_infrastructure_section.get("client_workers") {
        Some(value) => match value.parse::<usize>() {
            Ok(usize_value) => usize_value,
            Err(error) => {
                warn!(
                    "could not use the given value for the key `client_workers` [{}]",
                    error
                );
                info!(
                    "using the default value for `client_workers` ({})",
                    defaults::DEFAULT_CLIENT_WORKERS
                );
                defaults::DEFAULT_CLIENT_WORKERS
            }
        },
        None => {
            warn!("Unable to determine 'client_workers' from general settings");
            info!(
                "using the default value for `client_workers` ({})",
                defaults::DEFAULT_CLIENT_WORKERS,
            );
            defaults::DEFAULT_CLIENT_WORKERS
        }
    };

    match args.len() < 2 {
        true => {
            // bootstrap
        }
        false => {
            let specific_settings = match Ini::load_from_file(&args[1]) {
                Ok(ini) => ini,
                Err(error) => panic!("{}", error),
            };

            let infrastructure_section = match specific_settings.section(Some("Infrastructure")) {
                Some(section) => section,
                None => {
                    panic!("Infrastructure section did not found in instance specific settings")
                }
            };

            let server_address = match infrastructure_section.get("address") {
                Some(value) => value,
                None => panic!("Unable to determine instance server IP address from instance specific settings")
            };

            let sequence_number = match args.len() < 3 {
                true => None,
                false => match args[2].parse::<u16>() {
                    Ok(sn) => Some(sn),
                    Err(error) => panic!("{}", error),
                },
            };

            let server_type = match infrastructure_section.get("type") {
                Some(some_server_type) => match some_server_type {
                    "login" => "login",
                    "world" => match sequence_number {
                        Some(_) => "channel",
                        None => "world",
                    },
                    _ => panic!("Unidentified instance server type {}", some_server_type),
                },
                None => panic!("Unable to determine instance type from instance specific settings"),
            };

            let server_port: u16 = match infrastructure_section.get("port") {
                Some(textual_port) => match textual_port.parse::<u16>() {
                    Ok(port) => match server_type == "world" {
                        true => port,
                        false => match sequence_number {
                            Some(id) => port + id,
                            None => panic!(
                                "Server instance requires sequence number which did not supplied"
                            ),
                        },
                    },
                    Err(error) => panic!("{}", error),
                },
                None => panic!(
                    "Unable to determine instance server port from instance specific settings"
                ),
            };

            let database_section = match general_settings.section(Some("Database")) {
                Some(section) => section,
                None => panic!("Database section did not found in general settings"),
            };

            let db_connection_string = match database_section.get("DATABASE_URL") {
                Some(some_connection_string) => some_connection_string,
                None => panic!("Unable to connection string (DATABASE_URL) from general settings"),
            };

            match db::db::DBPool::init(db_connection_string) {
                Ok(_) => {}
                Err(error) => panic!("{}", error),
            };

            let server = net::server::ServerBuilder::new()
                .server_type(server_type)
                .clients_threads(clients_threads)
                .client_workers(client_workers)
                .spawn();

            let mut server = match server {
                Ok(server) => server,
                Err(error) => panic!(
                    "could not create server with the current configurations [{}]",
                    error
                ),
            };

            let address_and_port = format!("{}:{}", server_address, server_port);
            info!("start listening on {}", address_and_port);

            match server.listen(address_and_port.parse().unwrap(), |new_client_address| {
                info!("new connection [{}]", new_client_address);
            }) {
                Err(error) => {
                    error!("server could not start listening [{}]", error);
                    std::process::exit(1);
                }
                _ => (),
            }
        }
    }
}
