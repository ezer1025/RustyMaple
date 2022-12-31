extern crate diesel;
extern crate log;
extern crate simplelog;

use dotenv::dotenv;

use std::env;
use std::fs::File;

use log::*;
use simplelog::*;

mod db;
mod defaults;
mod net;

fn main() {
    CombinedLogger::init(vec![
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
    ])
    .unwrap();

    dotenv().ok();

    db::db::init();

    let server_address: String = match env::var("address") {
        Ok(value) => value,
        Err(error) => {
            error!(
                "could not find the key `address` key in the environment variables/file [{}]",
                error
            );
            std::process::exit(1);
        }
    };

    let server_port: u16 = match env::var("port") {
        Ok(value) => match value.parse::<u16>() {
            Ok(u16_value) => u16_value,
            Err(error) => {
                error!(
                    "could not use the given value for the key `port` [{}]",
                    error
                );
                std::process::exit(1);
            }
        },
        Err(error) => {
            error!(
                "could not find the key `port` in the environment variables/file [{}]",
                error
            );
            std::process::exit(1);
        }
    };

    let server_type: String = match env::var("server_type") {
        Ok(value) => value,
        Err(error) => {
            error!(
                "could not find the key `server_type` in the environment variables/file [{}]",
                error
            );
            std::process::exit(1);
        }
    };

    let clients_threads: usize = match env::var("clients_threads") {
        Ok(value) => match value.parse::<usize>() {
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
        Err(error) => {
            warn!(
                "could not find the key `clients_threads` in the environment variables/file [{}]",
                error
            );
            info!(
                "using default value for `clients_threads` ({})",
                defaults::DEFAULT_CLIENTS_THREADS
            );
            defaults::DEFAULT_CLIENTS_THREADS
        }
    };

    let client_workers: usize = match env::var("client_workers") {
        Ok(value) => match value.parse::<usize>() {
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
        Err(error) => {
            warn!(
                "could not found the key `client_workers` in the environment variables/file [{}]",
                error
            );
            info!(
                "using the default value for `client_workers` ({})",
                defaults::DEFAULT_CLIENT_WORKERS,
            );
            defaults::DEFAULT_CLIENT_WORKERS
        }
    };

    let server = net::server::ServerBuilder::new()
        .server_type(&server_type)
        .clients_threads(clients_threads)
        .client_workers(client_workers)
        .spawn();

    let mut server = match server {
        Ok(server) => server,
        Err(error) => {
            error!(
                "could not create server with the current configurations [{}]",
                error
            );
            std::process::exit(1);
        }
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
