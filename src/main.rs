extern crate log;
extern crate simplelog;

use dotenv::dotenv;

use std::env;
use std::fs::File;

use log::*;
use simplelog::*;

mod net;

fn main() {
    // Setting up logger settings for both console and file
    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Trace, Config::default(), TerminalMode::Mixed),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create("rusty_maple.log").unwrap(),
        ),
    ])
    .unwrap();

    // Loading .env file into environment variables
    dotenv().ok();

    // loading address, port and server_type environment variables values

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

    let server = net::server::ServerBuilder::new()
        .server_type(&server_type)
        .spawn();

    let server = match server {
        Ok(server) => server,
        Err(error) => {
            error!(
                "Could not create server with the current configurations [{}]",
                error
            );
            std::process::exit(1);
        }
    };

    let address_and_port = format!("{}:{}", server_address, server_port);
    info!("Start listening on {}", address_and_port);

    match server.listen(address_and_port.parse().unwrap(), |new_client_address| {
        info!("New connection [{}]", new_client_address);
    }) {
        Err(error) => {
            error!("Server could not start listening [{}]", error);
            std::process::exit(1);
        }
        _ => (),
    }
}
