extern crate log;
extern crate simplelog;

use dotenv::dotenv;

use std::env;
use std::fs::File;

use log::*;
use simplelog::*;

fn main() {
    // Setting up logger settings for both console and file
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Trace, Config::default(), TerminalMode::Mixed),
            WriteLogger::new(LevelFilter::Info, Config::default(), File::create("rust_maple.log").unwrap()),
        ]
    ).unwrap();

    // Loading .env file into environment variables
    dotenv().ok();

    // loading address, port and server_type environment variables values

    let _address:String = match env::var("address") {
        Ok(value) => value,
        Err(error) => {
            error!("could not find the key `address` key in the environment variables/file [{}]", error);
            std::process::exit(1);
        }
    };

    let _port:u16 = match env::var("port") {
        Ok(value) => match value.parse::<u16>() {
            Ok(u16_value) => u16_value,
            Err(error) => {
                error!("could not use the given value for the key `port` [{}]", error);
                std::process::exit(1);
            }
        },
        Err(error) => {
            error!("could not find the key `port` in the environment variables/file [{}]", error);
            std::process::exit(1);
        }
    };

    let _server_type:String = match env::var("server_type") {
        Ok(value) => value,
        Err(error) => {
            error!("could not find the key `server_type` in the environment variables/file [{}]", error);
            std::process::exit(1);
        }
    };
}