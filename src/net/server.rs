use crate::net::handler;

use std::error;
use std::net::SocketAddr;
use std::net::TcpListener;

pub struct Server {
    packet_handler: Box<dyn handler::GenericHandler>,
}

impl Server {
    pub fn listen(
        &self,
        address: SocketAddr,
        on_new_connection: fn(SocketAddr),
    ) -> Result<(), Box<dyn error::Error>> {
        let listener = TcpListener::bind(address)?;
        for connection in listener.incoming() {
            match connection {
                Ok(connection) => match connection.local_addr() {
                    Ok(local_addr) => on_new_connection(local_addr),
                    Err(error) => return Err(error.into()),
                },
                Err(error) => {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }
}

pub struct ServerBuilder<'a> {
    server_packet_handler: Option<&'a str>,
}

impl<'a> ServerBuilder<'a> {
    pub fn new() -> ServerBuilder<'a> {
        ServerBuilder {
            server_packet_handler: None,
        }
    }

    pub fn server_type(&mut self, server_type: &'a str) -> &mut Self {
        self.server_packet_handler = Some(server_type);
        self
    }

    pub fn spawn(&self) -> Result<Server, Box<dyn error::Error>> {
        let packet_handler: Box<dyn handler::GenericHandler> = match self.server_packet_handler {
            Some("login") => Box::new(handler::LoginHandler {}),
            Some("channel") => Box::new(handler::ChannelHandler {}),
            Some("world") => Box::new(handler::WorldHandler {}),
            Some(server_type) => {
                return Err(format!("Unknown server type `{}`", server_type).into())
            }
            None => return Err("Server type not supplied".into()),
        };

        Ok(Server {
            packet_handler: packet_handler,
        })
    }
}
