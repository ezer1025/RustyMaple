use crate::defaults;
use crate::net::client;
use crate::net::handler;

use std::error;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::Arc;
use threadpool::ThreadPool;

pub struct Server {
    packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
    connection_threads: usize,
    client_workers: usize,
}

impl Server {
    pub fn listen(
        &self,
        address: SocketAddr,
        on_new_connection: fn(SocketAddr),
    ) -> Result<(), Box<dyn error::Error>> {
        let listener = TcpListener::bind(address)?;
        let thread_pool = ThreadPool::new(self.connection_threads);

        for connection in listener.incoming() {
            let stream = match connection {
                Ok(unwrapped_stream) => {
                    match unwrapped_stream.peer_addr() {
                        Ok(peer_addr) => on_new_connection(peer_addr),
                        Err(error) => return Err(error.into()),
                    };
                    unwrapped_stream
                }
                Err(error) => {
                    return Err(error.into());
                }
            };

            let mut client = match client::ClientBuilder::new()
                .packet_handler(&self.packet_handler)
                .workers_count(&self.client_workers)
                .spawn()
            {
                Ok(client) => client,
                Err(error) => return Err(error.into()),
            };
            thread_pool.execute(move || {
                client.start(stream);
            });
        }
        Ok(())
    }
}

pub struct ServerBuilder<'a> {
    server_packet_handler: Option<&'a str>,
    client_main_thread_count: usize,
    client_workers_count: usize,
}

impl<'a> ServerBuilder<'a> {
    pub fn new() -> ServerBuilder<'a> {
        ServerBuilder {
            server_packet_handler: None,
            client_main_thread_count: defaults::DEFAULT_CLIENT_WORKERS,
            client_workers_count: defaults::DEFAULT_CLIENT_WORKERS,
        }
    }

    pub fn server_type(&mut self, server_type: &'a str) -> &mut Self {
        self.server_packet_handler = Some(server_type);
        self
    }

    pub fn clients_threads(&mut self, thread_count: usize) -> &mut Self {
        self.client_main_thread_count = thread_count;
        self
    }

    pub fn client_workers(&mut self, workers_count: usize) -> &mut Self {
        self.client_workers_count = workers_count;
        self
    }

    pub fn spawn(&self) -> Result<Server, Box<dyn error::Error>> {
        let matched_packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static> =
            match self.server_packet_handler {
                Some(name) => match handler::get_handler_by_name(name) {
                    None => return Err(format!("unknown server type `{}`", name).into()),
                    Some(handler) => handler,
                },
                None => return Err("cannot spawn Server without specifiying server type".into()),
            };
        Ok(Server {
            packet_handler: matched_packet_handler,
            connection_threads: self.client_main_thread_count,
            client_workers: self.client_workers_count,
        })
    }
}
