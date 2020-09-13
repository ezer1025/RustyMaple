use crate::defaults;
use crate::net::handler;

use log::*;
use std::error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

pub struct Client {
    workers_count: usize,
    packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
}

impl Client {
    pub fn start(&mut self, mut stream: TcpStream) {
        let (sender, receiver) = channel::<Vec<u8>>();
        let receive_thread_pool = threadpool::ThreadPool::new(self.workers_count);
        let write_stream = match stream.try_clone() {
            Ok(cloned_stream) => cloned_stream,
            Err(error) => panic!("could not copy TcpStream [{}]", error),
        };
        let _ = thread::spawn(|| Self::send_messages(receiver, write_stream));
        loop {
            let mut read_buffer: Vec<u8> = vec![0; defaults::DEFAULT_BUFFER_SIZE];
            match stream.read(&mut read_buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        break;
                    }
                    let sender_clone = sender.clone();
                    let packet_handler = self.packet_handler.clone();
                    receive_thread_pool.execute(move || {
                        Self::handle_receive(read_buffer, bytes_read, sender_clone, packet_handler)
                    });
                }
                Err(error) => warn!("could not read from TcpStream [{}]", error),
            };
        }
    }

    pub fn handle_receive(
        buffer: Vec<u8>,
        buffer_size: usize,
        sender_channel: Sender<Vec<u8>>,
        packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
    ) {
        let (send_buffer, _) = packet_handler.handle(buffer, buffer_size);
        match sender_channel.send(send_buffer) {
            Err(error) => debug!("mpsc channel hung up [{}]", error),
            Ok(()) => (),
        };
    }

    pub fn send_messages(receive_channel: Receiver<Vec<u8>>, mut stream: TcpStream) {
        loop {
            match receive_channel.recv() {
                Ok(received_data) => match stream.write(&received_data[..]) {
                    Ok(bytes_written) => debug!(
                        "written {} bytes to {}",
                        bytes_written,
                        stream.peer_addr().unwrap()
                    ),
                    Err(error) => warn!("could not write to TcpStream [{}]", error),
                },
                Err(error) => {
                    debug!("mpsc channel hung up [{}]", error);
                    break;
                }
            };
        }
    }
}

pub struct ClientBuilder<'a> {
    workers_count: usize,
    packet_handler: Option<&'a Arc<dyn handler::GenericHandler + Sync + Send + 'static>>,
}

impl<'a> ClientBuilder<'a> {
    pub fn new() -> ClientBuilder<'a> {
        ClientBuilder {
            workers_count: defaults::DEFAULT_CLIENT_WORKERS,
            packet_handler: None,
        }
    }

    pub fn workers_count(&mut self, workers: &usize) -> &mut Self {
        self.workers_count = *workers;
        self
    }

    pub fn packet_handler(
        &mut self,
        handler: &'a Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
    ) -> &mut Self {
        self.packet_handler = Some(handler);
        self
    }

    pub fn spawn(&self) -> Result<Client, Box<dyn error::Error>> {
        let client_packet_handler = match self.packet_handler {
            Some(specifiyed_handler) => Arc::clone(specifiyed_handler),
            None => return Err("could not spawn Client without specifying packet handler".into()),
        };
        Ok(Client {
            workers_count: self.workers_count,
            packet_handler: client_packet_handler,
        })
    }
}
