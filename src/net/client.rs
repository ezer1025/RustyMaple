use crate::defaults;
use crate::net::handler;

use bytes::{BufMut, BytesMut};
use log::*;
use std::error;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

pub struct SecurityContext {
    send_iv: [u8; defaults::INITIALIZE_VECTORS_SIZE],
    recv_iv: [u8; defaults::INITIALIZE_VECTORS_SIZE],
}

pub struct Client {
    workers_count: usize,
    packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
    security_context: SecurityContext,
}

impl Client {
    pub fn start(&mut self, mut stream: TcpStream) {
        let (sender, receiver) = channel::<Vec<u8>>();
        let receive_thread_pool = threadpool::ThreadPool::new(self.workers_count);

        let write_stream = match stream.try_clone() {
            Ok(cloned_stream) => cloned_stream,
            Err(error) => panic!("could not copy TcpStream [{}]", error),
        };

        thread::spawn(|| Self::send_messages(receiver, write_stream));

        let mut data_to_read = 0;
        let mut total_data_read = 0;
        let mut data_buffer: Vec<u8> = vec![0; defaults::DEFAULT_HEADER_LENGTH];

        let (handshake_packet, _handshake_length) = Self::create_handshake(&self.security_context);
        match sender.send(handshake_packet) {
            Err(error) => {
                debug!("mpsc channel hung up [{}]", error);
                return;
            }
            Ok(()) => (),
        };

        loop {
            if data_to_read == 0 {
                match stream.read_exact(&mut data_buffer) {
                    Ok(()) => {
                        if data_buffer.len() != defaults::DEFAULT_HEADER_LENGTH {
                            debug!("failed to read packet header from TcpStream");
                        } else {
                            data_to_read = 8;
                            total_data_read = 0;
                            data_buffer = vec![0; data_to_read];
                        }
                    }
                    Err(error) => {
                        warn!("could not read from TcpStream [{}]", error);
                        break;
                    }
                };
            } else {
                match stream.read(&mut data_buffer[total_data_read..]) {
                    Ok(bytes_read) => {
                        if bytes_read == 0 {
                            break;
                        }

                        total_data_read += bytes_read;
                        if total_data_read == data_to_read {
                            let sender_clone = sender.clone();
                            let packet_handler = self.packet_handler.clone();
                            receive_thread_pool.execute(move || {
                                Self::handle_receive(
                                    data_buffer,
                                    total_data_read,
                                    sender_clone,
                                    packet_handler,
                                )
                            });
                            data_to_read = 0;
                            data_buffer = vec![0; defaults::DEFAULT_HEADER_LENGTH];
                        }
                    }
                    Err(error) => {
                        warn!("could not read from TcpStream [{}]", error);
                        break;
                    }
                }
            }
        }
    }

    pub fn create_handshake(security_context: &SecurityContext) -> (Vec<u8>, usize) {
        let mut data = BytesMut::new();
        data.put_u16_le(defaults::MAPLESTORY_VERSION);
        data.put_u16_le(defaults::MAPLESTORY_SUBVERSION.len() as u16);
        data.put_slice(defaults::MAPLESTORY_SUBVERSION.as_bytes());
        data.put_slice(&security_context.recv_iv);
        data.put_slice(&security_context.send_iv);
        data.put_u8(defaults::MAPLESTORY_LOCALE);

        let mut result = BytesMut::with_capacity(data.len() + size_of::<u16>());
        result.put_u16_le(data.len() as u16);
        result.put_slice(&data);

        (result.to_vec(), result.len())
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
            security_context: SecurityContext {
                send_iv: [0; defaults::INITIALIZE_VECTORS_SIZE],
                recv_iv: [0; defaults::INITIALIZE_VECTORS_SIZE],
            },
        })
    }
}
