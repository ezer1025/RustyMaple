use crate::defaults;
use crate::net::crypto;
use crate::net::handler;

use bytes::{BufMut, BytesMut};
use log::*;
use rand::prelude::*;
use std::error;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use rayon;
use crate::db::model::user;

pub struct Client {
    workers_count: usize,
    pub db_user: Option<user::User>,
    packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
}

pub struct SendableMessage {
    buffer: Vec<u8>,
    encrypted: bool,
}

impl Client {
    pub fn start(&mut self, mut stream: TcpStream) {
        let mut prng: StdRng = StdRng::from_entropy();
        let (sender, receiver) = channel::<SendableMessage>();
        let receive_thread_pool = match rayon::ThreadPoolBuilder::new().num_threads(self.workers_count).build() {
            Ok(thread_pool) => thread_pool,
            Err(error) => panic!("Could not user's create thread pool [{}]", error)
        };

        let write_stream = match stream.try_clone() {
            Ok(cloned_stream) => cloned_stream,
            Err(error) => panic!("could not copy TcpStream [{}]", error),
        };

        let mut send_sequence: [u8; defaults::USER_SEQUENCE_SIZE] = Default::default();
        let mut receive_sequence: [u8; defaults::USER_SEQUENCE_SIZE] = Default::default();

        prng.fill(&mut send_sequence);
        prng.fill(&mut receive_sequence);

        let mut data_to_read = 0;
        let mut total_data_read = 0;
        let mut data_buffer: Vec<u8> = vec![0; defaults::DEFAULT_HEADER_LENGTH];

        let (handshake_packet, _handshake_length) =
            Self::create_handshake(&receive_sequence, &send_sequence);

        thread::spawn(move || Self::send_messages(receiver, write_stream, &mut send_sequence));

        match sender.send(SendableMessage {
            buffer: handshake_packet,
            encrypted: false,
        }) {
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
                            data_to_read = crypto::get_packet_length(&data_buffer);
                            total_data_read = 0;
                            data_buffer = vec![0u8; data_to_read];
                            info!("about to read {} bytes", data_to_read);
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
                            let decrypted_buffer = match crypto::maple_custom_decrypt(
                                data_buffer,
                                &mut receive_sequence,
                            ) {
                                Ok(decrypted_buffer) => decrypted_buffer,
                                Err(error) => {
                                    warn!("unable to decrypt packet [{}]", error);
                                    data_to_read = 0;
                                    data_buffer = vec![0; defaults::DEFAULT_HEADER_LENGTH];
                                    continue;
                                }
                            };

                            let sender_clone = sender.clone();
                            let packet_handler = self.packet_handler.clone();


                            receive_thread_pool.scope(|scope| {
                                scope.spawn(|_| {
                                    Self::handle_receive(
                                        self,
                                        decrypted_buffer,
                                        total_data_read,
                                        sender_clone,
                                        packet_handler,
                                    )
                                });
                                
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

    fn create_handshake(
        receive_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
        send_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
    ) -> (Vec<u8>, usize) {
        let mut data = BytesMut::new();
        data.put_u16_le(defaults::MAPLESTORY_VERSION);
        data.put_u16_le(defaults::MAPLESTORY_SUBVERSION.len() as u16);
        data.put_slice(defaults::MAPLESTORY_SUBVERSION.as_bytes());
        data.put_slice(receive_sequence);
        data.put_slice(send_sequence);
        data.put_u8(defaults::MAPLESTORY_LOCALE);

        let mut result = BytesMut::with_capacity(data.len() + size_of::<u16>());
        result.put_u16_le(data.len() as u16);
        result.put_slice(&data);

        (result.to_vec(), result.len())
    }

    fn handle_receive(
        client: &mut Client,
        buffer: Vec<u8>,
        buffer_size: usize,
        sender_channel: Sender<SendableMessage>,
        packet_handler: Arc<dyn handler::GenericHandler + Sync + Send + 'static>,
    ) {
        let (send_buffer, _) = packet_handler.handle(client, buffer, buffer_size);
        match sender_channel.send(SendableMessage {
            buffer: send_buffer,
            encrypted: true,
        }) {
            Err(error) => debug!("mpsc channel hung up [{}]", error),
            Ok(()) => (),
        };
    }

    fn send_messages(
        receive_channel: Receiver<SendableMessage>,
        mut stream: TcpStream,
        send_sequence: &[u8; defaults::USER_SEQUENCE_SIZE],
    ) {
        let mut user_send_sequence = send_sequence.clone();
        loop {
            match receive_channel.recv() {
                Ok(sendable_message) => {
                    let mut final_buffer = sendable_message.buffer;

                    if sendable_message.encrypted {
                        let packet_header = crypto::generate_packet_header(
                            final_buffer.len() as u16,
                            &user_send_sequence,
                            &defaults::MAPLESTORY_VERSION,
                        );

                        match stream.write(&packet_header[..]) {
                            Ok(_) => {
                                debug!("written packet header to {}", stream.peer_addr().unwrap())
                            }
                            Err(error) => {
                                warn!("could not write to TcpStream [{}]", error);
                                continue;
                            }
                        };

                        final_buffer = match crypto::maple_custom_encrypt(
                            &final_buffer,
                            &mut user_send_sequence,
                        ) {
                            Ok(encrypted_buffer) => encrypted_buffer,
                            Err(error) => {
                                warn!("unable to encrypt message [{}]", error);
                                break;
                            }
                        };
                    }

                    match stream.write(&final_buffer[..]) {
                        Ok(bytes_written) => debug!(
                            "written {} bytes to {}",
                            bytes_written,
                            stream.peer_addr().unwrap()
                        ),

                        Err(error) => warn!("could not write to TcpStream [{}]", error),
                    }
                }
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
            db_user: Default::default(),
            workers_count: self.workers_count,
            packet_handler: client_packet_handler,
        })
    }
}
