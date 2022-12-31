mod channel_handler;
mod login_handler;
mod world_handler;
use bytes::Buf;
use std::sync::{Arc, Mutex};
use log::error;

use super::client::Client;

pub trait GenericHandler {
    fn handle(
        &self,
        client: Arc<Mutex<Client>>,
        buffer: Vec<u8>,
        buffer_size: usize,
    ) -> Option<(Vec<u8>, usize)>;
}

pub struct CommonHandler {
    handler: Arc<dyn GenericHandler + Sync + Send + 'static>,
}

impl CommonHandler {
    fn new(handler: Arc<dyn GenericHandler + Sync + Send + 'static>) -> CommonHandler {
        CommonHandler { handler: handler }
    }

    pub fn handle(
        &self,
        client: Arc<Mutex<Client>>,
        buffer: Vec<u8>,
        buffer_size: usize,
    ) -> Option<(Vec<u8>, usize)> {
        let mut bytes = &buffer.clone()[..];

        match bytes.get_u16_le() {
            0x0018 => Self::handle_pong(client, buffer, buffer_size),
            _ => self.handler.handle(client, buffer, buffer_size),
        }
    }

    fn handle_pong(client: Arc<Mutex<Client>>, _buffer: Vec<u8>, _buffer_size: usize) -> Option<(Vec<u8>, usize)> {
        let mut client_guard = match client.lock() {
            Ok(guard) => guard,
            Err(error) => {
                error!("Unable to lock Client Mutext [{}]", error);
                return None
            }
        };

        client_guard.ponged = true;
        None
    }
}

impl Clone for CommonHandler {
    fn clone(&self) -> Self {
        CommonHandler {
            handler: Arc::clone(&self.handler),
        }
    }
}

pub fn get_handler_by_name(handler_name: &str) -> Option<CommonHandler> {
    match handler_name {
        "login" => Some(CommonHandler::new(Arc::new(login_handler::LoginHandler {}))),
        "channel" => Some(CommonHandler::new(Arc::new(
            channel_handler::ChannelHandler {},
        ))),
        "world" => Some(CommonHandler::new(Arc::new(world_handler::WorldHandler {}))),
        _ => None,
    }
}
