mod login;
mod pin;
mod world_select;

use crate::net::client::Client;
use crate::net::handler::GenericHandler;
use bytes::Buf;
use std::sync::{Arc, Mutex};


pub struct LoginHandler {}

impl GenericHandler for LoginHandler {
    fn handle(
        &self,
        client: Arc<Mutex<Client>>,
        buffer: Vec<u8>,
        _buffer_size: usize,
    ) -> Option<(Vec<u8>, usize)> {
        let mut bytes = &buffer.clone()[..];

        match bytes.get_u16_le() {
            0x01u16 => login::login(client, &mut bytes),
            0x09u16 => pin::check_pin_code(client, &mut bytes),
            0x0Au16 => pin::insert_pin_code(client, &mut bytes),
            0x0Bu16 => None, // Show Worlds
            _ => None,
        }
    }
}