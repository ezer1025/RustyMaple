use std::sync::{Arc, Mutex};

use crate::net::{handler::GenericHandler, client::{Client}};

pub struct ChannelHandler {}

impl GenericHandler for ChannelHandler {
    fn handle(&self, client: Arc<Mutex<Client>>, buffer: Vec<u8>, buffer_size: usize) -> Option<(Vec<u8>, usize)> {
        None
    }
}
