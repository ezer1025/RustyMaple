use std::sync::{Mutex, Arc};

use crate::net::{handler::GenericHandler, client::{Client}};

pub struct WorldHandler {}

impl GenericHandler for WorldHandler {
    fn handle(&self, client: Arc<Mutex<Client>>, buffer: Vec<u8>, buffer_size: usize) -> Option<(Vec<u8>, usize)> {
        None
    }
}
