use crate::net::{handler::GenericHandler, client};

pub struct WorldHandler {}

impl GenericHandler for WorldHandler {
    fn handle(&self, client: &mut client::Client, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}
