use crate::net::handler::GenericHandler;

pub struct WorldHandler {}

impl GenericHandler for WorldHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}
