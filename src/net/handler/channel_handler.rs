use crate::net::handler::GenericHandler;

pub struct ChannelHandler {}

impl GenericHandler for ChannelHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}
