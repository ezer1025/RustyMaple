use crate::net::handler::GenericHandler;
use bytes::Buf;

pub struct LoginHandler {}

impl GenericHandler for LoginHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        let mut bytes = &buffer[..];

        match bytes.get_u16() {
            _ => (),
        };
        return (buffer, buffer_size);
    }
}
