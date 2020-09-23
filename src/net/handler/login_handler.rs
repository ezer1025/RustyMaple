use crate::net::handler::GenericHandler;
use bytes::Buf;

pub struct LoginHandler {}

impl GenericHandler for LoginHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        let mut bytes = &buffer.clone()[..];

        match bytes.get_u16_le() {
            0x1bu16 => Self::login(&mut bytes),
            _ => (),
        };
        return (buffer, buffer_size);
    }
}

impl LoginHandler {
    fn login(buffer: &mut &[u8]) {
        let username_length = buffer.get_u16_le();
        let mut username = vec![0u8; username_length as usize];
        buffer.copy_to_slice(&mut username);

        let password_length = buffer.get_u16_le();
        let mut password = vec![0u8; password_length as usize];
        buffer.copy_to_slice(&mut password);
    }
}
