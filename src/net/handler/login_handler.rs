use crate::net::handler::GenericHandler;
use bytes::{Buf, BufMut, BytesMut};

pub struct LoginHandler {}

impl GenericHandler for LoginHandler {
    fn handle(&self, buffer: Vec<u8>, _buffer_size: usize) -> (Vec<u8>, usize) {
        let mut bytes = &buffer.clone()[..];

        let (response, response_len) = match bytes.get_u16_le() {
            0x1bu16 => Self::login(&mut bytes),
            _ => (Vec::new(), 0),
        };
        return (response, response_len);
    }
}

impl LoginHandler {
    fn login(buffer: &mut &[u8]) -> (Vec<u8>, usize){
        let username_length = buffer.get_u16_le();
        let mut username = vec![0u8; username_length as usize];
        buffer.copy_to_slice(&mut username);

        let password_length = buffer.get_u16_le();
        let mut password = vec![0u8; password_length as usize];
        buffer.copy_to_slice(&mut password);

        let mut response = BytesMut::new();

        response.put_u16_le(0);
        
        /*
            *   3: ID deleted or blocked<br>
            *   4: Incorrect password<br>
            *   5: Not a registered id<br>
            *   6: System error<br>
            *   7: Already logged in<br>
            *   8: System error<br>
            *   9: System error<br>
            *   10: Cannot process so many connections<br>
            *   11: Only users older than 20 can use this channel
        */
        
        response.put_u32_le(6);
        response.put_u16_le(0);

        (response.to_vec(), response.len())
    }
}
