pub struct LoginHandler {}

pub struct ChannelHandler {}

pub struct WorldHandler {}

pub trait GenericHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize);
}

impl GenericHandler for LoginHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}

impl GenericHandler for ChannelHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}

impl GenericHandler for WorldHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize) {
        return (buffer, buffer_size);
    }
}
