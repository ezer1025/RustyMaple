use crate::defaults;

pub struct LoginHandler {}

pub struct ChannelHandler {}

pub struct WorldHandler {}

pub trait GenericHandler {
    fn handle(
        &self,
        buffer: [u8; defaults::DEFAULT_BUFFER_SIZE],
    ) -> [u8; defaults::DEFAULT_BUFFER_SIZE];
}

impl GenericHandler for LoginHandler {
    fn handle(
        &self,
        buffer: [u8; defaults::DEFAULT_BUFFER_SIZE],
    ) -> [u8; defaults::DEFAULT_BUFFER_SIZE] {
        return buffer;
    }
}

impl GenericHandler for ChannelHandler {
    fn handle(
        &self,
        buffer: [u8; defaults::DEFAULT_BUFFER_SIZE],
    ) -> [u8; defaults::DEFAULT_BUFFER_SIZE] {
        return buffer;
    }
}

impl GenericHandler for WorldHandler {
    fn handle(
        &self,
        buffer: [u8; defaults::DEFAULT_BUFFER_SIZE],
    ) -> [u8; defaults::DEFAULT_BUFFER_SIZE] {
        return buffer;
    }
}
