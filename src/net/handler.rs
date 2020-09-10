pub struct LoginHandler {}

pub struct ChannelHandler {}

pub struct WorldHandler {}

pub trait GenericHandler {
    fn handle(&self);
}

impl GenericHandler for LoginHandler {
    fn handle(&self) {}
}

impl GenericHandler for ChannelHandler {
    fn handle(&self) {}
}

impl GenericHandler for WorldHandler {
    fn handle(&self) {}
}
