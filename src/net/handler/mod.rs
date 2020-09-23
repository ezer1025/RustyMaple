mod channel_handler;
mod login_handler;
mod world_handler;

use std::sync::Arc;

pub trait GenericHandler {
    fn handle(&self, buffer: Vec<u8>, buffer_size: usize) -> (Vec<u8>, usize);
}

pub fn get_handler_by_name(
    handler_name: &str,
) -> Option<Arc<dyn GenericHandler + Sync + Send + 'static>> {
    match handler_name {
        "login" => Some(Arc::new(login_handler::LoginHandler {})),
        "channel" => Some(Arc::new(channel_handler::ChannelHandler {})),
        "world" => Some(Arc::new(world_handler::WorldHandler {})),
        _ => None,
    }
}
