#[allow(dead_code)]
pub mod service {
    use angel_whisper::ServerSession;
    use angel_whisper::errors::{AWError, AWResult};
    use angel_whisper::system::{Handler, ServiceHub};
    use bytes::{Bytes, BytesMut};
    use std::default::Default;
    use std::sync::{Arc, RwLock};

    pub struct EchoHandler;
    impl Default for EchoHandler {
        fn default() -> EchoHandler {
            EchoHandler {}
        }
    }
    impl Handler for EchoHandler {
        fn handle(&self,
                  _: ServiceHub,
                  _: Arc<RwLock<ServerSession>>,
                  msg: &mut BytesMut)
                  -> AWResult<Bytes> {
            if msg.clone().to_vec() == b"ping".to_vec() {
                Ok(b"pong".to_vec().into())
            } else {
                Err(AWError::NotImplemented)
            }
        }
    }
}
#[allow(dead_code)]
pub mod client;
