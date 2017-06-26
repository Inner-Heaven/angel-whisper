

use super::errors::AWResult;
use super::llsd::session::server::Session;

use std::sync::{Arc, RwLock};
use typemap::ShareMap;

pub mod router;
pub mod authenticator;
pub mod hashmapstore;
pub mod sessionstore;

pub type ServiceHub = Arc<RwLock<ShareMap>>;
pub type ShareSession = Arc<RwLock<Session>>;
pub type Response = AWResult<Vec<u8>>;

pub trait Handler: Send + Sync + 'static {
    /// Handle incoming message.
    #[inline]
    fn handle(&self,
              services: ServiceHub,
              session: Arc<RwLock<Session>>,
              msg: Vec<u8>)
              -> AWResult<Vec<u8>>;
}

impl<F> Handler for F
where
    F: Send + Sync + 'static + Fn(ServiceHub, ShareSession, Vec<u8>) -> Response,
{
    fn handle(&self, services: ServiceHub, session: ShareSession, msg: Vec<u8>) -> Response {
        (*self)(services, session, msg)
    }
}
