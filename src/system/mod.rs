

use super::errors::AWResult;
use super::llsd::session::server::Session;

use std::sync::{Arc, RwLock};
use typemap::TypeMap;

pub mod router;
pub mod authenticator;
pub mod hashmapstore;
pub mod sessionstore;

pub type ServiceHub = Arc<RwLock<TypeMap>>;

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
where F: Send + Sync + 'static + Fn(ServiceHub, Arc<RwLock<Session>>, Vec<u8>) -> AWResult<Vec<u8>> {
    fn handle(&self, services: ServiceHub, session: Arc<RwLock<Session>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
        (*self)(services, session, msg)
    }
}
