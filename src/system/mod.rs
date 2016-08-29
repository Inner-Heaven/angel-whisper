use typemap::TypeMap;

use std::sync::{Arc, RwLock};

use super::errors::AWResult;

pub mod router;

pub type ServiceHub = Arc<RwLock<TypeMap>>;

/// Generic handler trait.
pub trait Handler: Send + Sync + 'static {
    /// Handle incoming message.
    fn handle(&self, services: ServiceHub, msg: Vec<u8>) -> AWResult<Vec<u8>>;
}

impl<F> Handler for F
where F: Send + Sync + 'static + Fn(ServiceHub, Vec<u8>) -> AWResult<Vec<u8>> {
    fn handle(&self, services: ServiceHub, msg: Vec<u8>) -> AWResult<Vec<u8>> {
        (*self)(services, msg)
    }
}

impl Handler for Box<Handler> {
    fn handle(&self, services: ServiceHub, msg: Vec<u8>) -> AWResult<Vec<u8>> {
        (**self).handle(services, msg)
    }
}
