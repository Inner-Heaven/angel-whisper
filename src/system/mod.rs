

use super::errors::AWResult;
use super::llsd::session::server::Session;
use bytes::{Bytes, BytesMut};

use std::sync::{Arc, RwLock};
use typemap::ShareMap;

pub mod router;
pub mod authenticator;
pub mod hashmapstore;
pub mod sessionstore;

pub type ServiceHub = Arc<RwLock<ShareMap>>;
pub type ShareSession = Arc<RwLock<Session>>;

pub trait Handler: Send + Sync + 'static {
    /// Handle incoming message.
    fn handle(&self,
              services: ServiceHub,
              session: Arc<RwLock<Session>>,
              msg: &mut BytesMut)
              -> AWResult<Bytes>;
}