
#[macro_use]
extern crate blunder;
extern crate sodiumoxide;
extern crate uuid;
extern crate chrono;
extern crate byteorder;
extern crate bytes;
extern crate typemap;
extern crate murmurhash64;
extern crate protobuf;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate slog;

#[cfg(feature = "system-on-tokio")]
extern crate futures;
#[cfg(feature = "system-on-tokio")]
extern crate tokio_io;
#[cfg(feature = "system-on-tokio")]
extern crate tokio_proto;
#[cfg(feature = "system-on-tokio")]
extern crate tokio_service;
#[cfg(feature = "system-on-tokio")]
extern crate tokio_core;

pub mod llsd;
pub use llsd::frames;
pub use llsd::session::Sendable;
pub use llsd::session::client::Session as ClientSession;
pub use llsd::session::server::Session as ServerSession;
pub mod errors;
pub mod system;

pub mod angel_system;
pub use angel_system::AngelSystem;


/// Reexport libsodium things.
pub mod crypto {
    pub use sodiumoxide::crypto::box_::{PublicKey, SecretKey, gen_keypair};
}

/// Reexport tokio things for building a client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    pub use tokio_service::Service;
    pub use futures::{Async, Future};
    pub use tokio_proto::TcpClient;
    pub use tokio_core::net::TcpStream;
    pub use tokio_core::reactor::{Handle, Core};
    pub use tokio_proto::pipeline::{ClientProto, ClientService};
}