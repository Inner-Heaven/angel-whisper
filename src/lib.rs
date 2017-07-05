extern crate sodiumoxide;
extern crate uuid;
extern crate chrono;
extern crate byteorder;
extern crate bytes;
extern crate typemap;
extern crate murmurhash64;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate quick_error;

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
#[cfg(feature = "protobuf")]
extern crate prost;
#[cfg(feature = "protobuf")]
#[macro_use]
extern crate prost_derive;

/// Honestly I forgot what LLSD stands for. Something like Low-Level System
/// Description.
/// I remember only Low-Level part.
/// The idea was to group all low level things that can be attributed to both
/// client and server together,
/// so it can be extracted into separate crate later.
/// Main rule — nothing in LLSD should ever use anything from parent andn
/// sibling modules.
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
    pub use futures::{Async, Future};
    pub use tokio_core::net::TcpStream;
    pub use tokio_core::reactor::{Core, Handle};
    pub use tokio_proto::TcpClient;
    pub use tokio_proto::pipeline::{ClientProto, ClientService};
    pub use tokio_service::Service;
}
