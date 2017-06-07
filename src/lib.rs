
#[macro_use] extern crate blunder;
extern crate sodiumoxide;
extern crate uuid;
extern crate chrono;
extern crate byteorder;
extern crate bytes;
extern crate typemap;
extern crate murmurhash64;
extern crate protobuf;
#[macro_use] extern crate nom;
#[macro_use] extern crate slog;

#[cfg(feature = "system-on-tokio")] extern crate futures;
#[cfg(feature = "system-on-tokio")] extern crate tokio_io;
#[cfg(feature = "system-on-tokio")] extern crate tokio_proto;
#[cfg(feature = "system-on-tokio")] extern crate tokio_service;

pub mod llsd;
pub use llsd::session::client::Session as ClientSession;
pub use llsd::session::server::Session as ServerSession;
pub use llsd::session::Sendable;
pub use llsd::frames;
pub mod errors;
pub mod system;

mod angel_system;
pub use angel_system::{AngelSystem};

/// Reexport libsodium things.
pub mod crypto {
    pub use sodiumoxide::crypto::box_::{PublicKey, SecretKey, gen_keypair};
}
