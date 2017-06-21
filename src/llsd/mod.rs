#![deny(missing_docs)]
/// This should be an example of how to use session module, but oh well.
pub mod session;
/// This module should only return errors from this sub-module.
pub mod errors;
/// Again, this should be an example of how to use frames, but oh well.
pub mod frames;
/// Things related to running either client or server on top of tokio.
#[cfg(feature = "system-on-tokio")]
pub mod tokio;
/// This should be a separate crate in the future. Things related to building a client to `AngelSystem`.
pub mod client;
