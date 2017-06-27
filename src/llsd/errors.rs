#![allow(missing_docs)]
use std::io;
use std::result::Result;

/// Result type that should be used inside of llsd module.
pub type LlsdResult<T> = Result<T, LlsdError>;

quick_error! {
    #[derive(Debug)]
    pub enum LlsdError {
        Io(err: io::Error) {
            from()
            cause(err)
            description("Underlying I/O error.")
            display("I/O error: {}", err)
        }
        HandshakeFailed {}
        InvalidReadyFrame {
            description("Server sent invalid payload for Ready frame.")
        }
        DecryptionFailed {}
        InvalidHelloFrame {
            description("Client sent invalid payload for Hello frame.")
        }
        InvalidWelcomeFrame {}
        InvalidSessionState {}
        IncompleteFrame {}
        BadFrame {}
        ExpiredSession {}
    }
}
