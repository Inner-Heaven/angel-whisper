

use blunder::Blunder;
use std::convert::{From, Into};
use std::error::Error;
use std::fmt;
use std::io;
use std::result::Result;

/// Error type that should be unsed inside of llsd module.
pub type LlsdError = Blunder<LlsdErrorKind>;
/// Result type that should be used inside of llsd module.
pub type LlsdResult<T> = Result<T, LlsdError>;


#[derive(Debug, PartialEq, Clone)]
/// Types of error that can be returned within this error.
pub enum LlsdErrorKind {
    /// Error during handshake stage. Probably means server doesn't recognize
    /// the client
    HandshakeFailed,
    /// Payload is too big. You don't want make server or client do decryption
    /// of your movie collection in request.
    MessageTooBig,
    /// Read it as decryption failed.
    BadFrame,
    /// Stale session. Remember, each session expiry regardless of activity in
    /// predefined intervals.
    /// Client should handle this without comsumer notice.
    SessionExpired,
    /// Handshake frames have to be sent in specific order. Messages can be
    /// sent only when session is Ready.
    InvalidState,
    /// Missing some bytes.
    IncompleteFrame,
}

impl Error for LlsdErrorKind {
    fn cause(&self) -> Option<&Error> {
        None
    }

    fn description(&self) -> &str {
        match *self {
            _ => "Description not available",
        }
    }
}

impl fmt::Display for LlsdErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Into<io::Error> for LlsdErrorKind {
    fn into(self) -> io::Error {
        match self {
            LlsdErrorKind::BadFrame => io::Error::new(io::ErrorKind::InvalidData, self),
            _ => io::Error::new(io::ErrorKind::Other, self),
        }
    }
}

impl From<io::Error> for LlsdErrorKind {
    fn from(_error: io::Error) -> LlsdErrorKind {
        LlsdErrorKind::BadFrame
    }
}
